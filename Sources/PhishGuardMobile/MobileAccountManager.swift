import Foundation
import os.log
import PhishGuardCore

private let logger = Logger(subsystem: "com.phishguard.mobile", category: "MobileAccountManager")

/// Runtime connection state for an account (not persisted).
enum AccountConnectionStatus: Equatable {
    case disconnected
    case connecting
    case monitoring
    case error(String)
}

/// Represents a monitored account on iOS.
struct MobileMonitoredAccount: Identifiable, Codable {
    let id: UUID
    var email: String
    var displayName: String
    var provider: MailProvider
    var imapServer: String
    var imapPort: Int
    var useTLS: Bool
    var authMethod: AuthMethod
}

/// Manages mail accounts and IMAP monitors on iOS.
@MainActor
final class MobileAccountManager: ObservableObject {
    @Published var accounts: [MobileMonitoredAccount] = []
    @Published var accountStatuses: [UUID: AccountConnectionStatus] = [:]

    let oauthManager = OAuthManager()

    private var monitors: [UUID: IMAPMonitor] = [:]
    let session: CoreSession

    // Convenience accessors for stores
    var verdictStore: VerdictStore { session.verdictStore }
    var allowlistStore: AllowlistStore { session.allowlistStore }
    var trustedLinkDomainStore: TrustedLinkDomainStore { session.trustedLinkDomainStore }
    var campaignStore: SafeonwebCampaignStore { session.campaignStore }
    var userBrandStore: UserBrandStore { session.userBrandStore }
    var userBlocklistStore: UserBlocklistStore { session.userBlocklistStore }
    var safeonwebUpdater: SafeonwebUpdater { session.safeonwebUpdater }

    private static let accountsKey = "mobileAccounts"
    /// Number of recent emails to check during iOS background refresh (kept low for ~30s time budget).
    private static let backgroundScanCount = 5

    init() {
        self.session = CoreSession(databasePath: Self.mobileDatabasePath())
        session.seedAndStartUpdates()
        loadAccounts()
    }

    /// Database path for the iOS app group container.
    static func mobileDatabasePath() -> String {
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AppConstants.appGroupIdentifier
        ) {
            return containerURL.appendingPathComponent("verdicts.sqlite").path
        }
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let phishGuardDir = appSupport.appendingPathComponent("PhishGuard")
        return phishGuardDir.appendingPathComponent("verdicts.sqlite").path
    }

    // MARK: - Account Management

    /// Adds an account with password authentication.
    func addAccount(email: String, password: String, imapServer: String? = nil, imapPort: Int? = nil) async {
        let provider = MailProviderDetector.detect(email: email)
        let server = imapServer ?? provider.defaultServer
        let port = imapPort ?? provider.defaultPort

        let account = MobileMonitoredAccount(
            id: UUID(),
            email: email,
            displayName: email,
            provider: provider,
            imapServer: server,
            imapPort: port,
            useTLS: true,
            authMethod: .password
        )

        accounts.append(account)
        accountStatuses[account.id] = .connecting
        saveAccounts()

        KeychainHelper.savePassword(accountId: account.id.uuidString, password: password)
        await startMonitor(account: account, credential: .password(password))
    }

    /// Adds an account with OAuth2 authentication.
    func addAccountWithOAuth(email: String, provider: MailProvider) async throws {
        let oauthProvider: OAuthConfig.Provider
        switch provider {
        case .gmail: oauthProvider = .google
        case .outlook: oauthProvider = .microsoft
        default: return
        }

        let tokens = try await oauthManager.authenticate(provider: oauthProvider)

        let account = MobileMonitoredAccount(
            id: UUID(),
            email: email,
            displayName: email,
            provider: provider,
            imapServer: provider.defaultServer,
            imapPort: provider.defaultPort,
            useTLS: true,
            authMethod: .oauth2
        )

        accounts.append(account)
        accountStatuses[account.id] = .connecting
        saveAccounts()

        KeychainHelper.saveTokens(
            accountId: account.id.uuidString,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        )

        await startMonitor(account: account, credential: .oauth2(email: email, accessToken: tokens.accessToken))
    }

    /// Removes an account and stops its monitor.
    func removeAccount(id: UUID) {
        monitors[id]?.stop()
        monitors.removeValue(forKey: id)
        KeychainHelper.deleteCredentials(accountId: id.uuidString)
        accounts.removeAll { $0.id == id }
        accountStatuses.removeValue(forKey: id)
        saveAccounts()
    }

    /// Reconnects all saved accounts on app launch or background wake.
    func reconnectAll() async {
        for account in accounts {
            guard accountStatuses[account.id] != .monitoring else { continue }
            await reconnect(account: account)
        }
    }

    /// Resolves IMAP credentials for an account from Keychain.
    func resolveCredential(for account: MobileMonitoredAccount) async -> IMAPCredential? {
        if account.authMethod == .oauth2 {
            guard let refreshToken = KeychainHelper.loadRefreshToken(accountId: account.id.uuidString) else { return nil }
            let oauthProvider: OAuthConfig.Provider = account.provider == .gmail ? .google : .microsoft
            do {
                let tokens = try await oauthManager.refreshAccessToken(provider: oauthProvider, refreshToken: refreshToken)
                KeychainHelper.saveTokens(
                    accountId: account.id.uuidString,
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken ?? refreshToken
                )
                return .oauth2(email: account.email, accessToken: tokens.accessToken)
            } catch {
                logger.error("Token refresh failed for \(account.email): \(error.localizedDescription)")
                return nil
            }
        } else {
            guard let password = KeychainHelper.loadPassword(accountId: account.id.uuidString) else { return nil }
            return .password(password)
        }
    }

    /// Whether any account is actively monitoring.
    var isAnyMonitoring: Bool {
        accountStatuses.values.contains(.monitoring)
    }

    /// Status for a specific account.
    func status(for id: UUID) -> AccountConnectionStatus {
        accountStatuses[id] ?? .disconnected
    }

    /// Deletes an email from the IMAP server.
    func deleteFromIMAP(verdict: Verdict) async {
        guard let uid = verdict.imapUID else {
            try? verdictStore.delete(messageId: verdict.messageId)
            return
        }

        guard let accountId = verdict.accountId,
              let accountUUID = UUID(uuidString: accountId),
              let account = accounts.first(where: { $0.id == accountUUID }),
              let credential = await resolveCredential(for: account) else {
            try? verdictStore.delete(messageId: verdict.messageId)
            return
        }

        let config = AccountConfig(
            displayName: account.displayName,
            imapServer: account.imapServer,
            imapPort: account.imapPort,
            username: account.email,
            useTLS: account.useTLS,
            authMethod: account.authMethod
        )

        let monitor = IMAPMonitor(account: config, analyzer: session.analyzer, verdictStore: verdictStore, accountId: account.id.uuidString)

        do {
            try await monitor.connectAndDelete(uid: uid, credential: credential)
            logger.info("Deleted email UID \(uid) from IMAP account \(account.email)")
        } catch {
            logger.error("IMAP delete failed for \(account.email): \(error.localizedDescription)")
        }

        try? verdictStore.delete(messageId: verdict.messageId)
    }

    // MARK: - Scan Mailbox

    @Published var scanRunning = false
    @Published var scanResult: IMAPMonitor.ScanResult?

    /// Scans the last `count` emails from each account's mailbox.
    func scanAllAccounts(count: Int) async {
        guard !accounts.isEmpty else { return }

        scanRunning = true
        scanResult = nil

        var totalEmails = 0
        var totalTime: TimeInterval = 0
        var totalSkipped = 0

        for account in accounts {
            guard let credential = await resolveCredential(for: account) else { continue }

            let config = AccountConfig(
                displayName: account.displayName,
                imapServer: account.imapServer,
                imapPort: account.imapPort,
                username: account.email,
                useTLS: account.useTLS,
                authMethod: account.authMethod
            )

            let monitor = IMAPMonitor(account: config, analyzer: session.analyzer, verdictStore: verdictStore, accountId: account.id.uuidString)

            do {
                let result = try await monitor.scanInbox(count: count, credential: credential)
                totalEmails += result.emailCount
                totalTime += result.totalTime
                totalSkipped += result.skippedParts
                logger.info("Scan \(account.email): \(result.emailCount) emails in \(String(format: "%.2f", result.totalTime))s")
            } catch {
                logger.error("Scan \(account.email) failed: \(error.localizedDescription)")
            }
        }

        scanResult = IMAPMonitor.ScanResult(
            emailCount: totalEmails,
            fetchInfoTime: 0,
            fetchBodiesTime: 0,
            fetchHeadersTime: 0,
            analysisTime: 0,
            storageTime: 0,
            totalTime: totalTime,
            skippedParts: totalSkipped
        )

        scanRunning = false
    }

    // MARK: - Background Check

    /// Performs a quick scan of new emails across all accounts. Used by BackgroundMonitor.
    func checkNewEmails() async {
        for account in accounts {
            guard let credential = await resolveCredential(for: account) else { continue }

            let config = AccountConfig(
                displayName: account.displayName,
                imapServer: account.imapServer,
                imapPort: account.imapPort,
                username: account.email,
                useTLS: account.useTLS,
                authMethod: account.authMethod
            )

            let monitor = IMAPMonitor(account: config, analyzer: session.analyzer, verdictStore: verdictStore, accountId: account.id.uuidString)

            do {
                _ = try await monitor.scanInbox(count: Self.backgroundScanCount, credential: credential)
            } catch {
                logger.error("Background check failed for \(account.email): \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Private

    private func startMonitor(account: MobileMonitoredAccount, credential: IMAPCredential) async {
        let config = AccountConfig(
            displayName: account.displayName,
            imapServer: account.imapServer,
            imapPort: account.imapPort,
            username: account.email,
            useTLS: account.useTLS,
            authMethod: account.authMethod
        )

        let monitor = IMAPMonitor(account: config, analyzer: session.analyzer, verdictStore: verdictStore, accountId: account.id.uuidString)
        monitors[account.id] = monitor

        do {
            try await monitor.start(credential: credential)
            accountStatuses[account.id] = .monitoring
        } catch {
            accountStatuses[account.id] = .error(error.localizedDescription)
        }
    }

    private func reconnect(account: MobileMonitoredAccount) async {
        accountStatuses[account.id] = .connecting
        guard let credential = await resolveCredential(for: account) else {
            accountStatuses[account.id] = .error("No credentials found")
            return
        }
        await startMonitor(account: account, credential: credential)
    }

    // MARK: - Persistence

    private func loadAccounts() {
        guard let data = UserDefaults.standard.data(forKey: Self.accountsKey),
              let decoded = try? JSONDecoder().decode([MobileMonitoredAccount].self, from: data) else {
            return
        }
        accounts = decoded
    }

    private func saveAccounts() {
        guard let data = try? JSONEncoder().encode(accounts) else { return }
        UserDefaults.standard.set(data, forKey: Self.accountsKey)
    }
}
