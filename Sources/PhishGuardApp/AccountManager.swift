import Foundation
import os.log
import SwiftUI
import PhishGuardCore

private let logger = Logger(subsystem: "com.phishguard", category: "AccountManager")

/// Represents the monitoring state of an account.
enum MonitoringStatus: Equatable {
    case notMonitored
    case connecting
    case monitoring
    case error(String)

    var label: String {
        switch self {
        case .notMonitored: return "Not Monitored"
        case .connecting: return "Connecting..."
        case .monitoring: return "Monitoring"
        case .error(let msg): return "Error: \(msg)"
        }
    }

    var color: Color {
        switch self {
        case .notMonitored: return .gray
        case .connecting: return .orange
        case .monitoring: return .green
        case .error: return .red
        }
    }
}

/// A discovered account paired with its monitoring state.
struct MonitoredAccount: Identifiable {
    let discovered: DiscoveredAccount
    var status: MonitoringStatus = .notMonitored
    var isActivated: Bool = false

    var id: String { discovered.id }

    /// Determines the mail provider based on the IMAP server hostname.
    var provider: MailProvider {
        let server = discovered.server.lowercased()
        if server.contains("gmail") || server.contains("google") {
            return .gmail
        } else if server.contains("outlook") || server.contains("office365") || server.contains("hotmail") {
            return .outlook
        } else if server.contains("yahoo") || server.contains("ymail") {
            return .yahoo
        } else if server.contains("icloud") || server.contains("mail.me.com") || server.contains("mac.com") {
            return .icloud
        }
        return .custom
    }

    /// Maps the mail provider to the corresponding OAuth config provider.
    var oauthProvider: OAuthConfig.Provider? {
        switch provider {
        case .gmail: return .google
        case .outlook: return .microsoft
        case .icloud, .yahoo, .custom: return nil
        }
    }

    /// Whether this account uses OAuth2 for authentication.
    /// Only true if the provider supports OAuth AND a real client ID is configured.
    var usesOAuth: Bool {
        guard provider.authMethod == .oauth2, let oauthProv = oauthProvider else { return false }
        return OAuthConfig.isConfigured(for: oauthProv)
    }
}

/// Manages discovered mail accounts, activation state, and IMAP monitors.
@MainActor
final class AccountManager: ObservableObject {
    @Published var accounts: [MonitoredAccount] = []
    @Published var discoveryError: String?
    @Published var isDiscovering = false

    let oauthManager = OAuthManager()

    private var monitors: [String: IMAPMonitor] = [:]
    private let analyzer: PhishingAnalyzer
    let verdictStore: VerdictStore
    let allowlistStore: AllowlistStore
    let trustedLinkDomainStore: TrustedLinkDomainStore
    let campaignStore: SafeonwebCampaignStore
    let safeonwebUpdater: SafeonwebUpdater
    private let dbManager: DatabaseManager?

    private static let activatedAccountsKey = "activatedAccounts"

    init() {
        let db = try? DatabaseManager()
        self.dbManager = db
        if let db = db {
            let blacklistStore = BlacklistStore(database: db)
            let allowlistStore = AllowlistStore(database: db)
            let trustedLinkDomainStore = TrustedLinkDomainStore(database: db)
            let campaignStore = SafeonwebCampaignStore(database: db)
            self.verdictStore = VerdictStore(database: db)
            self.allowlistStore = allowlistStore
            self.trustedLinkDomainStore = trustedLinkDomainStore
            self.campaignStore = campaignStore
            self.safeonwebUpdater = SafeonwebUpdater(campaignStore: campaignStore)
            self.analyzer = PhishingAnalyzer(blacklistStore: blacklistStore, allowlistStore: allowlistStore, trustedLinkDomainStore: trustedLinkDomainStore, campaignStore: campaignStore)
        } else {
            let memDb = try! DatabaseManager(databasePath: ":memory:")
            let campaignStore = SafeonwebCampaignStore(database: memDb)
            self.verdictStore = VerdictStore(database: memDb)
            self.allowlistStore = AllowlistStore(database: memDb)
            self.trustedLinkDomainStore = TrustedLinkDomainStore(database: memDb)
            self.campaignStore = campaignStore
            self.safeonwebUpdater = SafeonwebUpdater(campaignStore: campaignStore)
            self.analyzer = PhishingAnalyzer(checks: [
                AuthHeaderCheck(),
                ReturnPathCheck(),
                LinkMismatchCheck(trustedLinkDomainStore: self.trustedLinkDomainStore),
                IPURLCheck(),
                SuspiciousTLDCheck(),
                BrandImpersonationCheck(campaignStore: campaignStore),
            ])
        }

        safeonwebUpdater.startPeriodicRefresh()
    }

    /// Discovers accounts from Mail.app and merges with saved activation state.
    func discoverAccounts() async {
        isDiscovering = true
        discoveryError = nil

        do {
            let discovered = try await MailAccountDiscovery.discover()
            let savedActivations = loadActivatedAccountIds()

            accounts = discovered.map { disc in
                var account = MonitoredAccount(discovered: disc)
                if savedActivations.contains(disc.id) {
                    account.isActivated = true
                }
                return account
            }

            // Auto-reconnect accounts that have stored credentials
            for account in accounts where account.isActivated {
                await reconnect(accountId: account.id)
            }
        } catch {
            discoveryError = error.localizedDescription
        }

        isDiscovering = false
    }

    /// Activates monitoring for an account using password authentication.
    func activateWithPassword(accountId: String, password: String) async {
        guard let index = accounts.firstIndex(where: { $0.id == accountId }) else { return }

        let account = accounts[index].discovered
        logger.info("Activating with password: \(account.email, privacy: .public) @ \(account.server, privacy: .public):\(account.port) (SSL: \(account.usesSSL))")

        accounts[index].isActivated = true
        accounts[index].status = .connecting
        saveActivatedAccountIds()

        // Store password in Keychain
        KeychainHelper.savePassword(accountId: accountId, password: password)

        await startMonitor(accountId: accountId, credential: .password(password))
    }

    /// Activates monitoring for an account using OAuth2 authentication.
    func activateWithOAuth(accountId: String) async {
        guard let index = accounts.firstIndex(where: { $0.id == accountId }) else { return }

        let account = accounts[index]
        let oauthProvider = account.oauthProvider!

        do {
            let tokens = try await oauthManager.authenticate(provider: oauthProvider)

            accounts[index].isActivated = true
            accounts[index].status = .connecting
            saveActivatedAccountIds()

            // Store tokens in Keychain
            KeychainHelper.saveTokens(
                accountId: accountId,
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken
            )

            let email = account.discovered.email
            await startMonitor(accountId: accountId, credential: .oauth2(email: email, accessToken: tokens.accessToken))
        } catch {
            if let idx = accounts.firstIndex(where: { $0.id == accountId }) {
                if case OAuthError.userCancelled = error {
                    // User cancelled — don't show error
                    accounts[idx].status = .notMonitored
                } else {
                    accounts[idx].status = .error(error.localizedDescription)
                }
            }
        }
    }

    /// Deactivates monitoring for an account.
    func deactivate(accountId: String) {
        guard let index = accounts.firstIndex(where: { $0.id == accountId }) else { return }

        monitors[accountId]?.stop()
        monitors.removeValue(forKey: accountId)

        // Clear credentials from Keychain
        KeychainHelper.deleteCredentials(accountId: accountId)

        accounts[index].isActivated = false
        accounts[index].status = .notMonitored
        saveActivatedAccountIds()
    }

    /// Whether any account is actively monitoring.
    var isAnyMonitoring: Bool {
        accounts.contains { $0.status == .monitoring }
    }

    // MARK: - Scan Mailbox

    @Published var scanRunning = false
    @Published var scanResult: IMAPMonitor.BenchmarkResult?

    /// Scans the last `count` emails from each activated account's mailbox.
    func scanAllAccounts(count: Int) async {
        let activeAccounts = accounts.filter(\.isActivated)
        guard !activeAccounts.isEmpty else { return }

        scanRunning = true
        scanResult = nil

        var totalEmails = 0
        var totalTime: TimeInterval = 0
        var totalSkipped = 0

        for account in activeAccounts {
            logger.info("Scanning \(account.discovered.email)...")

            guard let credential = await resolveCredential(for: account) else {
                logger.error("Scan: could not resolve credentials for \(account.discovered.email)")
                continue
            }

            let config = AccountConfig(
                displayName: account.discovered.name,
                imapServer: account.discovered.server,
                imapPort: account.discovered.port,
                username: account.discovered.email,
                useTLS: account.discovered.usesSSL,
                authMethod: account.usesOAuth ? .oauth2 : .password
            )

            let monitor = IMAPMonitor(account: config, analyzer: analyzer, verdictStore: verdictStore)

            do {
                let result = try await monitor.benchmarkScan(count: count, credential: credential)
                totalEmails += result.emailCount
                totalTime += result.totalTime
                totalSkipped += result.skippedParts
                logger.info("Scan \(account.discovered.email): \(result.emailCount) emails in \(String(format: "%.2f", result.totalTime))s")
            } catch {
                logger.error("Scan \(account.discovered.email) failed: \(error.localizedDescription)")
            }
        }

        scanResult = IMAPMonitor.BenchmarkResult(
            emailCount: totalEmails,
            fetchInfoTime: 0,
            fetchBodiesTime: 0,
            fetchHeadersTime: 0,
            analysisTime: 0,
            storageTime: 0,
            totalTime: totalTime,
            skippedParts: totalSkipped
        )
        logger.info("Scan complete: \(totalEmails) emails across \(activeAccounts.count) accounts in \(String(format: "%.2f", totalTime))s")

        scanRunning = false
    }

    /// Resolves IMAP credentials for an account from Keychain.
    private func resolveCredential(for account: MonitoredAccount) async -> IMAPCredential? {
        if account.usesOAuth {
            guard let refreshToken = KeychainHelper.loadRefreshToken(accountId: account.id),
                  let oauthProv = account.oauthProvider else { return nil }
            do {
                let tokens = try await oauthManager.refreshAccessToken(provider: oauthProv, refreshToken: refreshToken)
                KeychainHelper.saveTokens(
                    accountId: account.id,
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken ?? refreshToken
                )
                return .oauth2(email: account.discovered.email, accessToken: tokens.accessToken)
            } catch {
                logger.error("Token refresh failed for \(account.discovered.email): \(error.localizedDescription)")
                return nil
            }
        } else {
            guard let password = KeychainHelper.loadPassword(accountId: account.id) else { return nil }
            return .password(password)
        }
    }

    /// Deletes an email from the IMAP server using the stored UID.
    func deleteFromIMAP(verdict: Verdict) async {
        guard let uid = verdict.imapUID else {
            logger.warning("No IMAP UID for verdict \(verdict.messageId) — removing locally only")
            try? verdictStore.delete(messageId: verdict.messageId)
            return
        }

        // Find the activated account to create a monitor for deletion
        guard let account = accounts.first(where: { $0.isActivated }),
              let credential = await resolveCredential(for: account) else {
            logger.error("No activated account or credentials to delete email from")
            try? verdictStore.delete(messageId: verdict.messageId)
            return
        }

        let config = AccountConfig(
            displayName: account.discovered.name,
            imapServer: account.discovered.server,
            imapPort: account.discovered.port,
            username: account.discovered.email,
            useTLS: account.discovered.usesSSL,
            authMethod: account.usesOAuth ? .oauth2 : .password
        )

        let monitor = IMAPMonitor(account: config, analyzer: analyzer, verdictStore: verdictStore)

        do {
            try await monitor.connectAndDelete(uid: uid, credential: credential)
            logger.info("Deleted email UID \(uid) from IMAP")
        } catch {
            logger.error("IMAP delete failed: \(error.localizedDescription)")
        }

        try? verdictStore.delete(messageId: verdict.messageId)
    }

    // MARK: - Private

    private func startMonitor(accountId: String, credential: IMAPCredential) async {
        guard let index = accounts.firstIndex(where: { $0.id == accountId }) else { return }

        let account = accounts[index].discovered
        let config = AccountConfig(
            displayName: account.name,
            imapServer: account.server,
            imapPort: account.port,
            username: account.email,
            useTLS: account.usesSSL,
            authMethod: accounts[index].usesOAuth ? .oauth2 : .password
        )

        let monitor = IMAPMonitor(account: config, analyzer: analyzer, verdictStore: verdictStore)
        monitors[accountId] = monitor

        do {
            try await monitor.start(credential: credential)
            if let idx = accounts.firstIndex(where: { $0.id == accountId }) {
                accounts[idx].status = .monitoring
            }
        } catch {
            if let idx = accounts.firstIndex(where: { $0.id == accountId }) {
                accounts[idx].status = .error(error.localizedDescription)
            }
        }
    }

    /// Attempts to reconnect an activated account using stored credentials.
    private func reconnect(accountId: String) async {
        guard let index = accounts.firstIndex(where: { $0.id == accountId }) else { return }
        let account = accounts[index]

        if account.usesOAuth {
            // Try to load and refresh OAuth tokens
            guard let refreshToken = KeychainHelper.loadRefreshToken(accountId: accountId) else { return }

            let oauthProvider = account.oauthProvider!

            accounts[index].status = .connecting
            do {
                let tokens = try await oauthManager.refreshAccessToken(provider: oauthProvider, refreshToken: refreshToken)
                KeychainHelper.saveTokens(
                    accountId: accountId,
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken ?? refreshToken
                )
                await startMonitor(accountId: accountId, credential: .oauth2(email: account.discovered.email, accessToken: tokens.accessToken))
            } catch {
                if let idx = accounts.firstIndex(where: { $0.id == accountId }) {
                    accounts[idx].status = .error("Token refresh failed — please sign in again")
                }
            }
        } else {
            // Try to load password from Keychain
            guard let password = KeychainHelper.loadPassword(accountId: accountId) else { return }
            accounts[index].status = .connecting
            await startMonitor(accountId: accountId, credential: .password(password))
        }
    }

    // MARK: - Persistence

    private func loadActivatedAccountIds() -> Set<String> {
        let ids = UserDefaults.standard.stringArray(forKey: Self.activatedAccountsKey) ?? []
        return Set(ids)
    }

    private func saveActivatedAccountIds() {
        let ids = accounts.filter(\.isActivated).map(\.id)
        UserDefaults.standard.set(ids, forKey: Self.activatedAccountsKey)
    }
}
