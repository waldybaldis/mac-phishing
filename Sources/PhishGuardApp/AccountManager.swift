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
        } else if server.contains("icloud") || server.contains("mail.me.com") || server.contains("mac.com") {
            return .icloud
        }
        return .custom
    }

    /// Whether this account uses OAuth2 for authentication.
    /// Only true if the provider supports OAuth AND a real client ID is configured.
    var usesOAuth: Bool {
        guard provider.authMethod == .oauth2 else { return false }
        let oauthProvider: OAuthConfig.Provider = provider == .gmail ? .google : .microsoft
        return OAuthConfig.isConfigured(for: oauthProvider)
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
    private let dbManager: DatabaseManager?

    private static let activatedAccountsKey = "activatedAccounts"

    init() {
        let db = try? DatabaseManager()
        self.dbManager = db
        if let db = db {
            let blacklistStore = BlacklistStore(database: db)
            self.verdictStore = VerdictStore(database: db)
            self.analyzer = PhishingAnalyzer(blacklistStore: blacklistStore)
        } else {
            self.verdictStore = VerdictStore(database: try! DatabaseManager(databasePath: ":memory:"))
            self.analyzer = PhishingAnalyzer(checks: [
                AuthHeaderCheck(),
                ReturnPathCheck(),
                LinkMismatchCheck(),
                IPURLCheck(),
                SuspiciousTLDCheck(),
            ])
        }
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
        let oauthProvider: OAuthConfig.Provider = account.provider == .gmail ? .google : .microsoft

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

    /// Injects a fake phishing email into the analysis pipeline for testing.
    func injectTestPhishingEmail() {
        let testEmail = ParsedEmail(
            messageId: "test-\(UUID().uuidString)@fedrex.com",
            from: "FedEx Support <tracking-update@fedrex.xyz>",
            returnPath: "bounce@mail-server.suspicious-domain.ru",
            authenticationResults: "spf=fail; dkim=fail; dmarc=fail",
            subject: "URGENT: Your package is held - verify your address now!",
            htmlBody: """
            <html><body>
            <p>Dear Customer,</p>
            <p>Your package #38291 is waiting. Please <a href="http://192.168.1.100/track">click here to verify</a> your delivery address.</p>
            <p>Or visit <a href="http://fedrex.xyz/verify">FedEx tracking</a> to update your information.</p>
            <p>Act within 24 hours or your package will be returned!</p>
            </body></html>
            """,
            textBody: "Your package is held. Click http://192.168.1.100/track to verify.",
            receivedDate: Date(),
            headers: [
                "From": "FedEx Support <tracking-update@fedrex.xyz>",
                "Return-Path": "<bounce@mail-server.suspicious-domain.ru>",
                "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
            ]
        )

        let verdict = analyzer.analyze(email: testEmail)
        try? verdictStore.save(verdict)
        logger.info("Injected test phishing email — score: \(verdict.score), reasons: \(verdict.reasons.count)")
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

            let oauthProvider: OAuthConfig.Provider = account.provider == .gmail ? .google : .microsoft

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
