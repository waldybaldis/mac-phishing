import Foundation

/// Delegate protocol for receiving IMAP monitor events.
public protocol IMAPMonitorDelegate: AnyObject, Sendable {
    func imapMonitor(_ monitor: IMAPMonitor, didReceiveEmail email: ParsedEmail)
    func imapMonitor(_ monitor: IMAPMonitor, didEncounterError error: Error)
    func imapMonitorDidConnect(_ monitor: IMAPMonitor)
    func imapMonitorDidDisconnect(_ monitor: IMAPMonitor)
}

/// Monitors an IMAP mailbox for new emails using IDLE.
///
/// This is a scaffold for the SwiftMail-based IMAP client.
/// In production, this would use SwiftMail's IMAPServer actor for:
/// - Connecting with TLS
/// - Authenticating with PLAIN/LOGIN
/// - SELECT INBOX
/// - IDLE for real-time new mail detection
/// - FETCH headers + body of new messages
/// - STORE flags and MOVE for junk classification
public final class IMAPMonitor: @unchecked Sendable {
    public enum State: Sendable {
        case disconnected
        case connecting
        case connected
        case monitoring
        case error(String)
    }

    public weak var delegate: IMAPMonitorDelegate?

    private let account: AccountConfig
    private let analyzer: PhishingAnalyzer
    private let verdictStore: VerdictStore
    private var state: State = .disconnected
    private var monitorTask: Task<Void, Never>?

    public init(account: AccountConfig, analyzer: PhishingAnalyzer, verdictStore: VerdictStore) {
        self.account = account
        self.analyzer = analyzer
        self.verdictStore = verdictStore
    }

    /// The current connection state.
    public var currentState: State { state }

    /// Starts monitoring the IMAP mailbox for new emails.
    ///
    /// In production, this will:
    /// 1. Connect to the IMAP server via TLS
    /// 2. Authenticate with stored credentials from Keychain
    /// 3. SELECT INBOX
    /// 4. Start IDLE to listen for new messages
    /// 5. On new message: FETCH and analyze
    public func start(password: String) async throws {
        guard case .disconnected = state else { return }

        state = .connecting

        // --- SwiftMail Integration Point ---
        // In production, replace this with:
        //
        // let server = IMAPServer(
        //     host: account.imapServer,
        //     port: account.imapPort
        // )
        // try await server.login(username: account.username, password: password)
        // let inbox = try await server.select(mailbox: "INBOX")
        // delegate?.imapMonitorDidConnect(self)
        //
        // state = .monitoring
        //
        // for try await event in server.idle() {
        //     switch event {
        //     case .newMessage(let uid):
        //         let message = try await server.fetch(uid: uid, items: [.headers, .body])
        //         let email = parseIMAPMessage(message)
        //         await processNewEmail(email)
        //     case .expunge:
        //         break
        //     }
        // }
        // ---

        state = .connected
        delegate?.imapMonitorDidConnect(self)
        state = .monitoring
    }

    /// Stops monitoring and disconnects.
    public func stop() {
        monitorTask?.cancel()
        monitorTask = nil
        state = .disconnected
        delegate?.imapMonitorDidDisconnect(self)
    }

    /// Processes a new email: analyze it and store the verdict.
    /// This method is public so it can be called by both IMAP and test code.
    public func processNewEmail(_ email: ParsedEmail) {
        let verdict = analyzer.analyze(email: email)

        // Store verdict
        try? verdictStore.save(verdict)

        // Notify delegate
        delegate?.imapMonitor(self, didReceiveEmail: email)

        // --- IMAP-side actions ---
        // In production:
        // if verdict.threatLevel == .phishing {
        //     try await server.move(uid: messageUID, toMailbox: "Junk")
        // } else if verdict.threatLevel == .suspicious {
        //     try await server.store(uid: messageUID, flags: [.flagged])
        // }
    }

    /// Flags a message as junk via IMAP (moves to Junk folder).
    public func moveToJunk(messageId: String) async throws {
        // In production: try await server.move(uid: uid, toMailbox: "Junk")
    }

    /// Marks a message with a flag via IMAP.
    public func flagMessage(messageId: String) async throws {
        // In production: try await server.store(uid: uid, flags: [.flagged])
    }
}

// MARK: - Email Parsing

extension IMAPMonitor {
    /// Parses raw IMAP message data into a ParsedEmail.
    /// This will be used when SwiftMail returns fetched message data.
    static func parseRawEmail(
        messageId: String,
        headers: [String: String],
        htmlBody: String?,
        textBody: String?,
        receivedDate: Date
    ) -> ParsedEmail {
        ParsedEmail(
            messageId: messageId,
            from: headers["From"] ?? "",
            returnPath: headers["Return-Path"],
            authenticationResults: headers["Authentication-Results"],
            subject: headers["Subject"] ?? "(no subject)",
            htmlBody: htmlBody,
            textBody: textBody,
            receivedDate: receivedDate,
            headers: headers
        )
    }
}
