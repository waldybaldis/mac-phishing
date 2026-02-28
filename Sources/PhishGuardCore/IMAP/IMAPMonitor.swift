import Foundation
import os.log
import SwiftMail

private let logger = Logger(subsystem: "com.phishguard", category: "IMAPMonitor")

/// Delegate protocol for receiving IMAP monitor events.
public protocol IMAPMonitorDelegate: AnyObject, Sendable {
    func imapMonitor(_ monitor: IMAPMonitor, didReceiveEmail email: ParsedEmail)
    func imapMonitor(_ monitor: IMAPMonitor, didEncounterError error: Error)
    func imapMonitorDidConnect(_ monitor: IMAPMonitor)
    func imapMonitorDidDisconnect(_ monitor: IMAPMonitor)
}

/// Credential used to authenticate with an IMAP server.
public enum IMAPCredential: Sendable {
    case password(String)
    case oauth2(email: String, accessToken: String)
}

/// Monitors an IMAP mailbox for new emails using IDLE.
public final class IMAPMonitor: @unchecked Sendable {
    public enum State: Sendable {
        case disconnected
        case connecting
        case connected
        case monitoring
        case error(String)
    }

    public enum MonitorError: LocalizedError {
        case connectionFailed(String)
        case loginFailed(String)
        case alreadyRunning

        public var errorDescription: String? {
            switch self {
            case .connectionFailed(let msg): return "Connection failed: \(msg)"
            case .loginFailed(let msg): return "Login failed: \(msg)"
            case .alreadyRunning: return "Monitor is already running"
            }
        }
    }

    public weak var delegate: IMAPMonitorDelegate?

    private let account: AccountConfig
    private let analyzer: PhishingAnalyzer
    private let verdictStore: VerdictStore
    private var state: State = .disconnected
    private var monitorTask: Task<Void, Never>?
    private var server: IMAPServer?
    private var idleSession: IMAPIdleSession?

    public init(account: AccountConfig, analyzer: PhishingAnalyzer, verdictStore: VerdictStore) {
        self.account = account
        self.analyzer = analyzer
        self.verdictStore = verdictStore
    }

    /// The current connection state.
    public var currentState: State { state }

    /// Starts monitoring the IMAP mailbox for new emails.
    public func start(credential: IMAPCredential) async throws {
        guard case .disconnected = state else {
            throw MonitorError.alreadyRunning
        }

        state = .connecting

        logger.info("Connecting to \(self.account.imapServer, privacy: .public):\(self.account.imapPort) (TLS: \(self.account.useTLS))")

        let imapServer = IMAPServer(host: account.imapServer, port: account.imapPort)
        self.server = imapServer

        do {
            try await imapServer.connect()
            logger.info("Connected successfully to \(self.account.imapServer, privacy: .public)")
        } catch {
            logger.error("Connection failed to \(self.account.imapServer, privacy: .public): \(error.localizedDescription, privacy: .public)")
            state = .error(error.localizedDescription)
            throw MonitorError.connectionFailed(error.localizedDescription)
        }

        do {
            switch credential {
            case .password(let password):
                logger.info("Logging in with password for user: \(self.account.username, privacy: .public) (password length: \(password.count))")
                try await imapServer.login(username: account.username, password: password)
            case .oauth2(let email, let accessToken):
                logger.info("Authenticating with XOAUTH2 for: \(email, privacy: .public)")
                try await imapServer.authenticateXOAUTH2(email: email, accessToken: accessToken)
            }
            logger.info("Authentication successful for \(self.account.username, privacy: .public)")
        } catch {
            logger.error("Authentication failed for \(self.account.username, privacy: .public): \(error.localizedDescription, privacy: .public)")
            try? await imapServer.disconnect()
            state = .error(error.localizedDescription)
            throw MonitorError.loginFailed(error.localizedDescription)
        }

        state = .connected
        delegate?.imapMonitorDidConnect(self)

        try await imapServer.selectMailbox("INBOX")
        state = .monitoring

        // Start IDLE monitoring in a background task
        monitorTask = Task { [weak self] in
            guard let self = self else { return }
            await self.runIdleLoop(server: imapServer)
        }
    }

    /// Runs the IDLE loop, listening for new messages.
    private func runIdleLoop(server: IMAPServer) async {
        do {
            let session = try await server.idle(on: "INBOX")
            self.idleSession = session

            for await event in session.events {
                guard !Task.isCancelled else { break }

                switch event {
                case .exists(let count):
                    // New message(s) — fetch the latest
                    await fetchAndAnalyzeLatest(server: server, messageCount: count)
                default:
                    break
                }
            }
        } catch {
            if !Task.isCancelled {
                state = .error(error.localizedDescription)
                delegate?.imapMonitor(self, didEncounterError: error)
            }
        }
    }

    /// Fetches the latest message and runs phishing analysis.
    private func fetchAndAnalyzeLatest(server: IMAPServer, messageCount: Int) async {
        do {
            let seqNum = SequenceNumber(messageCount)
            guard let messageInfo = try await server.fetchMessageInfo(for: seqNum) else { return }

            // Fetch the full message for body content
            let message = try await server.fetchMessage(from: messageInfo)

            // Fetch raw message data for full headers (Authentication-Results, Return-Path, etc.)
            let headers = await extractHeaders(server: server, messageInfo: messageInfo)

            let email = ParsedEmail(
                messageId: messageInfo.messageId ?? UUID().uuidString,
                from: messageInfo.from ?? "",
                returnPath: headers["Return-Path"],
                authenticationResults: headers["Authentication-Results"],
                subject: messageInfo.subject ?? "(no subject)",
                htmlBody: message.htmlBody,
                textBody: message.textBody,
                receivedDate: messageInfo.internalDate ?? Date(),
                headers: headers
            )

            processNewEmail(email)
        } catch {
            delegate?.imapMonitor(self, didEncounterError: error)
        }
    }

    /// Extracts headers from raw message data.
    private func extractHeaders(server: IMAPServer, messageInfo: MessageInfo) async -> [String: String] {
        var headers: [String: String] = [:]

        // Use additionalFields if available
        if let additional = messageInfo.additionalFields {
            headers.merge(additional) { _, new in new }
        }

        // Try to fetch raw message for complete headers
        if let uid = messageInfo.uid {
            do {
                let rawData = try await server.fetchRawMessage(identifier: uid)
                if let rawString = String(data: rawData, encoding: .utf8) {
                    let parsed = Self.parseRawHeaders(rawString)
                    headers.merge(parsed) { _, new in new }
                }
            } catch {
                // Fall back to what we have from envelope
            }
        }

        // Ensure From is always present
        if headers["From"] == nil, let from = messageInfo.from {
            headers["From"] = from
        }
        if headers["Subject"] == nil, let subject = messageInfo.subject {
            headers["Subject"] = subject
        }

        return headers
    }

    /// Parses raw RFC 2822 header text into a dictionary.
    static func parseRawHeaders(_ raw: String) -> [String: String] {
        var headers: [String: String] = [:]

        // Split at the blank line separating headers from body
        let headerSection: String
        if let range = raw.range(of: "\r\n\r\n") {
            headerSection = String(raw[raw.startIndex..<range.lowerBound])
        } else if let range = raw.range(of: "\n\n") {
            headerSection = String(raw[raw.startIndex..<range.lowerBound])
        } else {
            headerSection = raw
        }

        // Unfold continuation lines (lines starting with whitespace)
        let unfolded = headerSection
            .replacingOccurrences(of: "\r\n ", with: " ")
            .replacingOccurrences(of: "\r\n\t", with: " ")
            .replacingOccurrences(of: "\n ", with: " ")
            .replacingOccurrences(of: "\n\t", with: " ")

        for line in unfolded.components(separatedBy: .newlines) {
            guard let colonIndex = line.firstIndex(of: ":") else { continue }
            let key = String(line[line.startIndex..<colonIndex]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { continue }
            headers[key] = value
        }

        return headers
    }

    /// Processes a new email: analyze it and store the verdict.
    public func processNewEmail(_ email: ParsedEmail) {
        let verdict = analyzer.analyze(email: email)
        try? verdictStore.save(verdict)
        delegate?.imapMonitor(self, didReceiveEmail: email)
    }

    /// Moves a message to the Junk folder via IMAP.
    public func moveToJunk(uid: UInt32) async throws {
        guard let server = self.server else { return }
        let uidValue = UID(uid)
        let uidSet = MessageIdentifierSet<UID>(uidValue)
        try await server.move(messages: uidSet, to: "Junk")
    }

    /// Flags a message via IMAP.
    public func flagMessage(uid: UInt32) async throws {
        guard let server = self.server else { return }
        let uidValue = UID(uid)
        let uidSet = MessageIdentifierSet<UID>(uidValue)
        try await server.store(flags: [.flagged], on: uidSet, operation: .add)
    }

    /// Stops monitoring and disconnects.
    public func stop() {
        monitorTask?.cancel()
        monitorTask = nil

        Task {
            try? await idleSession?.done()
            try? await server?.logout()
            try? await server?.disconnect()
        }

        idleSession = nil
        server = nil
        state = .disconnected
        delegate?.imapMonitorDidDisconnect(self)
    }
}
