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
/// @unchecked Sendable: mutable state (state, monitorTask, server, idleSession) is
/// protected by stateLock. Background tasks only read immutable config and call
/// thread-safe stores.
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
    private let accountId: String?
    private let stateLock = NSLock()
    private var _state: State = .disconnected
    private var monitorTask: Task<Void, Never>?
    private var server: IMAPServer?
    private var idleSession: IMAPIdleSession?
    private var storedCredential: IMAPCredential?

    private var state: State {
        get { stateLock.withLock { _state } }
        set { stateLock.withLock { _state = newValue } }
    }

    public init(account: AccountConfig, analyzer: PhishingAnalyzer, verdictStore: VerdictStore, accountId: String? = nil) {
        self.account = account
        self.analyzer = analyzer
        self.verdictStore = verdictStore
        self.accountId = accountId
    }

    /// The current connection state.
    public var currentState: State { state }

    /// Starts monitoring the IMAP mailbox for new emails.
    public func start(credential: IMAPCredential) async throws {
        guard case .disconnected = state else {
            throw MonitorError.alreadyRunning
        }

        state = .connecting
        self.storedCredential = credential

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
    /// Maximum number of consecutive reconnection attempts before giving up.
    private static let maxReconnectAttempts = 5

    private func runIdleLoop(server: IMAPServer) async {
        var currentServer = server
        var reconnectAttempts = 0

        while !Task.isCancelled {
            do {
                let session = try await currentServer.idle(on: "INBOX")
                self.idleSession = session
                reconnectAttempts = 0 // Reset on successful IDLE start

                for await event in session.events {
                    guard !Task.isCancelled else { return }

                    switch event {
                    case .exists(let count):
                        // New message(s) — fetch the latest using a separate connection
                        await fetchAndAnalyzeLatest(messageCount: count)
                    case .bye:
                        // Server or channel disconnected — break out to reconnect
                        logger.info("IDLE session received BYE for \(self.account.username, privacy: .public), will reconnect")
                    default:
                        break
                    }
                }

                // Stream ended (channel dropped or BYE received) — reconnect
                guard !Task.isCancelled else { return }
                logger.info("IDLE stream ended for \(self.account.username, privacy: .public), attempting reconnect")

            } catch {
                guard !Task.isCancelled else { return }
                logger.error("IDLE error for \(self.account.username, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }

            // Reconnect with exponential backoff
            reconnectAttempts += 1
            if reconnectAttempts > Self.maxReconnectAttempts {
                state = .error("Disconnected after \(Self.maxReconnectAttempts) reconnection attempts")
                delegate?.imapMonitor(self, didEncounterError: MonitorError.connectionFailed("Max reconnection attempts reached"))
                return
            }

            let delay = min(UInt64(pow(2.0, Double(reconnectAttempts))) * 1_000_000_000, 30_000_000_000) // 2s, 4s, 8s, 16s, 30s cap
            logger.info("Reconnecting in \(delay / 1_000_000_000)s (attempt \(reconnectAttempts)/\(Self.maxReconnectAttempts)) for \(self.account.username, privacy: .public)")
            try? await Task.sleep(nanoseconds: delay)
            guard !Task.isCancelled else { return }

            // Disconnect old server and create a fresh connection
            try? await currentServer.disconnect()
            self.idleSession = nil

            let newServer = IMAPServer(host: account.imapServer, port: account.imapPort)
            do {
                try await newServer.connect()
                guard let credential = storedCredential else {
                    state = .error("No credentials for reconnection")
                    return
                }
                switch credential {
                case .password(let password):
                    try await newServer.login(username: account.username, password: password)
                case .oauth2(let email, let accessToken):
                    try await newServer.authenticateXOAUTH2(email: email, accessToken: accessToken)
                }
                try await newServer.selectMailbox("INBOX")
                currentServer = newServer
                self.server = newServer
                state = .monitoring
                logger.info("Reconnected successfully for \(self.account.username, privacy: .public)")
            } catch {
                guard !Task.isCancelled else { return }
                logger.error("Reconnect failed for \(self.account.username, privacy: .public): \(error.localizedDescription, privacy: .public)")
                try? await newServer.disconnect()
                // Loop will retry with backoff
            }
        }
    }

    /// Fetches the latest message and runs phishing analysis.
    /// Uses a separate IMAP connection to avoid conflicting with the IDLE session.
    private func fetchAndAnalyzeLatest(messageCount: Int) async {
        guard let credential = storedCredential else { return }

        let fetchServer = IMAPServer(host: account.imapServer, port: account.imapPort)
        do {
            try await fetchServer.connect()
            switch credential {
            case .password(let password):
                try await fetchServer.login(username: account.username, password: password)
            case .oauth2(let email, let accessToken):
                try await fetchServer.authenticateXOAUTH2(email: email, accessToken: accessToken)
            }
            try await fetchServer.selectMailbox("INBOX")

            let seqNum = SequenceNumber(messageCount)
            guard let messageInfo = try await fetchServer.fetchMessageInfo(for: seqNum) else {
                try? await fetchServer.logout()
                try? await fetchServer.disconnect()
                return
            }

            // Fetch the full message for body content
            let message = try await fetchServer.fetchMessage(from: messageInfo)

            // Fetch raw message data for full headers (Authentication-Results, Return-Path, etc.)
            let headers = await extractHeaders(server: fetchServer, messageInfo: messageInfo)

            let email = ParsedEmail(
                messageId: messageInfo.messageId?.description ?? UUID().uuidString,
                from: messageInfo.from ?? "",
                returnPath: headers["Return-Path"],
                authenticationResults: headers["Authentication-Results"],
                subject: messageInfo.subject ?? "(no subject)",
                htmlBody: message.htmlBody,
                textBody: message.textBody,
                receivedDate: messageInfo.internalDate ?? Date(),
                headers: headers
            )

            try? await fetchServer.logout()
            try? await fetchServer.disconnect()

            processNewEmail(email, imapUID: messageInfo.uid?.value)
        } catch {
            try? await fetchServer.logout()
            try? await fetchServer.disconnect()
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
    public func processNewEmail(_ email: ParsedEmail, imapUID: UInt32? = nil) {
        let verdict = analyzer.analyze(email: email, imapUID: imapUID, accountId: accountId)
        do {
            try verdictStore.save(verdict)
        } catch {
            logger.error("Failed to save verdict for \(email.messageId): \(error.localizedDescription)")
        }
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

    /// Moves a message to Trash via IMAP.
    public func deleteEmail(uid: UInt32) async throws {
        guard let server = self.server else { return }
        let uidValue = UID(uid)
        let uidSet = MessageIdentifierSet<UID>(uidValue)
        try await server.moveToTrash(messages: uidSet)
    }

    /// Creates a temporary IMAP connection, deletes the email, and disconnects.
    public func connectAndDelete(uid: UInt32, credential: IMAPCredential) async throws {
        let tempServer = IMAPServer(host: account.imapServer, port: account.imapPort)
        try await tempServer.connect()
        switch credential {
        case .password(let password):
            try await tempServer.login(username: account.username, password: password)
        case .oauth2(let email, let accessToken):
            try await tempServer.authenticateXOAUTH2(email: email, accessToken: accessToken)
        }
        try await tempServer.selectMailbox("INBOX")

        let uidValue = UID(uid)
        let uidSet = MessageIdentifierSet<UID>(uidValue)
        try await tempServer.moveToTrash(messages: uidSet)

        try? await tempServer.logout()
        try? await tempServer.disconnect()
    }

    // MARK: - Inbox Scan

    /// Result of an inbox scan with timing breakdown.
    public struct ScanResult: Sendable {
        public let emailCount: Int
        public let fetchInfoTime: TimeInterval
        public let fetchBodiesTime: TimeInterval
        public let fetchHeadersTime: TimeInterval
        public let analysisTime: TimeInterval
        public let storageTime: TimeInterval
        public let totalTime: TimeInterval
        public let skippedParts: Int
        public let saveFailures: Int

        public init(emailCount: Int, fetchInfoTime: TimeInterval, fetchBodiesTime: TimeInterval,
                    fetchHeadersTime: TimeInterval, analysisTime: TimeInterval, storageTime: TimeInterval,
                    totalTime: TimeInterval, skippedParts: Int, saveFailures: Int = 0) {
            self.emailCount = emailCount
            self.fetchInfoTime = fetchInfoTime
            self.fetchBodiesTime = fetchBodiesTime
            self.fetchHeadersTime = fetchHeadersTime
            self.analysisTime = analysisTime
            self.storageTime = storageTime
            self.totalTime = totalTime
            self.skippedParts = skippedParts
            self.saveFailures = saveFailures
        }
    }

    /// Fetches the last `count` emails, runs phishing analysis, and returns timing stats.
    /// Uses a separate IMAP connection so it doesn't disturb the IDLE monitor.
    public func scanInbox(count: Int, credential: IMAPCredential) async throws -> ScanResult {
        let benchServer = IMAPServer(host: account.imapServer, port: account.imapPort)
        let totalStart = CFAbsoluteTimeGetCurrent()

        // Connect & authenticate
        try await benchServer.connect()
        switch credential {
        case .password(let password):
            try await benchServer.login(username: account.username, password: password)
        case .oauth2(let email, let accessToken):
            try await benchServer.authenticateXOAUTH2(email: email, accessToken: accessToken)
        }

        let selection = try await benchServer.selectMailbox("INBOX")
        let messageCount = selection.messageCount
        guard messageCount > 0 else {
            try? await benchServer.logout()
            try? await benchServer.disconnect()
            return ScanResult(
                emailCount: 0, fetchInfoTime: 0, fetchBodiesTime: 0,
                fetchHeadersTime: 0, analysisTime: 0, storageTime: 0,
                totalTime: 0, skippedParts: 0
            )
        }

        let fetchCount = count > 0 ? min(count, messageCount) : messageCount
        let startSeq = max(1, messageCount - fetchCount + 1)
        let seqRange = SequenceNumber(UInt32(startSeq))...SequenceNumber(UInt32(messageCount))
        let seqSet = MessageIdentifierSet<SequenceNumber>(seqRange)

        // Phase 1: Bulk fetch message info (envelope + MIME structure)
        let p1Start = CFAbsoluteTimeGetCurrent()
        let messageInfos = try await benchServer.fetchMessageInfosBulk(using: seqSet)
        let p1Time = CFAbsoluteTimeGetCurrent() - p1Start

        logger.info("Scan: fetched \(messageInfos.count) message infos in \(String(format: "%.2f", p1Time))s")

        // Create worker connections sequentially to avoid rate-limiting (e.g. Yahoo)
        let maxWorkers = 3
        let connStart = CFAbsoluteTimeGetCurrent()
        var workers: [IMAPServer] = []
        for i in 0..<maxWorkers {
            let worker = IMAPServer(host: self.account.imapServer, port: self.account.imapPort)
            do {
                try await worker.connect()
                switch credential {
                case .password(let password):
                    try await worker.login(username: self.account.username, password: password)
                case .oauth2(let email, let accessToken):
                    try await worker.authenticateXOAUTH2(email: email, accessToken: accessToken)
                }
                try await worker.selectMailbox("INBOX")
                workers.append(worker)
            } catch {
                logger.warning("Scan: failed to create worker \(i): \(error.localizedDescription)")
                break  // Stop trying if a connection fails (likely rate-limited)
            }
        }
        let connTime = CFAbsoluteTimeGetCurrent() - connStart
        logger.info("Scan: \(workers.count) worker connections in \(String(format: "%.2f", connTime))s")
        if workers.isEmpty { workers.append(benchServer) }

        // Phase 2: Fetch text body parts only (skip attachments) — parallel
        // Optimization: prefer HTML (needed for link analysis); only fetch text/plain
        // as fallback when no HTML part exists.
        let p2Start = CFAbsoluteTimeGetCurrent()
        let p2Results: [(Int, String?, String?, Int)] = await withTaskGroup(of: (Int, String?, String?, Int).self) { group in
            for (idx, info) in messageInfos.enumerated() {
                let worker = workers[idx % workers.count]
                group.addTask {
                    var html: String?
                    var text: String?
                    var skipped = 0
                    let identifier = info.sequenceNumber

                    // Separate parts by type
                    var htmlPart: MessagePart?
                    var textPart: MessagePart?
                    for part in info.parts {
                        let ct = part.contentType.lowercased()
                        if ct.hasPrefix("text/html") && htmlPart == nil {
                            htmlPart = part
                        } else if ct.hasPrefix("text/plain") && textPart == nil {
                            textPart = part
                        } else {
                            skipped += 1
                        }
                    }

                    // Fetch HTML first (primary need for link analysis)
                    if let part = htmlPart {
                        if let rawData = try? await worker.fetchPart(section: part.section, of: identifier) {
                            // Decode content-transfer-encoding (quoted-printable, base64)
                            let decoded = rawData.decoded(for: part)
                            html = String(data: decoded, encoding: .utf8)
                        }
                    }

                    // Only fetch text/plain if no HTML available (fallback for IP URL check)
                    if html == nil, let part = textPart {
                        if let rawData = try? await worker.fetchPart(section: part.section, of: identifier) {
                            let decoded = rawData.decoded(for: part)
                            text = String(data: decoded, encoding: .utf8)
                        }
                    } else if textPart != nil {
                        skipped += 1  // count skipped text/plain
                    }

                    if info.parts.isEmpty {
                        let message = try? await worker.fetchMessage(from: info)
                        html = message?.htmlBody
                        text = message?.textBody
                    }

                    return (idx, html, text, skipped)
                }
            }
            var results: [(Int, String?, String?, Int)] = []
            for await result in group {
                results.append(result)
            }
            return results
        }
        var textBodies: [Int: (html: String?, text: String?)] = [:]
        var skippedParts = 0
        for (idx, html, text, skipped) in p2Results {
            textBodies[idx] = (html: html, text: text)
            skippedParts += skipped
        }
        let p2Time = CFAbsoluteTimeGetCurrent() - p2Start

        // Phase 3: Use raw headers from bulk fetch (additionalFields),
        // only fall back to fetchRawMessage (parallel) for messages missing key headers
        let p3Start = CFAbsoluteTimeGetCurrent()
        let p3Results: [(Int, [String: String], Bool)] = await withTaskGroup(of: (Int, [String: String], Bool).self) { group in
            for (idx, info) in messageInfos.enumerated() {
                let worker = workers[idx % workers.count]
                group.addTask {
                    var headers: [String: String] = info.additionalFields ?? [:]
                    var didFallback = false

                    // Only fetch raw message if bulk fetch didn't provide key headers
                    if headers["Authentication-Results"] == nil && headers["Return-Path"] == nil {
                        if let uid = info.uid {
                            if let rawData = try? await worker.fetchRawMessage(identifier: uid),
                               let rawString = String(data: rawData, encoding: .utf8) {
                                let parsed = Self.parseRawHeaders(rawString)
                                headers.merge(parsed) { _, new in new }
                            }
                            didFallback = true
                        }
                    }

                    if headers["From"] == nil, let from = info.from {
                        headers["From"] = from
                    }
                    if headers["Subject"] == nil, let subject = info.subject {
                        headers["Subject"] = subject
                    }
                    return (idx, headers, didFallback)
                }
            }
            var results: [(Int, [String: String], Bool)] = []
            for await result in group {
                results.append(result)
            }
            return results
        }
        var allHeaders: [Int: [String: String]] = [:]
        var fallbackCount = 0
        for (idx, headers, didFallback) in p3Results {
            allHeaders[idx] = headers
            if didFallback { fallbackCount += 1 }
        }
        let p3Time = CFAbsoluteTimeGetCurrent() - p3Start

        // Cleanup worker connections
        for worker in workers where worker !== benchServer {
            try? await worker.logout()
            try? await worker.disconnect()
        }

        // Phase 4: Build ParsedEmail and run analysis
        var verdicts: [Verdict] = []
        let p4Start = CFAbsoluteTimeGetCurrent()

        for (idx, info) in messageInfos.enumerated() {
            let bodies = textBodies[idx] ?? (html: nil, text: nil)
            let headers = allHeaders[idx] ?? [:]

            let email = ParsedEmail(
                messageId: info.messageId?.description ?? UUID().uuidString,
                from: info.from ?? "",
                returnPath: headers["Return-Path"],
                authenticationResults: headers["Authentication-Results"],
                subject: info.subject ?? "(no subject)",
                htmlBody: bodies.html,
                textBody: bodies.text,
                receivedDate: info.internalDate ?? Date(),
                headers: headers
            )

            let verdict = analyzer.analyze(email: email, imapUID: info.uid?.value, accountId: accountId)
            verdicts.append(verdict)
        }
        let p4Time = CFAbsoluteTimeGetCurrent() - p4Start

        // Phase 5: Store verdicts
        let p5Start = CFAbsoluteTimeGetCurrent()
        var saveFailures = 0
        for verdict in verdicts {
            do {
                try verdictStore.save(verdict)
            } catch {
                saveFailures += 1
                logger.error("Failed to save verdict for \(verdict.messageId): \(error.localizedDescription)")
            }
        }
        let p5Time = CFAbsoluteTimeGetCurrent() - p5Start
        if saveFailures > 0 {
            logger.warning("Scan: \(saveFailures) verdict(s) failed to save")
        }

        // Cleanup
        try? await benchServer.logout()
        try? await benchServer.disconnect()

        let totalTime = CFAbsoluteTimeGetCurrent() - totalStart
        let n = Double(messageInfos.count)

        // Log timing breakdown
        logger.info("""
        === PhishGuard Inbox Scan: \(messageInfos.count) emails ===
        Worker connections (\(workers.count)):         \(String(format: "%.2f", connTime))s
        Phase 1 - Fetch message info (bulk):  \(String(format: "%.2f", p1Time))s
        Phase 2 - Fetch text bodies:          \(String(format: "%.2f", p2Time))s  (avg \(String(format: "%.3f", p2Time / max(n, 1)))s/email)
        Phase 3 - Fetch raw headers:          \(String(format: "%.2f", p3Time))s  (avg \(String(format: "%.3f", p3Time / max(n, 1)))s/email)
        Phase 4 - Phishing analysis:          \(String(format: "%.2f", p4Time))s  (avg \(String(format: "%.3f", p4Time / max(n, 1)))s/email)
        Phase 5 - Verdict storage:            \(String(format: "%.2f", p5Time))s
        ─────────────────────────────────────
        Total:                                 \(String(format: "%.2f", totalTime))s  (avg \(String(format: "%.3f", totalTime / max(n, 1)))s/email)
        Extrapolated for 1000 emails:          ~\(String(format: "%.1f", totalTime / max(n, 1) * 1000))s
        Emails with attachments skipped:       \(skippedParts) parts skipped
        """)

        return ScanResult(
            emailCount: messageInfos.count,
            fetchInfoTime: p1Time,
            fetchBodiesTime: p2Time,
            fetchHeadersTime: p3Time,
            analysisTime: p4Time,
            storageTime: p5Time,
            totalTime: totalTime,
            skippedParts: skippedParts,
            saveFailures: saveFailures
        )
    }

    /// Scans only unseen (unread) messages in the inbox.
    /// Uses IMAP SEARCH UNSEEN to find unread messages, then analyzes them.
    public func scanUnseen(credential: IMAPCredential) async throws -> ScanResult {
        let benchServer = IMAPServer(host: account.imapServer, port: account.imapPort)
        let totalStart = CFAbsoluteTimeGetCurrent()

        try await benchServer.connect()
        switch credential {
        case .password(let password):
            try await benchServer.login(username: account.username, password: password)
        case .oauth2(let email, let accessToken):
            try await benchServer.authenticateXOAUTH2(email: email, accessToken: accessToken)
        }

        try await benchServer.selectMailbox("INBOX")

        // Search for unseen messages
        let unseenUIDs: MessageIdentifierSet<UID> = try await benchServer.search(criteria: [.unseen])
        guard !unseenUIDs.isEmpty else {
            try? await benchServer.logout()
            try? await benchServer.disconnect()
            return ScanResult(
                emailCount: 0, fetchInfoTime: 0, fetchBodiesTime: 0,
                fetchHeadersTime: 0, analysisTime: 0, storageTime: 0,
                totalTime: CFAbsoluteTimeGetCurrent() - totalStart, skippedParts: 0
            )
        }

        logger.info("Unseen scan: found \(unseenUIDs.count) unread messages")

        // Reuse the same pipeline as scanInbox but with UID set
        let p1Start = CFAbsoluteTimeGetCurrent()
        let messageInfos = try await benchServer.fetchMessageInfosBulk(using: unseenUIDs)
        let p1Time = CFAbsoluteTimeGetCurrent() - p1Start

        // Single connection for unseen scan (typically few messages)
        var skippedParts = 0
        let p2Start = CFAbsoluteTimeGetCurrent()
        var textBodies: [Int: (html: String?, text: String?)] = [:]
        for (idx, info) in messageInfos.enumerated() {
            var html: String?
            var text: String?
            let identifier = info.sequenceNumber

            var htmlPart: MessagePart?
            var textPart: MessagePart?
            for part in info.parts {
                let ct = part.contentType.lowercased()
                if ct.hasPrefix("text/html") && htmlPart == nil {
                    htmlPart = part
                } else if ct.hasPrefix("text/plain") && textPart == nil {
                    textPart = part
                } else {
                    skippedParts += 1
                }
            }

            if let part = htmlPart {
                if let rawData = try? await benchServer.fetchPart(section: part.section, of: identifier) {
                    let decoded = rawData.decoded(for: part)
                    html = String(data: decoded, encoding: .utf8)
                }
            }
            if html == nil, let part = textPart {
                if let rawData = try? await benchServer.fetchPart(section: part.section, of: identifier) {
                    let decoded = rawData.decoded(for: part)
                    text = String(data: decoded, encoding: .utf8)
                }
            } else if textPart != nil {
                skippedParts += 1
            }
            if info.parts.isEmpty {
                let message = try? await benchServer.fetchMessage(from: info)
                html = message?.htmlBody
                text = message?.textBody
            }
            textBodies[idx] = (html: html, text: text)
        }
        let p2Time = CFAbsoluteTimeGetCurrent() - p2Start

        // Headers
        let p3Start = CFAbsoluteTimeGetCurrent()
        var allHeaders: [Int: [String: String]] = [:]
        for (idx, info) in messageInfos.enumerated() {
            var headers: [String: String] = info.additionalFields ?? [:]
            if headers["Authentication-Results"] == nil && headers["Return-Path"] == nil {
                if let uid = info.uid {
                    if let rawData = try? await benchServer.fetchRawMessage(identifier: uid),
                       let rawString = String(data: rawData, encoding: .utf8) {
                        let parsed = Self.parseRawHeaders(rawString)
                        headers.merge(parsed) { _, new in new }
                    }
                }
            }
            if headers["From"] == nil, let from = info.from { headers["From"] = from }
            if headers["Subject"] == nil, let subject = info.subject { headers["Subject"] = subject }
            allHeaders[idx] = headers
        }
        let p3Time = CFAbsoluteTimeGetCurrent() - p3Start

        // Analysis
        let p4Start = CFAbsoluteTimeGetCurrent()
        var verdicts: [Verdict] = []
        for (idx, info) in messageInfos.enumerated() {
            let bodies = textBodies[idx] ?? (html: nil, text: nil)
            let headers = allHeaders[idx] ?? [:]
            let email = ParsedEmail(
                messageId: info.messageId?.description ?? UUID().uuidString,
                from: info.from ?? "",
                returnPath: headers["Return-Path"],
                authenticationResults: headers["Authentication-Results"],
                subject: info.subject ?? "(no subject)",
                htmlBody: bodies.html,
                textBody: bodies.text,
                receivedDate: info.internalDate ?? Date(),
                headers: headers
            )
            let verdict = analyzer.analyze(email: email, imapUID: info.uid?.value, accountId: accountId)
            verdicts.append(verdict)
        }
        let p4Time = CFAbsoluteTimeGetCurrent() - p4Start

        // Store
        let p5Start = CFAbsoluteTimeGetCurrent()
        var saveFailures = 0
        for verdict in verdicts {
            do { try verdictStore.save(verdict) }
            catch { saveFailures += 1 }
        }
        let p5Time = CFAbsoluteTimeGetCurrent() - p5Start

        try? await benchServer.logout()
        try? await benchServer.disconnect()

        let totalTime = CFAbsoluteTimeGetCurrent() - totalStart
        logger.info("Unseen scan: \(messageInfos.count) emails analyzed in \(String(format: "%.2f", totalTime))s")

        return ScanResult(
            emailCount: messageInfos.count,
            fetchInfoTime: p1Time,
            fetchBodiesTime: p2Time,
            fetchHeadersTime: p3Time,
            analysisTime: p4Time,
            storageTime: p5Time,
            totalTime: totalTime,
            skippedParts: skippedParts,
            saveFailures: saveFailures
        )
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
        storedCredential = nil
        state = .disconnected
        delegate?.imapMonitorDidDisconnect(self)
    }
}
