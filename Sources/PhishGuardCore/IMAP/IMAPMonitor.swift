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

            processNewEmail(email, imapUID: messageInfo.uid?.value)
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
    public func processNewEmail(_ email: ParsedEmail, imapUID: UInt32? = nil) {
        let verdict = analyzer.analyze(email: email, imapUID: imapUID)
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

    // MARK: - Benchmark

    /// Result of a benchmark scan with timing breakdown.
    public struct BenchmarkResult: Sendable {
        public let emailCount: Int
        public let fetchInfoTime: TimeInterval
        public let fetchBodiesTime: TimeInterval
        public let fetchHeadersTime: TimeInterval
        public let analysisTime: TimeInterval
        public let storageTime: TimeInterval
        public let totalTime: TimeInterval
        public let skippedParts: Int
    }

    /// Fetches the last `count` emails, runs phishing analysis, and returns timing stats.
    /// Uses a separate IMAP connection so it doesn't disturb the IDLE monitor.
    public func benchmarkScan(count: Int, credential: IMAPCredential) async throws -> BenchmarkResult {
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
            return BenchmarkResult(
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

        logger.info("Benchmark: fetched \(messageInfos.count) message infos in \(String(format: "%.2f", p1Time))s")

        // Create worker connections in parallel for Phases 2 & 3
        let workerCount = 10
        let connStart = CFAbsoluteTimeGetCurrent()
        let workerResults: [IMAPServer?] = await withTaskGroup(of: (Int, IMAPServer?).self) { group in
            for i in 0..<workerCount {
                group.addTask {
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
                        return (i, worker)
                    } catch {
                        logger.warning("Benchmark: failed to create worker \(i): \(error.localizedDescription)")
                        return (i, nil)
                    }
                }
            }
            var results = Array<IMAPServer?>(repeating: nil, count: workerCount)
            for await (i, worker) in group {
                results[i] = worker
            }
            return results
        }
        var workers: [IMAPServer] = workerResults.compactMap { $0 }
        let connTime = CFAbsoluteTimeGetCurrent() - connStart
        logger.info("Benchmark: \(workers.count) worker connections in \(String(format: "%.2f", connTime))s")
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
                messageId: info.messageId ?? UUID().uuidString,
                from: info.from ?? "",
                returnPath: headers["Return-Path"],
                authenticationResults: headers["Authentication-Results"],
                subject: info.subject ?? "(no subject)",
                htmlBody: bodies.html,
                textBody: bodies.text,
                receivedDate: info.internalDate ?? Date(),
                headers: headers
            )

            let verdict = analyzer.analyze(email: email, imapUID: info.uid?.value)
            verdicts.append(verdict)
        }
        let p4Time = CFAbsoluteTimeGetCurrent() - p4Start

        // Phase 5: Store verdicts
        let p5Start = CFAbsoluteTimeGetCurrent()
        for verdict in verdicts {
            try? verdictStore.save(verdict)
        }
        let p5Time = CFAbsoluteTimeGetCurrent() - p5Start

        // Cleanup
        try? await benchServer.logout()
        try? await benchServer.disconnect()

        let totalTime = CFAbsoluteTimeGetCurrent() - totalStart
        let n = Double(messageInfos.count)

        // Log timing breakdown
        logger.info("""
        === PhishGuard Benchmark: \(messageInfos.count) emails ===
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

        return BenchmarkResult(
            emailCount: messageInfos.count,
            fetchInfoTime: p1Time,
            fetchBodiesTime: p2Time,
            fetchHeadersTime: p3Time,
            analysisTime: p4Time,
            storageTime: p5Time,
            totalTime: totalTime,
            skippedParts: skippedParts
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
        state = .disconnected
        delegate?.imapMonitorDidDisconnect(self)
    }
}
