import XCTest
@testable import PhishGuardCore

final class JevSignalCheckTests: XCTestCase {

    // MARK: - Signal mapping

    func testOnlyConfidentSignalsScore() {
        let results = JevSignalCheck.results(from: [
            "impersonation": 0.92,
            "credential_lure": 0.81,
            "pressure": 0.69,
            "generic_sender": 0.10,
        ])
        XCTAssertEqual(results.count, 2)
        XCTAssertEqual(results.reduce(0) { $0 + $1.points }, 5)
        XCTAssertTrue(results.allSatisfy { $0.checkName == JevSignalCheck.checkName })
    }

    func testLegitSecurityNoticeStaysClean() {
        // "Your password expires soon" from the real IT department: lure + pressure only.
        let results = JevSignalCheck.results(from: ["credential_lure": 0.95, "pressure": 0.9])
        let score = results.reduce(0) { $0 + $1.points }
        XCTAssertEqual(ThreatLevel(score: score), .clean)
    }

    func testImpersonationWithLureAndPressureIsPhishing() {
        let results = JevSignalCheck.results(from: ["impersonation": 0.9, "credential_lure": 0.9, "pressure": 0.9])
        XCTAssertEqual(ThreatLevel(score: results.reduce(0) { $0 + $1.points }), .phishing)
    }

    func testEverySignalHasAQuestion() {
        XCTAssertEqual(Set(JevSignalCheck.questions.keys), Set(JevSignalCheck.signals.map(\.id)))
    }

    // MARK: - State building

    func testStateStripsQueryStringsAndDeduplicatesLinks() {
        let email = makeEmail(html: """
        <a href="https://evil.example/login?user=me@mail.com&t=abc#frag">Sign in</a>
        <a href="https://evil.example/login?user=other">Sign in</a>
        <a href="mailto:help@evil.example">Mail us</a>
        """, headers: ["Reply-To": "boss@gmail.com"])
        let state = JevSignalCheck.state(for: email, context: AnalysisContext.from(email: email))

        XCTAssertEqual(state["links"], "Sign in -> https://evil.example/login")
        XCTAssertEqual(state["reply_to"], "boss@gmail.com")
        XCTAssertEqual(state["from_domain"], "sender.example")
        XCTAssertFalse(state["links"]?.contains("me@mail.com") ?? true)
    }

    func testStateTruncatesBody() {
        let email = makeEmail(text: String(repeating: "word ", count: 2_000))
        let state = JevSignalCheck.state(for: email, context: .empty)
        XCTAssertEqual(state["body"]?.count, JevSignalCheck.maxBodyCharacters)
        XCTAssertNil(state["links"])
    }

    // MARK: - Gating

    func testSkipsWhenLocalChecksAreConclusive() async {
        let stub = StubJev(answers: ["impersonation": 0.9])
        let jev = JevSignalCheck(client: stub)
        let result = await jev.signals(for: makeEmail(), context: .empty, localScore: PhishGuardThresholds.phishing)
        XCTAssertNil(result)
        let calls = await stub.calls
        XCTAssertEqual(calls, 0)
    }

    func testSkipsEstablishedAuthenticatedSender() async throws {
        let store = VerdictStore(database: try DatabaseManager(inMemory: true))
        for i in 0..<JevSignalCheck.knownSenderMinimum {
            try store.save(Verdict(messageId: "old-\(i)", score: 0, reasons: [], from: "News <news@sender.example>"))
        }
        let stub = StubJev(answers: [:])
        let jev = JevSignalCheck(client: stub, verdictStore: store)

        let authenticated = makeEmail(auth: "mx; spf=pass; dkim=pass; dmarc=pass")
        let unauthenticated = makeEmail(id: "new-2", auth: "mx; spf=pass; dkim=none; dmarc=none")
        let skipped = await jev.signals(for: authenticated, context: .empty, localScore: 0)
        let asked = await jev.signals(for: unauthenticated, context: .empty, localScore: 0)
        XCTAssertNil(skipped)
        XCTAssertNotNil(asked)
    }

    func testLookalikeDomainIsNotAnEstablishedSender() async throws {
        let store = VerdictStore(database: try DatabaseManager(inMemory: true))
        for i in 0..<JevSignalCheck.knownSenderMinimum {
            try store.save(Verdict(messageId: "old-\(i)", score: 0, reasons: [], from: "news@sender.example"))
        }
        let jev = JevSignalCheck(client: StubJev(answers: [:]), verdictStore: store)
        let lookalike = makeEmail(from: "Bank <alert@sender.example.evil.xyz>", auth: "mx; dmarc=pass")
        XCTAssertTrue(jev.needsQuery(email: lookalike, localScore: 0))
    }

    func testDisabledNeverCalls() async {
        let stub = StubJev(answers: ["impersonation": 0.9])
        let jev = JevSignalCheck(client: stub, isEnabled: { false })
        let result = await jev.signals(for: makeEmail(), context: .empty, localScore: 0)
        XCTAssertNil(result)
        let calls = await stub.calls
        XCTAssertEqual(calls, 0)
    }

    func testCachesPerMessageAndEnforcesDailyLimit() async {
        let stub = StubJev(answers: ["impersonation": 0.9])
        let jev = JevSignalCheck(client: stub, dailyCallLimit: 2)

        _ = await jev.signals(for: makeEmail(id: "a"), context: .empty, localScore: 0)
        _ = await jev.signals(for: makeEmail(id: "a"), context: .empty, localScore: 0)
        _ = await jev.signals(for: makeEmail(id: "b"), context: .empty, localScore: 0)
        let overLimit = await jev.signals(for: makeEmail(id: "c"), context: .empty, localScore: 0)

        XCTAssertNil(overLimit)
        let calls = await stub.calls
        XCTAssertEqual(calls, 2)
    }

    // MARK: - Analyzer integration

    func testJevSignalsReplaceBrandCheck() async {
        let jev = JevSignalCheck(client: StubJev(answers: ["impersonation": 0.9, "credential_lure": 0.9]))
        let analyzer = PhishingAnalyzer(checks: [FixedBrandCheck()], jev: jev)

        let local = analyzer.analyze(email: makeEmail())
        let combined = await analyzer.evaluate(email: makeEmail())

        XCTAssertEqual(local.reasons.map(\.checkName), [BrandImpersonationCheck.checkName])
        XCTAssertEqual(combined.score, 5)
        XCTAssertFalse(combined.reasons.contains { $0.checkName == BrandImpersonationCheck.checkName })
    }

    func testFailureFallsBackToLocalVerdict() async {
        let jev = JevSignalCheck(client: StubJev(answers: [:], fails: true))
        let analyzer = PhishingAnalyzer(checks: [FixedBrandCheck()], jev: jev)
        let verdict = await analyzer.evaluate(email: makeEmail())
        XCTAssertEqual(verdict.score, 3)
        XCTAssertEqual(verdict.reasons.map(\.checkName), [BrandImpersonationCheck.checkName])
    }

    func testBatchKeepsInputOrder() async {
        let jev = JevSignalCheck(client: StubJev(answers: ["generic_sender": 0.9]))
        let analyzer = PhishingAnalyzer(checks: [], jev: jev)
        let items = (0..<10).map { (email: makeEmail(id: "m\($0)"), imapUID: UInt32?.some(UInt32($0))) }

        let verdicts = await analyzer.evaluate(items, maxConcurrent: 3)

        XCTAssertEqual(verdicts.map(\.messageId), items.map { $0.email.messageId })
        XCTAssertTrue(verdicts.allSatisfy { $0.score == 3 })
    }

    // MARK: - Helpers

    private func makeEmail(
        id: String = "msg-1",
        from: String = "Support <support@sender.example>",
        auth: String? = nil,
        html: String? = nil,
        text: String? = "Hello",
        headers: [String: String] = [:]
    ) -> ParsedEmail {
        ParsedEmail(
            messageId: id,
            from: from,
            returnPath: nil,
            authenticationResults: auth,
            subject: "Test",
            htmlBody: html,
            textBody: html == nil ? text : nil,
            receivedDate: Date(),
            headers: headers
        )
    }
}

private actor StubJev: JevAnswering {
    private(set) var calls = 0
    private let answers: [String: Double]
    private let fails: Bool

    init(answers: [String: Double], fails: Bool = false) {
        self.answers = answers
        self.fails = fails
    }

    func probabilities(state: [String: String], questions: [String: JevQuestion]) async throws -> [String: Double] {
        calls += 1
        if fails { throw JevError.http(status: 529) }
        return answers
    }
}

/// Stands in for a keyword-list brand hit without needing the brand database.
private struct FixedBrandCheck: PhishingCheck {
    let name = BrandImpersonationCheck.checkName
    func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        [CheckResult(checkName: name, points: 3, reason: "Brand in display name")]
    }
}
