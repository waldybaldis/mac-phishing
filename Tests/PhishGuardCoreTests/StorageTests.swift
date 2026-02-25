import XCTest
@testable import PhishGuardCore

final class StorageTests: XCTestCase {
    var db: DatabaseManager!

    override func setUp() async throws {
        db = try DatabaseManager(inMemory: true)
    }

    // MARK: - Verdict Store Tests

    func testSaveAndLookupVerdict() throws {
        let store = VerdictStore(database: db)
        let verdict = Verdict(
            messageId: "msg-001",
            score: 7,
            reasons: [
                CheckResult(checkName: "Test", points: 4, reason: "Test reason 1"),
                CheckResult(checkName: "Test", points: 3, reason: "Test reason 2"),
            ]
        )

        try store.save(verdict)
        let looked = try store.lookup(messageId: "msg-001")

        XCTAssertNotNil(looked)
        XCTAssertEqual(looked?.messageId, "msg-001")
        XCTAssertEqual(looked?.score, 7)
        XCTAssertEqual(looked?.reasons.count, 2)
    }

    func testLookupNonexistent() throws {
        let store = VerdictStore(database: db)
        let result = try store.lookup(messageId: "nonexistent")
        XCTAssertNil(result)
    }

    func testRecentVerdicts() throws {
        let store = VerdictStore(database: db)

        // Save several verdicts
        for i in 1...5 {
            let verdict = Verdict(
                messageId: "msg-\(i)",
                score: i * 2,
                reasons: [CheckResult(checkName: "Test", points: i * 2, reason: "Reason \(i)")],
                timestamp: Date().addingTimeInterval(Double(i) * 60)
            )
            try store.save(verdict)
        }

        let recent = try store.recentVerdicts(limit: 3, minimumScore: 3)
        XCTAssertEqual(recent.count, 3)
        // Should be ordered by timestamp descending
        XCTAssertGreaterThan(recent[0].timestamp, recent[1].timestamp)
    }

    func testUpdateAction() throws {
        let store = VerdictStore(database: db)
        let verdict = Verdict(messageId: "msg-action", score: 8, reasons: [])
        try store.save(verdict)

        try store.updateAction(messageId: "msg-action", action: .movedToJunk)
        let updated = try store.lookup(messageId: "msg-action")
        XCTAssertEqual(updated?.actionTaken, .movedToJunk)
    }

    // MARK: - Allowlist Store Tests

    func testAllowlist() throws {
        let store = AllowlistStore(database: db)

        try store.add(domain: "trusted.com")
        XCTAssertTrue(try store.isAllowed(domain: "trusted.com"))
        XCTAssertFalse(try store.isAllowed(domain: "untrusted.com"))

        try store.remove(domain: "trusted.com")
        XCTAssertFalse(try store.isAllowed(domain: "trusted.com"))
    }

    func testAllowlistCaseInsensitive() throws {
        let store = AllowlistStore(database: db)

        try store.add(domain: "Example.COM")
        XCTAssertTrue(try store.isAllowed(domain: "example.com"))
    }

    // MARK: - Blacklist Store Tests

    func testBlacklistReplaceAll() throws {
        let store = BlacklistStore(database: db)

        try store.replaceAll(domains: ["bad1.com", "bad2.com"], source: "test")
        XCTAssertEqual(try store.count(), 2)
        XCTAssertTrue(try store.isBlacklisted(domain: "bad1.com"))

        // Replace with new list
        try store.replaceAll(domains: ["bad3.com"], source: "test")
        XCTAssertEqual(try store.count(), 1)
        XCTAssertFalse(try store.isBlacklisted(domain: "bad1.com"))
        XCTAssertTrue(try store.isBlacklisted(domain: "bad3.com"))
    }

    func testBlacklistCheckMultiple() throws {
        let store = BlacklistStore(database: db)
        try store.replaceAll(domains: ["evil.com", "phish.net", "scam.org"], source: "test")

        let found = try store.checkDomains(["evil.com", "safe.com", "phish.net"])
        XCTAssertEqual(found.count, 2)
        XCTAssertTrue(found.contains("evil.com"))
        XCTAssertTrue(found.contains("phish.net"))
        XCTAssertFalse(found.contains("safe.com"))
    }
}
