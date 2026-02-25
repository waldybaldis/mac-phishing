import XCTest
@testable import PhishGuardCore

final class BlacklistCheckTests: XCTestCase {
    var db: DatabaseManager!
    var blacklistStore: BlacklistStore!

    override func setUp() async throws {
        db = try DatabaseManager(inMemory: true)
        blacklistStore = BlacklistStore(database: db)

        // Populate test blacklist
        try blacklistStore.replaceAll(
            domains: [
                "evil-phishing.com",
                "fake-bank.net",
                "steal-creds.org",
                "phish.tk",
            ],
            source: "test"
        )
    }

    func testBlacklistedSenderDomain() throws {
        let check = BlacklistCheck(blacklistStore: blacklistStore)
        let email = ParsedEmail(
            messageId: "bl-test-1",
            from: "admin@evil-phishing.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 5)
        XCTAssert(results[0].reason.contains("evil-phishing.com"))
    }

    func testBlacklistedLinkDomain() throws {
        let check = BlacklistCheck(blacklistStore: blacklistStore)
        let html = """
        <html><body>
        <a href="https://fake-bank.net/login">Login to your bank</a>
        </body></html>
        """
        let email = ParsedEmail(
            messageId: "bl-test-2",
            from: "user@legitimate.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: html,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 5)
        XCTAssert(results[0].reason.contains("fake-bank.net"))
    }

    func testNonBlacklistedDomain() throws {
        let check = BlacklistCheck(blacklistStore: blacklistStore)
        let email = ParsedEmail(
            messageId: "bl-test-3",
            from: "user@safe-domain.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: "<html><body><a href=\"https://google.com\">Google</a></body></html>",
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    func testMultipleBlacklistedDomains() throws {
        let check = BlacklistCheck(blacklistStore: blacklistStore)
        let html = """
        <html><body>
        <a href="https://fake-bank.net/login">Bank</a>
        <a href="https://steal-creds.org/verify">Verify</a>
        </body></html>
        """
        let email = ParsedEmail(
            messageId: "bl-test-4",
            from: "admin@evil-phishing.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: html,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 3) // sender + 2 link domains
        XCTAssertEqual(results.reduce(0) { $0 + $1.points }, 15) // 5 + 5 + 5
    }
}
