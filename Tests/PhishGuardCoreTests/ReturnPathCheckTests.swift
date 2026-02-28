import XCTest
@testable import PhishGuardCore

final class ReturnPathCheckTests: XCTestCase {
    let check = ReturnPathCheck()

    func testMatchingDomains() {
        let email = ParsedEmail(
            messageId: "test-1",
            from: "user@example.com",
            returnPath: "bounce@example.com",
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty)
    }

    func testMismatchedDomains() {
        let email = ParsedEmail(
            messageId: "test-2",
            from: "support@paypal.com",
            returnPath: "bounce@evil-site.com",
            authenticationResults: nil,
            subject: "Verify your account",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
        XCTAssert(results[0].reason.contains("evil-site.com"))
        XCTAssert(results[0].reason.contains("paypal.com"))
    }

    func testSubdomainMatch() {
        let email = ParsedEmail(
            messageId: "test-3",
            from: "user@mail.example.com",
            returnPath: "bounce@notify.example.com",
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty, "Subdomains of the same base domain should not trigger")
    }

    func testNoReturnPath() {
        let email = ParsedEmail(
            messageId: "test-4",
            from: "user@example.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty)
    }

    func testAngleBracketFormat() {
        let email = ParsedEmail(
            messageId: "test-5",
            from: "John Doe <john@paypal.com>",
            returnPath: "<bounce@phishing-site.net>",
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
    }
}
