import XCTest
@testable import PhishGuardCore

final class ParsedEmailTests: XCTestCase {

    func testExtractDomainSimple() {
        XCTAssertEqual(ParsedEmail.extractDomain(from: "user@example.com"), "example.com")
    }

    func testExtractDomainWithDisplayName() {
        XCTAssertEqual(ParsedEmail.extractDomain(from: "John Doe <john@example.com>"), "example.com")
    }

    func testExtractDomainAngleBrackets() {
        XCTAssertEqual(ParsedEmail.extractDomain(from: "<bounce@mail.example.com>"), "mail.example.com")
    }

    func testExtractDomainCaseInsensitive() {
        XCTAssertEqual(ParsedEmail.extractDomain(from: "USER@EXAMPLE.COM"), "example.com")
    }

    func testExtractDomainNoAt() {
        XCTAssertNil(ParsedEmail.extractDomain(from: "not-an-email"))
    }

    func testExtractDomainEmpty() {
        XCTAssertNil(ParsedEmail.extractDomain(from: ""))
    }

    func testFromDomainPopulated() {
        let email = ParsedEmail(
            messageId: "test",
            from: "John <john@paypal.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        XCTAssertEqual(email.fromDomain, "paypal.com")
    }

    func testReturnPathDomainPopulated() {
        let email = ParsedEmail(
            messageId: "test",
            from: "user@example.com",
            returnPath: "bounce@mail-server.net",
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        XCTAssertEqual(email.returnPathDomain, "mail-server.net")
    }
}
