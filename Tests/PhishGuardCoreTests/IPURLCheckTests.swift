import XCTest
@testable import PhishGuardCore

final class IPURLCheckTests: XCTestCase {
    let check = IPURLCheck()

    func testIPInLink() {
        let html = """
        <html><body>
        <a href="http://192.168.1.1/login">Login here</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email, context: .from(email: email))
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 4)
        XCTAssert(results[0].reason.contains("192.168.1.1"))
    }

    func testMultipleIPLinks() {
        let html = """
        <html><body>
        <a href="http://10.0.0.1/page">Page 1</a>
        <a href="https://203.0.113.50/verify">Verify</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email, context: .from(email: email))
        XCTAssertEqual(results.count, 2)
    }

    func testNormalDomainLinks() {
        let html = """
        <html><body>
        <a href="https://www.example.com/page">Normal link</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email, context: .from(email: email))
        XCTAssertTrue(results.isEmpty)
    }

    func testIPInPlainText() {
        let email = ParsedEmail(
            messageId: "test-ip-text",
            from: "user@example.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: "Visit http://192.168.1.100/reset to reset your password",
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .from(email: email))
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 4)
    }

    func testNoBody() {
        let email = ParsedEmail(
            messageId: "test-ip-nobody",
            from: "user@example.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .from(email: email))
        XCTAssertTrue(results.isEmpty)
    }

    // MARK: - Helpers

    private func makeEmail(html: String) -> ParsedEmail {
        ParsedEmail(
            messageId: "test-ip-\(UUID().uuidString)",
            from: "user@example.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: html,
            textBody: nil,
            receivedDate: Date()
        )
    }
}
