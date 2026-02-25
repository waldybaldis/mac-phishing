import XCTest
@testable import PhishGuardCore

final class LinkMismatchCheckTests: XCTestCase {
    let check = LinkMismatchCheck()

    func testMismatchedLink() {
        let html = """
        <html><body>
        <a href="https://evil-site.com/login">https://paypal.com/verify</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 4)
        XCTAssert(results[0].reason.contains("paypal.com"))
        XCTAssert(results[0].reason.contains("evil-site.com"))
    }

    func testMatchingLink() {
        let html = """
        <html><body>
        <a href="https://paypal.com/account">https://paypal.com/account</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    func testNonURLDisplayText() {
        let html = """
        <html><body>
        <a href="https://example.com/page">Click here to verify</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty, "Non-URL display text should not trigger the check")
    }

    func testMultipleMismatchedLinks() {
        let html = """
        <html><body>
        <a href="https://phish1.com/login">https://bank.com/login</a>
        <a href="https://phish2.com/verify">https://amazon.com/orders</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 2)
        XCTAssertEqual(results.reduce(0) { $0 + $1.points }, 8) // 4 + 4
    }

    func testNoHTMLBody() {
        let email = ParsedEmail(
            messageId: "test-link-none",
            from: "user@example.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: "Plain text only",
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    func testSubdomainMatch() {
        let html = """
        <html><body>
        <a href="https://mail.google.com/login">https://accounts.google.com/signin</a>
        </body></html>
        """
        let email = makeEmail(html: html)
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty, "Subdomains of the same base domain should not trigger")
    }

    // MARK: - Helpers

    private func makeEmail(html: String) -> ParsedEmail {
        ParsedEmail(
            messageId: "test-link-\(UUID().uuidString)",
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
