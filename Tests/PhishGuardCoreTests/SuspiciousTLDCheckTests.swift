import XCTest
@testable import PhishGuardCore

final class SuspiciousTLDCheckTests: XCTestCase {
    let check = SuspiciousTLDCheck()

    func testSuspiciousSenderTLD() {
        let email = ParsedEmail(
            messageId: "test-tld-1",
            from: "admin@secure-login.xyz",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Verify your account",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 2)
        XCTAssert(results[0].reason.contains(".xyz"))
        XCTAssert(results[0].reason.contains("sender"))
    }

    func testSuspiciousLinkTLD() {
        let html = """
        <html><body>
        <a href="https://login.example.tk/verify">Verify now</a>
        </body></html>
        """
        let email = ParsedEmail(
            messageId: "test-tld-2",
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
        XCTAssertEqual(results[0].points, 2)
        XCTAssert(results[0].reason.contains(".tk"))
        XCTAssert(results[0].reason.contains("link"))
    }

    func testNormalTLDs() {
        let html = """
        <html><body>
        <a href="https://www.example.com/page">Link 1</a>
        <a href="https://www.example.org/page">Link 2</a>
        <a href="https://www.example.net/page">Link 3</a>
        </body></html>
        """
        let email = ParsedEmail(
            messageId: "test-tld-3",
            from: "user@legitimate.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: html,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    func testMultipleSuspiciousTLDs() {
        let html = """
        <html><body>
        <a href="https://site1.ml/page">Link 1</a>
        <a href="https://site2.ga/page">Link 2</a>
        </body></html>
        """
        let email = ParsedEmail(
            messageId: "test-tld-4",
            from: "admin@phish.cf",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: html,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 3) // sender + 2 links
        XCTAssertEqual(results.reduce(0) { $0 + $1.points }, 6) // 2 + 2 + 2
    }
}
