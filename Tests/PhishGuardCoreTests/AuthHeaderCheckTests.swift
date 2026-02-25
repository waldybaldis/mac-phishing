import XCTest
@testable import PhishGuardCore

final class AuthHeaderCheckTests: XCTestCase {
    let check = AuthHeaderCheck()

    // MARK: - SPF Tests

    func testSPFFail() {
        let email = makeEmail(authResults: "mx.google.com; spf=fail (domain not designated) smtp.mailfrom=spoofed.com")
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
        XCTAssert(results[0].reason.contains("SPF"))
        XCTAssert(results[0].reason.contains("fail"))
    }

    func testSPFSoftfail() {
        let email = makeEmail(authResults: "mx.example.com; spf=softfail smtp.mailfrom=test.com")
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
        XCTAssert(results[0].reason.contains("SPF"))
    }

    func testSPFPass() {
        let email = makeEmail(authResults: "mx.google.com; spf=pass smtp.mailfrom=legitimate.com")
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    // MARK: - DKIM Tests

    func testDKIMFail() {
        let email = makeEmail(authResults: "mx.google.com; dkim=fail header.i=@example.com")
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
        XCTAssert(results[0].reason.contains("DKIM"))
    }

    func testDKIMPass() {
        let email = makeEmail(authResults: "mx.google.com; dkim=pass header.i=@example.com")
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    // MARK: - DMARC Tests

    func testDMARCFail() {
        let email = makeEmail(authResults: "mx.google.com; dmarc=fail (p=REJECT) header.from=example.com")
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
        XCTAssert(results[0].reason.contains("DMARC"))
    }

    func testDMARCNone() {
        let email = makeEmail(authResults: "mx.google.com; dmarc=none header.from=newdomain.com")
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
        XCTAssert(results[0].reason.contains("not found"))
    }

    // MARK: - Multiple Failures

    func testAllThreeFail() {
        let authResults = """
        mx.google.com;
            dkim=fail header.i=@example.com;
            spf=fail (domain not designated) smtp.mailfrom=spoofed.com;
            dmarc=fail (p=REJECT) header.from=example.com
        """
        let email = makeEmail(authResults: authResults)
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 3)
        XCTAssertEqual(results.reduce(0) { $0 + $1.points }, 9) // 3 + 3 + 3
    }

    func testNoAuthHeader() {
        let email = makeEmail(authResults: nil)
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    func testEmptyAuthHeader() {
        let email = makeEmail(authResults: "")
        let results = check.analyze(email: email)
        XCTAssertTrue(results.isEmpty)
    }

    // MARK: - Error States

    func testTemperror() {
        let email = makeEmail(authResults: "mx.google.com; spf=temperror smtp.mailfrom=test.com")
        let results = check.analyze(email: email)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 2) // Lower score for errors
    }

    // MARK: - Helpers

    private func makeEmail(authResults: String?) -> ParsedEmail {
        ParsedEmail(
            messageId: "test-\(UUID().uuidString)",
            from: "user@example.com",
            returnPath: nil,
            authenticationResults: authResults,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
    }
}
