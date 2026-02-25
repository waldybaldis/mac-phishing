import XCTest
@testable import PhishGuardCore

final class PhishingAnalyzerTests: XCTestCase {

    // MARK: - Clean Email

    func testCleanEmail() {
        let analyzer = makeAnalyzer()
        let email = ParsedEmail(
            messageId: "clean-1",
            from: "user@legitimate.com",
            returnPath: "bounce@legitimate.com",
            authenticationResults: "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
            subject: "Monthly newsletter",
            htmlBody: """
            <html><body>
            <p>Hello! Here is your monthly update.</p>
            <a href="https://legitimate.com/newsletter">Read more</a>
            </body></html>
            """,
            textBody: nil,
            receivedDate: Date()
        )
        let verdict = analyzer.analyze(email: email)
        XCTAssertEqual(verdict.threatLevel, .clean)
        XCTAssertEqual(verdict.score, 0)
        XCTAssertTrue(verdict.reasons.isEmpty)
    }

    // MARK: - Suspicious Email

    func testSuspiciousEmail() {
        let analyzer = makeAnalyzer()
        let email = ParsedEmail(
            messageId: "suspicious-1",
            from: "support@paypal.com",
            returnPath: "bounce@unrelated-server.net",
            authenticationResults: "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
            subject: "Action required on your account",
            htmlBody: "<html><body><p>Please verify your account.</p></body></html>",
            textBody: nil,
            receivedDate: Date()
        )
        let verdict = analyzer.analyze(email: email)
        XCTAssertEqual(verdict.threatLevel, .suspicious)
        XCTAssertEqual(verdict.score, 3) // Return-Path mismatch only
    }

    // MARK: - Phishing Email

    func testObviousPhishingEmail() {
        let analyzer = makeAnalyzer()
        let email = ParsedEmail(
            messageId: "phishing-1",
            from: "security@paypal.com",
            returnPath: "x@evil.xyz",
            authenticationResults: """
            mx.google.com; spf=fail; dkim=fail; dmarc=fail
            """,
            subject: "Your account has been limited",
            htmlBody: """
            <html><body>
            <p>Your account has been limited. Click below to verify:</p>
            <a href="https://evil-site.com/paypal-login">https://paypal.com/verify</a>
            <a href="http://192.168.1.100/steal">http://192.168.1.100/steal</a>
            </body></html>
            """,
            textBody: nil,
            receivedDate: Date()
        )
        let verdict = analyzer.analyze(email: email)
        XCTAssertEqual(verdict.threatLevel, .phishing)
        XCTAssertGreaterThanOrEqual(verdict.score, 6)
        XCTAssertFalse(verdict.reasons.isEmpty)
    }

    // MARK: - Score Thresholds

    func testCleanThreshold() {
        XCTAssertEqual(ThreatLevel(score: 0), .clean)
        XCTAssertEqual(ThreatLevel(score: 1), .clean)
        XCTAssertEqual(ThreatLevel(score: 2), .clean)
    }

    func testSuspiciousThreshold() {
        XCTAssertEqual(ThreatLevel(score: 3), .suspicious)
        XCTAssertEqual(ThreatLevel(score: 4), .suspicious)
        XCTAssertEqual(ThreatLevel(score: 5), .suspicious)
    }

    func testPhishingThreshold() {
        XCTAssertEqual(ThreatLevel(score: 6), .phishing)
        XCTAssertEqual(ThreatLevel(score: 10), .phishing)
        XCTAssertEqual(ThreatLevel(score: 20), .phishing)
    }

    // MARK: - Helpers

    /// Creates an analyzer without the blacklist check (no DB dependency for basic tests).
    private func makeAnalyzer() -> PhishingAnalyzer {
        let checks: [PhishingCheck] = [
            AuthHeaderCheck(),
            ReturnPathCheck(),
            LinkMismatchCheck(),
            IPURLCheck(),
            SuspiciousTLDCheck(),
        ]
        return PhishingAnalyzer(checks: checks)
    }
}
