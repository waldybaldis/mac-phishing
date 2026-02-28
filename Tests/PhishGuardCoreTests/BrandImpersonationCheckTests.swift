import XCTest
@testable import PhishGuardCore

final class BrandImpersonationCheckTests: XCTestCase {
    let check = BrandImpersonationCheck()

    // MARK: - Should flag (brand impersonation)

    func testBrandNameNotInDomain() {
        let email = ParsedEmail(
            messageId: "test-1",
            from: "DPD <john@gmail.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Your package",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 2)
        XCTAssert(results[0].reason.contains("DPD"))
        XCTAssert(results[0].reason.contains("gmail.com"))
    }

    func testBrandWithDescriptorNotInDomain() {
        let email = ParsedEmail(
            messageId: "test-2",
            from: "PayPal Support <alerts@scammer.net>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Verify your account",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 2)
    }

    // MARK: - Should NOT flag (legitimate)

    func testBrandMatchesDomain() {
        let email = ParsedEmail(
            messageId: "test-3",
            from: "PayPal <service@paypal.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Receipt",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty)
    }

    func testBrandMatchesSubdomain() {
        let email = ParsedEmail(
            messageId: "test-4",
            from: "Amazon <noreply@shipping.amazon.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Your order",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty)
    }

    func testPersonalEmailNameInLocalPart() {
        let email = ParsedEmail(
            messageId: "test-5",
            from: "John Smith <john.smith@gmail.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Hello",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty, "Personal name matching local part should not flag")
    }

    func testPersonalEmailConcatenatedLocalPart() {
        let email = ParsedEmail(
            messageId: "test-6",
            from: "Liliane Quintyn <lilianequintyn@yahoo.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Forwarded message",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty, "Name appearing in concatenated local part should not flag")
    }

    func testBareEmailNoDisplayName() {
        let email = ParsedEmail(
            messageId: "test-7",
            from: "user@example.com",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Test",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty, "No display name means nothing to check")
    }

    func testShortDisplayNameWordsSkipped() {
        let email = ParsedEmail(
            messageId: "test-8",
            from: "IT <support@company.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Password reset",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty, "Words under 3 chars should be ignored")
    }

    func testQuotedDisplayName() {
        let email = ParsedEmail(
            messageId: "test-9",
            from: "\"Netflix\" <billing@evil-site.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Payment failed",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 2)
    }

    func testDPDFromPickupServices() {
        // Real DPD email — display name "DPD" matches local part "dpd"
        let email = ParsedEmail(
            messageId: "test-10",
            from: "DPD <dpd@network1.pickup-services.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Je pakket van DPD BE",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty, "DPD in local part 'dpd' should not flag")
    }
}
