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
        XCTAssertEqual(results[0].points, 3)
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
        XCTAssertEqual(results[0].points, 3)
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
        XCTAssertEqual(results[0].points, 3)
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

    // MARK: - Link domain vs brand

    func testLinksToUnrelatedDomain() {
        // Argenta phishing: display name "ARGENTA" but links go to tradebulls.in
        let email = ParsedEmail(
            messageId: "test-11",
            from: "ARGENTA <digipass-new@tradebulls.in>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Update uw diensten",
            htmlBody: "<a href=\"http://delivery.tradebulls.in/path\">Meer informatie</a>",
            textBody: nil,
            receivedDate: Date()
        )
        let context = AnalysisContext.from(email: email)
        let results = check.analyze(email: email, context: context)
        XCTAssertEqual(results.count, 2)
        XCTAssertEqual(results[0].points, 3, "Brand impersonation base score")
        XCTAssertEqual(results[1].points, 2, "No links point to brand domain")
    }

    func testLinksPointToBrandDomain() {
        // Brand impersonation but links DO go to the brand — only base flag, no link flag
        let email = ParsedEmail(
            messageId: "test-12",
            from: "Argenta <noreply@scammer.net>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Update",
            htmlBody: "<a href=\"https://www.argenta.be/login\">Login</a>",
            textBody: nil,
            receivedDate: Date()
        )
        let context = AnalysisContext.from(email: email)
        let results = check.analyze(email: email, context: context)
        XCTAssertEqual(results.count, 1, "Only base impersonation, links contain brand")
        XCTAssertEqual(results[0].points, 3)
    }

    func testNoLinksNoExtraFlag() {
        // No links in email — only base impersonation flag, no link check
        let email = ParsedEmail(
            messageId: "test-13",
            from: "PayPal <alerts@scammer.net>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Alert",
            htmlBody: "<p>Plain text email</p>",
            textBody: nil,
            receivedDate: Date()
        )
        let context = AnalysisContext.from(email: email)
        let results = check.analyze(email: email, context: context)
        XCTAssertEqual(results.count, 1, "No links means no link domain check")
        XCTAssertEqual(results[0].points, 3)
    }

    // MARK: - Safeonweb campaign boost

    func testCampaignBrandBoostsScore() throws {
        let db = try DatabaseManager(inMemory: true)
        let campaignStore = SafeonwebCampaignStore(database: db)
        try campaignStore.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Phishing in naam van Argenta")

        let checkWithCampaign = BrandImpersonationCheck(campaignStore: campaignStore)

        let email = ParsedEmail(
            messageId: "test-campaign-1",
            from: "ARGENTA <digipass-new@tradebulls.in>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Update uw diensten",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = checkWithCampaign.analyze(email: email, context: .empty)

        // Should have base impersonation (3) + campaign boost (2)
        XCTAssertTrue(results.contains { $0.points == 3 }, "Should have base impersonation score")
        XCTAssertTrue(results.contains { $0.points == 2 && $0.reason.contains("Safeonweb") },
                      "Should have Safeonweb campaign boost")
    }

    func testNoCampaignStoreNoBoost() {
        // Default check (no campaign store) should not produce campaign boost
        let email = ParsedEmail(
            messageId: "test-campaign-2",
            from: "ARGENTA <digipass-new@tradebulls.in>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Update uw diensten",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)

        XCTAssertEqual(results.count, 1, "Without campaign store, only base impersonation")
        XCTAssertEqual(results[0].points, 3)
        XCTAssertFalse(results[0].reason.contains("Safeonweb"))
    }
}
