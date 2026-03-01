import XCTest
@testable import PhishGuardCore

final class BrandImpersonationCheckTests: XCTestCase {
    let check = BrandImpersonationCheck()

    // MARK: - Should NOT flag (no brand store match)

    func testUnknownBrandNotFlagged() {
        // DPD is not in any brand store — should NOT flag
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
        XCTAssertTrue(results.isEmpty, "Unknown brand should not flag without brand store")
    }

    func testUnknownBrandOnNonFreemailNotFlagged() {
        // "PayPal Support" on scammer.net — but paypal is not in any brand store
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
        XCTAssertTrue(results.isEmpty, "Unknown brand on non-freemail domain should not flag")
    }

    func testPersonalNameOnGmailNotFlagged() {
        let email = ParsedEmail(
            messageId: "test-personal-1",
            from: "Bruno Woestyn <woestoetoe@gmail.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Hello",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = check.analyze(email: email, context: .empty)
        XCTAssertTrue(results.isEmpty, "Personal name on gmail should not flag")
    }

    // MARK: - Should flag (user brand store match)

    func testUserBrandFlagged() throws {
        let db = try DatabaseManager(inMemory: true)
        let userBrandStore = UserBrandStore(database: db)
        try userBrandStore.add(brand: "DPD")

        let checkWithBrands = BrandImpersonationCheck(userBrandStore: userBrandStore)

        let email = ParsedEmail(
            messageId: "test-user-brand-1",
            from: "DPD <john@gmail.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Your package",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = checkWithBrands.analyze(email: email, context: .empty)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].points, 3)
        XCTAssert(results[0].reason.contains("DPD"))
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

    func testQuotedDisplayNameNotFlaggedWithoutBrandStore() {
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
        XCTAssertTrue(results.isEmpty, "Netflix not in brand store should not flag")
    }

    func testQuotedDisplayNameFlaggedWithBrandStore() throws {
        let db = try DatabaseManager(inMemory: true)
        let userBrandStore = UserBrandStore(database: db)
        try userBrandStore.add(brand: "Netflix")

        let checkWithBrands = BrandImpersonationCheck(userBrandStore: userBrandStore)

        let email = ParsedEmail(
            messageId: "test-9b",
            from: "\"Netflix\" <billing@evil-site.com>",
            returnPath: nil,
            authenticationResults: nil,
            subject: "Payment failed",
            htmlBody: nil,
            textBody: nil,
            receivedDate: Date()
        )
        let results = checkWithBrands.analyze(email: email, context: .empty)
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

    // MARK: - Link domain vs brand (with campaign store)

    func testLinksToUnrelatedDomain() throws {
        let db = try DatabaseManager(inMemory: true)
        let campaignStore = SafeonwebCampaignStore(database: db)
        try campaignStore.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Phishing Argenta")

        let checkWithCampaign = BrandImpersonationCheck(campaignStore: campaignStore)

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
        let results = checkWithCampaign.analyze(email: email, context: context)
        XCTAssertEqual(results.count, 3)
        XCTAssertEqual(results[0].points, 3, "Brand impersonation base score")
        XCTAssertEqual(results[1].points, 2, "No links point to brand domain")
        XCTAssertEqual(results[2].points, 2, "Safeonweb campaign boost")
    }

    func testLinksPointToBrandDomain() throws {
        let db = try DatabaseManager(inMemory: true)
        let userBrandStore = UserBrandStore(database: db)
        try userBrandStore.add(brand: "argenta")

        let checkWithBrands = BrandImpersonationCheck(userBrandStore: userBrandStore)

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
        let results = checkWithBrands.analyze(email: email, context: context)
        XCTAssertEqual(results.count, 1, "Only base impersonation, links contain brand")
        XCTAssertEqual(results[0].points, 3)
    }

    func testNoLinksNoExtraFlag() throws {
        let db = try DatabaseManager(inMemory: true)
        let userBrandStore = UserBrandStore(database: db)
        try userBrandStore.add(brand: "paypal")

        let checkWithBrands = BrandImpersonationCheck(userBrandStore: userBrandStore)

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
        let results = checkWithBrands.analyze(email: email, context: context)
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
        // Default check (no campaign store) should not produce any results for unknown brands
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

        XCTAssertTrue(results.isEmpty, "Without any brand store, unknown brands should not flag")
    }
}
