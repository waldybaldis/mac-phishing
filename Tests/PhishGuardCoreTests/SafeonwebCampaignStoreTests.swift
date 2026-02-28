import XCTest
@testable import PhishGuardCore

final class SafeonwebCampaignStoreTests: XCTestCase {
    var store: SafeonwebCampaignStore!

    override func setUp() async throws {
        let db = try DatabaseManager(inMemory: true)
        store = SafeonwebCampaignStore(database: db)
    }

    func testInsertAndQuery() throws {
        try store.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Phishing in naam van Argenta")

        XCTAssertTrue(try store.isActiveCampaignBrand("argenta"))
        XCTAssertFalse(try store.isActiveCampaignBrand("itsme"))
        XCTAssertEqual(try store.count(), 1)
    }

    func testActiveBrands() throws {
        try store.insertBrands(["argenta", "itsme"], publishedDate: Date(), articleTitle: "Test article")

        let brands = try store.activeBrands()
        XCTAssertEqual(brands, Set(["argenta", "itsme"]))
    }

    func testExpiredBrandsNotActive() throws {
        let expired = Date().addingTimeInterval(-(SafeonwebCampaignStore.expiryInterval + 1))
        try store.insertBrands(["argenta"], publishedDate: expired, articleTitle: "Old article")

        XCTAssertFalse(try store.isActiveCampaignBrand("argenta"))
        XCTAssertTrue(try store.activeBrands().isEmpty)
    }

    func testPurgeExpired() throws {
        let expired = Date().addingTimeInterval(-(SafeonwebCampaignStore.expiryInterval + 1))
        try store.insertBrands(["argenta"], publishedDate: expired, articleTitle: "Old article")
        try store.insertBrands(["itsme"], publishedDate: Date(), articleTitle: "New article")

        XCTAssertEqual(try store.count(), 2)

        try store.purgeExpired()

        XCTAssertEqual(try store.count(), 1)
        XCTAssertTrue(try store.isActiveCampaignBrand("itsme"))
        XCTAssertFalse(try store.isActiveCampaignBrand("argenta"))
    }

    func testDeduplication() throws {
        try store.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Same article")
        try store.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Same article")

        XCTAssertEqual(try store.count(), 1)
    }

    func testSameBrandDifferentArticles() throws {
        try store.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Article 1")
        try store.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Article 2")

        XCTAssertEqual(try store.count(), 2)
    }

    func testLastFetched() throws {
        XCTAssertNil(try store.lastFetched())

        try store.insertBrands(["argenta"], publishedDate: Date(), articleTitle: "Test")

        let fetched = try store.lastFetched()
        XCTAssertNotNil(fetched)
        XCTAssertTrue(abs(fetched!.timeIntervalSinceNow) < 5)
    }

    func testCaseNormalization() throws {
        try store.insertBrands(["Argenta"], publishedDate: Date(), articleTitle: "Test")

        XCTAssertTrue(try store.isActiveCampaignBrand("argenta"))
        XCTAssertTrue(try store.isActiveCampaignBrand("ARGENTA"))
    }
}
