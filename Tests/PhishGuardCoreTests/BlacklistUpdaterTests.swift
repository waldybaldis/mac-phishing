import XCTest
@testable import PhishGuardCore

final class BlacklistUpdaterTests: XCTestCase {
    var db: DatabaseManager!
    var blacklistStore: BlacklistStore!

    override func setUp() async throws {
        db = try DatabaseManager(inMemory: true)
        blacklistStore = BlacklistStore(database: db)
    }

    func testParseDomainList() {
        let updater = BlacklistUpdater(blacklistStore: blacklistStore)

        let input = """
        # Phishing Army blocklist
        # Last updated: 2025-01-01

        evil-domain.com
        phishing-site.net
        scam.org
        # This is a comment
        another-bad.tk

        """

        let domains = updater.parseDomainList(input)
        XCTAssertEqual(domains.count, 4)
        XCTAssertTrue(domains.contains("evil-domain.com"))
        XCTAssertTrue(domains.contains("phishing-site.net"))
        XCTAssertTrue(domains.contains("scam.org"))
        XCTAssertTrue(domains.contains("another-bad.tk"))
    }

    func testParseDomainListEmpty() {
        let updater = BlacklistUpdater(blacklistStore: blacklistStore)
        let domains = updater.parseDomainList("")
        XCTAssertTrue(domains.isEmpty)
    }

    func testParseDomainListCommentsOnly() {
        let updater = BlacklistUpdater(blacklistStore: blacklistStore)
        let input = """
        # Comment 1
        # Comment 2
        """
        let domains = updater.parseDomainList(input)
        XCTAssertTrue(domains.isEmpty)
    }

    func testNeedsRefreshWhenNeverUpdated() throws {
        let updater = BlacklistUpdater(blacklistStore: blacklistStore)
        XCTAssertTrue(try updater.needsRefresh())
    }

    func testNeedsRefreshAfterRecent() throws {
        // Populate blacklist (simulates recent update)
        try blacklistStore.replaceAll(domains: ["test.com"], source: BlacklistUpdater.sourceName)

        let updater = BlacklistUpdater(blacklistStore: blacklistStore)
        XCTAssertFalse(try updater.needsRefresh())
    }
}
