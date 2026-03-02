import Foundation
import SQLite

/// Manages Safeonweb active phishing campaign brands in the shared database.
/// @unchecked Sendable: only holds an immutable reference to DatabaseManager.
/// Thread safety is provided by SQLite.swift's Connection (WAL mode + busyTimeout).
public final class SafeonwebCampaignStore: @unchecked Sendable {
    private let db: DatabaseManager

    /// Campaigns older than 90 days are considered expired.
    public static let expiryInterval: TimeInterval = 90 * 24 * 60 * 60

    /// Article title used for seeded archive brands (exempt from expiry).
    public static let seedArticleTitle = "Safeonweb archive seed"

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Returns all non-expired campaign brand names (lowercased).
    /// Seeded archive brands are always included regardless of age.
    public func activeBrands() throws -> Set<String> {
        let cutoff = Date().timeIntervalSince1970 - Self.expiryInterval
        let query = DatabaseManager.safeonwebCampaigns
            .filter(DatabaseManager.safeonwebPublishedDate > cutoff
                    || DatabaseManager.safeonwebArticleTitle == Self.seedArticleTitle)
            .select(distinct: DatabaseManager.safeonwebBrand)
        var brands = Set<String>()
        for row in try db.connection.prepare(query) {
            brands.insert(row[DatabaseManager.safeonwebBrand])
        }
        return brands
    }

    /// Checks if a brand has an active (non-expired) Safeonweb campaign or is a seeded archive brand.
    public func isActiveCampaignBrand(_ brand: String) throws -> Bool {
        let normalized = brand.lowercased()
        let cutoff = Date().timeIntervalSince1970 - Self.expiryInterval
        let query = DatabaseManager.safeonwebCampaigns
            .filter(DatabaseManager.safeonwebBrand == normalized
                    && (DatabaseManager.safeonwebPublishedDate > cutoff
                        || DatabaseManager.safeonwebArticleTitle == Self.seedArticleTitle))
            .limit(1)
        return try db.connection.pluck(query) != nil
    }

    /// Inserts brands extracted from an article. Duplicates (same brand + article title) are ignored.
    public func insertBrands(_ brands: [String], publishedDate: Date, articleTitle: String) throws {
        let now = Date().timeIntervalSince1970
        let pubTimestamp = publishedDate.timeIntervalSince1970

        for brand in brands {
            let normalized = brand.lowercased()
            try db.connection.run(
                DatabaseManager.safeonwebCampaigns.insert(or: .ignore,
                    DatabaseManager.safeonwebBrand <- normalized,
                    DatabaseManager.safeonwebPublishedDate <- pubTimestamp,
                    DatabaseManager.safeonwebFetchedDate <- now,
                    DatabaseManager.safeonwebArticleTitle <- articleTitle
                )
            )
        }
    }

    /// Deletes campaigns older than 90 days, preserving seeded archive brands.
    public func purgeExpired() throws {
        let cutoff = Date().timeIntervalSince1970 - Self.expiryInterval
        let expired = DatabaseManager.safeonwebCampaigns
            .filter(DatabaseManager.safeonwebPublishedDate <= cutoff
                    && DatabaseManager.safeonwebArticleTitle != Self.seedArticleTitle)
        try db.connection.run(expired.delete())
    }

    /// Returns the most recent fetch date, or nil if never fetched.
    public func lastFetched() throws -> Date? {
        let query = DatabaseManager.safeonwebCampaigns
            .select(DatabaseManager.safeonwebFetchedDate)
            .order(DatabaseManager.safeonwebFetchedDate.desc)
            .limit(1)
        guard let row = try db.connection.pluck(query) else { return nil }
        return Date(timeIntervalSince1970: row[DatabaseManager.safeonwebFetchedDate])
    }

    /// Returns the total number of campaign entries.
    public func count() throws -> Int {
        try db.connection.scalar(DatabaseManager.safeonwebCampaigns.count)
    }

    /// Seeds the campaign store with brands extracted from the full Safeonweb news archive (2020–2026).
    /// Uses insert-or-ignore so existing entries are not overwritten.
    /// Call once from the installer or on first launch.
    public func seedArchiveBrands() throws {
        let now = Date()
        for brand in Self.archiveBrands {
            try insertBrands([brand], publishedDate: now, articleTitle: Self.seedArticleTitle)
        }
    }

    /// Brands extracted from 445 Safeonweb news articles (2020–2026).
    static let archiveBrands: [String] = [
        // Belgian banks & financial
        "argenta", "belfius", "kbc", "fortis", "bnp",
        // Payment & fintech
        "paypal", "bitvavo", "visa",
        // Belgian government & public services
        "csam", "ebox", "mypension", "onss", "onva", "nmbs", "sncb",
        // Belgian utilities & telecom
        "proximus", "telenet", "fluvius", "luminus", "engie", "orange",
        "skynet", "watergroep", "farys",
        // Insurance & mutuals
        "partenamut", "axa", "pluxee", "febelfin", "atradius",
        // Retail & delivery
        "bpost", "postnl", "bol.com", "delhaize", "lidl", "amazon",
        "combell", "doccle", "casa",
        // Package delivery
        "dpd", "dhl", "fedex", "ups", "gls",
        // Tech & social
        "netflix", "microsoft", "facebook", "instagram", "whatsapp",
        "icloud", "wetransfer", "itsme",
        // Belgian orgs
        "europol", "liantis", "nihdi", "ccb",
        // Transport
        "2dehands", "sodexo", "cardstop",
    ]
}
