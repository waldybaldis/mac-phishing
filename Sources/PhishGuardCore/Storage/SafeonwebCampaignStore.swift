import Foundation
import SQLite

/// Manages Safeonweb active phishing campaign brands in the shared database.
public final class SafeonwebCampaignStore: @unchecked Sendable {
    private let db: DatabaseManager

    /// Campaigns older than 90 days are considered expired.
    public static let expiryInterval: TimeInterval = 90 * 24 * 60 * 60

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Returns all non-expired campaign brand names (lowercased).
    public func activeBrands() throws -> Set<String> {
        let cutoff = Date().timeIntervalSince1970 - Self.expiryInterval
        let query = DatabaseManager.safeonwebCampaigns
            .filter(DatabaseManager.safeonwebPublishedDate > cutoff)
            .select(distinct: DatabaseManager.safeonwebBrand)
        var brands = Set<String>()
        for row in try db.connection.prepare(query) {
            brands.insert(row[DatabaseManager.safeonwebBrand])
        }
        return brands
    }

    /// Checks if a brand has an active (non-expired) Safeonweb campaign.
    public func isActiveCampaignBrand(_ brand: String) throws -> Bool {
        let normalized = brand.lowercased()
        let cutoff = Date().timeIntervalSince1970 - Self.expiryInterval
        let query = DatabaseManager.safeonwebCampaigns
            .filter(DatabaseManager.safeonwebBrand == normalized
                    && DatabaseManager.safeonwebPublishedDate > cutoff)
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

    /// Deletes campaigns older than 90 days.
    public func purgeExpired() throws {
        let cutoff = Date().timeIntervalSince1970 - Self.expiryInterval
        let expired = DatabaseManager.safeonwebCampaigns
            .filter(DatabaseManager.safeonwebPublishedDate <= cutoff)
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
}
