import Foundation
import SQLite

/// Manages the phishing domain blacklist in the shared database.
public final class BlacklistStore: @unchecked Sendable {
    private let db: DatabaseManager

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Checks if a domain is in the blacklist.
    public func isBlacklisted(domain: String) throws -> Bool {
        let normalized = domain.lowercased()
        let query = DatabaseManager.blacklist.filter(DatabaseManager.blacklistDomain == normalized)
        return try db.connection.pluck(query) != nil
    }

    /// Checks multiple domains at once, returns the set of blacklisted ones.
    public func checkDomains(_ domains: Set<String>) throws -> Set<String> {
        guard !domains.isEmpty else { return [] }
        let normalized = domains.map { $0.lowercased() }
        let query = DatabaseManager.blacklist.filter(normalized.contains(DatabaseManager.blacklistDomain))
        var found = Set<String>()
        for row in try db.connection.prepare(query) {
            found.insert(row[DatabaseManager.blacklistDomain])
        }
        return found
    }

    /// Replaces the entire blacklist with new entries from a given source.
    public func replaceAll(domains: [String], source: String) throws {
        let now = Date().timeIntervalSince1970

        try db.connection.transaction {
            // Delete existing entries from this source
            let sourceEntries = DatabaseManager.blacklist.filter(DatabaseManager.blacklistSource == source)
            try self.db.connection.run(sourceEntries.delete())

            // Batch insert new entries
            for domain in domains {
                let normalized = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
                guard !normalized.isEmpty, !normalized.hasPrefix("#") else { continue }
                try self.db.connection.run(
                    DatabaseManager.blacklist.insert(or: .replace,
                        DatabaseManager.blacklistDomain <- normalized,
                        DatabaseManager.blacklistSource <- source,
                        DatabaseManager.blacklistLastUpdated <- now
                    )
                )
            }
        }
    }

    /// Returns the total number of entries in the blacklist.
    public func count() throws -> Int {
        try db.connection.scalar(DatabaseManager.blacklist.count)
    }

    /// Returns when the blacklist was last updated for a given source.
    public func lastUpdated(source: String) throws -> Date? {
        let query = DatabaseManager.blacklist
            .filter(DatabaseManager.blacklistSource == source)
            .order(DatabaseManager.blacklistLastUpdated.desc)
            .limit(1)

        guard let row = try db.connection.pluck(query) else { return nil }
        let timestamp = row[DatabaseManager.blacklistLastUpdated]
        return Date(timeIntervalSince1970: timestamp)
    }
}
