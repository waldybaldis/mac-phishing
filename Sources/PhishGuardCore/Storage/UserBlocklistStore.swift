import Foundation
import SQLite

/// Manages the user's blocklist of sender domains they want flagged.
public final class UserBlocklistStore: @unchecked Sendable {
    private let db: DatabaseManager

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Checks if a domain is in the user blocklist.
    public func isBlocked(domain: String) throws -> Bool {
        let normalized = domain.lowercased()
        let query = DatabaseManager.userBlocklist.filter(DatabaseManager.userBlocklistDomain == normalized)
        return try db.connection.pluck(query) != nil
    }

    /// Adds a domain to the user blocklist.
    public func add(domain: String) throws {
        let normalized = domain.lowercased()
        try db.connection.run(
            DatabaseManager.userBlocklist.insert(or: .replace,
                DatabaseManager.userBlocklistDomain <- normalized,
                DatabaseManager.userBlocklistTimestamp <- Date().timeIntervalSince1970
            )
        )
    }

    /// Removes a domain from the user blocklist.
    public func remove(domain: String) throws {
        let normalized = domain.lowercased()
        let target = DatabaseManager.userBlocklist.filter(DatabaseManager.userBlocklistDomain == normalized)
        try db.connection.run(target.delete())
    }

    /// Returns all blocked domains.
    public func allDomains() throws -> [String] {
        let query = DatabaseManager.userBlocklist.order(DatabaseManager.userBlocklistDomain)
        return try db.connection.prepare(query).map { $0[DatabaseManager.userBlocklistDomain] }
    }

    /// Returns the number of blocked domains.
    public func count() throws -> Int {
        try db.connection.scalar(DatabaseManager.userBlocklist.count)
    }
}
