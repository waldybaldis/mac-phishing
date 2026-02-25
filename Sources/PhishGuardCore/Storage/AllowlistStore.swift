import Foundation
import SQLite

/// Manages the user's allowlist of trusted sender domains.
public final class AllowlistStore: @unchecked Sendable {
    private let db: DatabaseManager

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Checks if a domain is in the allowlist.
    public func isAllowed(domain: String) throws -> Bool {
        let normalized = domain.lowercased()
        let query = DatabaseManager.allowlist.filter(DatabaseManager.allowlistDomain == normalized)
        return try db.connection.pluck(query) != nil
    }

    /// Adds a domain to the allowlist.
    public func add(domain: String, addedByUser: Bool = true) throws {
        let normalized = domain.lowercased()
        try db.connection.run(
            DatabaseManager.allowlist.insert(or: .replace,
                DatabaseManager.allowlistDomain <- normalized,
                DatabaseManager.allowlistAddedByUser <- addedByUser,
                DatabaseManager.allowlistTimestamp <- Date().timeIntervalSince1970
            )
        )
    }

    /// Removes a domain from the allowlist.
    public func remove(domain: String) throws {
        let normalized = domain.lowercased()
        let target = DatabaseManager.allowlist.filter(DatabaseManager.allowlistDomain == normalized)
        try db.connection.run(target.delete())
    }

    /// Returns all allowlisted domains.
    public func allDomains() throws -> [String] {
        let query = DatabaseManager.allowlist.order(DatabaseManager.allowlistDomain)
        return try db.connection.prepare(query).map { $0[DatabaseManager.allowlistDomain] }
    }
}
