import Foundation
import SQLite

/// Manages user-trusted link domains. When a user marks a link mismatch alert as safe,
/// the href domain is added here so LinkMismatchCheck skips it in future analysis.
public final class TrustedLinkDomainStore: @unchecked Sendable {
    private let db: DatabaseManager

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Checks if a domain is trusted.
    public func isTrusted(domain: String) throws -> Bool {
        let normalized = domain.lowercased()
        let query = DatabaseManager.trustedLinkDomains.filter(DatabaseManager.trustedLinkDomain == normalized)
        return try db.connection.pluck(query) != nil
    }

    /// Adds a domain to the trusted list.
    public func add(domain: String) throws {
        let normalized = domain.lowercased()
        try db.connection.run(
            DatabaseManager.trustedLinkDomains.insert(or: .replace,
                DatabaseManager.trustedLinkDomain <- normalized,
                DatabaseManager.trustedLinkTimestamp <- Date().timeIntervalSince1970
            )
        )
    }

    /// Returns all trusted link domains.
    public func allDomains() throws -> Set<String> {
        let query = DatabaseManager.trustedLinkDomains
        return Set(try db.connection.prepare(query).map { $0[DatabaseManager.trustedLinkDomain] })
    }
}
