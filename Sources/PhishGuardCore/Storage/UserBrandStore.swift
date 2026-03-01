import Foundation
import SQLite

/// Manages user-defined brand names to watch for impersonation.
public final class UserBrandStore: @unchecked Sendable {
    private let db: DatabaseManager

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Adds a brand to the watchlist.
    public func add(brand: String) throws {
        let normalized = brand.lowercased()
        try db.connection.run(
            DatabaseManager.userBrands.insert(or: .replace,
                DatabaseManager.userBrand <- normalized,
                DatabaseManager.userBrandTimestamp <- Date().timeIntervalSince1970
            )
        )
    }

    /// Removes a brand from the watchlist.
    public func remove(brand: String) throws {
        let normalized = brand.lowercased()
        let target = DatabaseManager.userBrands.filter(DatabaseManager.userBrand == normalized)
        try db.connection.run(target.delete())
    }

    /// Returns all watched brands, sorted alphabetically.
    public func allBrands() throws -> [String] {
        let query = DatabaseManager.userBrands.order(DatabaseManager.userBrand)
        return try db.connection.prepare(query).map { $0[DatabaseManager.userBrand] }
    }

    /// Checks if a brand is in the watchlist.
    public func isWatched(_ brand: String) throws -> Bool {
        let normalized = brand.lowercased()
        let query = DatabaseManager.userBrands.filter(DatabaseManager.userBrand == normalized)
        return try db.connection.pluck(query) != nil
    }

    /// Removes all brands from the watchlist.
    public func removeAll() throws {
        try db.connection.run(DatabaseManager.userBrands.delete())
    }

    /// Returns the number of watched brands.
    public func count() throws -> Int {
        try db.connection.scalar(DatabaseManager.userBrands.count)
    }

}
