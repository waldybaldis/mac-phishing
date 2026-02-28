import Foundation
import SQLite

/// Manages the shared SQLite database in the App Group container.
public final class DatabaseManager: @unchecked Sendable {
    let connection: Connection

    // MARK: - Table Definitions

    static let verdicts = Table("verdicts")
    static let verdictMessageId = SQLite.Expression<String>("message_id")
    static let verdictScore = SQLite.Expression<Int>("score")
    static let verdictReasons = SQLite.Expression<String>("reasons")  // JSON
    static let verdictTimestamp = SQLite.Expression<Double>("timestamp")
    static let verdictActionTaken = SQLite.Expression<String?>("action_taken")
    static let verdictFrom = SQLite.Expression<String>("sender")
    static let verdictSubject = SQLite.Expression<String>("subject")
    static let verdictReceivedDate = SQLite.Expression<Double>("received_date")
    static let verdictImapUID = SQLite.Expression<Int?>("imap_uid")

    static let blacklist = Table("blacklist")
    static let blacklistDomain = SQLite.Expression<String>("domain")
    static let blacklistSource = SQLite.Expression<String>("source")
    static let blacklistLastUpdated = SQLite.Expression<Double>("last_updated")

    static let allowlist = Table("allowlist")
    static let allowlistDomain = SQLite.Expression<String>("domain")
    static let allowlistAddedByUser = SQLite.Expression<Bool>("added_by_user")
    static let allowlistTimestamp = SQLite.Expression<Double>("timestamp")

    static let trustedLinkDomains = Table("trusted_link_domains")
    static let trustedLinkDomain = SQLite.Expression<String>("domain")
    static let trustedLinkTimestamp = SQLite.Expression<Double>("timestamp")

    static let safeonwebCampaigns = Table("safeonweb_campaigns")
    static let safeonwebBrand = SQLite.Expression<String>("brand")
    static let safeonwebPublishedDate = SQLite.Expression<Double>("published_date")
    static let safeonwebFetchedDate = SQLite.Expression<Double>("fetched_date")
    static let safeonwebArticleTitle = SQLite.Expression<String>("article_title")

    public init(databasePath: String? = nil) throws {
        let path = databasePath ?? Self.defaultDatabasePath()

        // Ensure directory exists
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        connection = try Connection(path)
        connection.busyTimeout = 5
        try createTables()
    }

    /// Initializes with an in-memory database, useful for testing.
    public init(inMemory: Bool) throws {
        connection = try Connection(.inMemory)
        connection.busyTimeout = 5
        try createTables()
    }

    /// Returns the default database path in the App Group container.
    public static func defaultDatabasePath() -> String {
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.phishguard"
        ) {
            return containerURL.appendingPathComponent("verdicts.sqlite").path
        }
        // Fallback for unsigned dev builds
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let phishGuardDir = appSupport.appendingPathComponent("PhishGuard")
        return phishGuardDir.appendingPathComponent("verdicts.sqlite").path
    }

    private func createTables() throws {
        try connection.run(Self.verdicts.create(ifNotExists: true) { t in
            t.column(Self.verdictMessageId, primaryKey: true)
            t.column(Self.verdictScore)
            t.column(Self.verdictReasons)
            t.column(Self.verdictTimestamp)
            t.column(Self.verdictActionTaken)
            t.column(Self.verdictFrom, defaultValue: "")
            t.column(Self.verdictSubject, defaultValue: "")
            t.column(Self.verdictReceivedDate, defaultValue: 0)
            t.column(Self.verdictImapUID)
        })

        // Migration: add new columns to existing databases
        let tableInfo = try connection.prepare("PRAGMA table_info(verdicts)")
        let existingColumns = Set(tableInfo.map { $0[1] as! String })
        if !existingColumns.contains("sender") {
            try connection.run(Self.verdicts.addColumn(Self.verdictFrom, defaultValue: ""))
        }
        if !existingColumns.contains("subject") {
            try connection.run(Self.verdicts.addColumn(Self.verdictSubject, defaultValue: ""))
        }
        if !existingColumns.contains("received_date") {
            try connection.run(Self.verdicts.addColumn(Self.verdictReceivedDate, defaultValue: 0))
        }
        if !existingColumns.contains("imap_uid") {
            try connection.run(Self.verdicts.addColumn(Self.verdictImapUID))
        }

        try connection.run(Self.blacklist.create(ifNotExists: true) { t in
            t.column(Self.blacklistDomain, primaryKey: true)
            t.column(Self.blacklistSource)
            t.column(Self.blacklistLastUpdated)
        })

        try connection.run(Self.allowlist.create(ifNotExists: true) { t in
            t.column(Self.allowlistDomain, primaryKey: true)
            t.column(Self.allowlistAddedByUser)
            t.column(Self.allowlistTimestamp)
        })

        try connection.run(Self.trustedLinkDomains.create(ifNotExists: true) { t in
            t.column(Self.trustedLinkDomain, primaryKey: true)
            t.column(Self.trustedLinkTimestamp)
        })

        try connection.run(Self.safeonwebCampaigns.create(ifNotExists: true) { t in
            t.column(Self.safeonwebBrand)
            t.column(Self.safeonwebPublishedDate)
            t.column(Self.safeonwebFetchedDate)
            t.column(Self.safeonwebArticleTitle)
            t.unique(Self.safeonwebBrand, Self.safeonwebArticleTitle)
        })

        try connection.run(Self.verdicts.createIndex(Self.verdictTimestamp, ifNotExists: true))
    }
}
