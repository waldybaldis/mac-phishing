import Foundation
import os.log

private let logger = Logger(subsystem: "com.phishguard", category: "CoreSession")

/// Owns the shared database, all stores, and the phishing analyzer.
/// Both macOS `AccountManager` and iOS `MobileAccountManager` use this as a dependency
/// to avoid duplicating ~170 lines of initialization logic.
public final class CoreSession {
    public let dbManager: DatabaseManager?
    public let verdictStore: VerdictStore
    public let blacklistStore: BlacklistStore
    public let allowlistStore: AllowlistStore
    public let trustedLinkDomainStore: TrustedLinkDomainStore
    public let campaignStore: SafeonwebCampaignStore
    public let userBrandStore: UserBrandStore
    public let userBlocklistStore: UserBlocklistStore
    public let safeonwebUpdater: SafeonwebUpdater
    public let analyzer: PhishingAnalyzer

    /// Creates a CoreSession using the given database path.
    /// Falls back to an in-memory database if the on-disk database can't be opened.
    public init(databasePath: String? = nil) {
        let db = Self.openDatabase(path: databasePath)
        self.dbManager = db

        let blacklistStore = BlacklistStore(database: db)
        let allowlistStore = AllowlistStore(database: db)
        let trustedLinkDomainStore = TrustedLinkDomainStore(database: db)
        let campaignStore = SafeonwebCampaignStore(database: db)
        let userBrandStore = UserBrandStore(database: db)
        let userBlocklistStore = UserBlocklistStore(database: db)

        self.verdictStore = VerdictStore(database: db)
        self.blacklistStore = blacklistStore
        self.allowlistStore = allowlistStore
        self.trustedLinkDomainStore = trustedLinkDomainStore
        self.campaignStore = campaignStore
        self.userBrandStore = userBrandStore
        self.userBlocklistStore = userBlocklistStore
        self.safeonwebUpdater = SafeonwebUpdater(campaignStore: campaignStore)
        self.analyzer = PhishingAnalyzer(
            blacklistStore: blacklistStore,
            allowlistStore: allowlistStore,
            trustedLinkDomainStore: trustedLinkDomainStore,
            campaignStore: campaignStore,
            userBrandStore: userBrandStore,
            userBlocklistStore: userBlocklistStore
        )
    }

    /// Convenience: creates a `VerdictActionService` from this session's stores.
    public func makeVerdictActionService() -> VerdictActionService {
        VerdictActionService(
            verdictStore: verdictStore,
            allowlistStore: allowlistStore,
            trustedLinkDomainStore: trustedLinkDomainStore,
            userBlocklistStore: userBlocklistStore
        )
    }

    /// Seeds Safeonweb archive brands if not yet done, and starts periodic refresh.
    @MainActor
    public func seedAndStartUpdates() {
        if !UserDefaults.standard.bool(forKey: "safeonwebArchiveSeeded") {
            try? campaignStore.seedArchiveBrands()
            UserDefaults.standard.set(true, forKey: "safeonwebArchiveSeeded")
        }
        safeonwebUpdater.startPeriodicRefresh()
    }

    // MARK: - Private

    private static func openDatabase(path: String?) -> DatabaseManager {
        if let path = path {
            if let db = try? DatabaseManager(databasePath: path) { return db }
        } else {
            if let db = try? DatabaseManager() { return db }
        }
        logger.warning("Failed to open on-disk database, falling back to in-memory")
        return try! DatabaseManager(inMemory: true)
    }
}
