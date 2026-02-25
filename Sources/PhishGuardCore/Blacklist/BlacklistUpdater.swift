import Foundation

/// Downloads and updates the phishing domain blacklist from remote sources.
public final class BlacklistUpdater: @unchecked Sendable {
    /// The Phishing Army blocklist URL.
    public static let phishingArmyURL = URL(string: "https://phishing.army/download/phishing_army_blocklist.txt")!
    public static let sourceName = "phishing_army"

    /// Default refresh interval: 6 hours.
    public static let refreshInterval: TimeInterval = 6 * 60 * 60

    private let blacklistStore: BlacklistStore
    private let urlSession: URLSession
    private var refreshTimer: Timer?

    public init(blacklistStore: BlacklistStore, urlSession: URLSession = .shared) {
        self.blacklistStore = blacklistStore
        self.urlSession = urlSession
    }

    /// Downloads and updates the blacklist from Phishing Army.
    public func update() async throws -> Int {
        let (data, response) = try await urlSession.data(from: Self.phishingArmyURL)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw BlacklistError.downloadFailed
        }

        guard let text = String(data: data, encoding: .utf8) else {
            throw BlacklistError.invalidFormat
        }

        let domains = parseDomainList(text)
        try blacklistStore.replaceAll(domains: domains, source: Self.sourceName)

        return domains.count
    }

    /// Checks if the blacklist needs refreshing.
    public func needsRefresh() throws -> Bool {
        guard let lastUpdated = try blacklistStore.lastUpdated(source: Self.sourceName) else {
            return true // Never updated
        }
        return Date().timeIntervalSince(lastUpdated) > Self.refreshInterval
    }

    /// Updates the blacklist if it needs refreshing.
    public func updateIfNeeded() async throws {
        if try needsRefresh() {
            _ = try await update()
        }
    }

    /// Starts a periodic refresh timer.
    @MainActor
    public func startPeriodicRefresh() {
        stopPeriodicRefresh()

        refreshTimer = Timer.scheduledTimer(
            withTimeInterval: Self.refreshInterval,
            repeats: true
        ) { [weak self] _ in
            guard let self else { return }
            Task {
                try? await self.updateIfNeeded()
            }
        }

        // Also trigger an immediate check
        Task {
            try? await updateIfNeeded()
        }
    }

    /// Stops the periodic refresh timer.
    @MainActor
    public func stopPeriodicRefresh() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    // MARK: - Parsing

    /// Parses a plain text domain list (one domain per line, # comments).
    func parseDomainList(_ text: String) -> [String] {
        text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }
}

/// Errors that can occur during blacklist operations.
public enum BlacklistError: Error, LocalizedError {
    case downloadFailed
    case invalidFormat

    public var errorDescription: String? {
        switch self {
        case .downloadFailed: return "Failed to download the phishing blacklist"
        case .invalidFormat: return "The blacklist file format is invalid"
        }
    }
}
