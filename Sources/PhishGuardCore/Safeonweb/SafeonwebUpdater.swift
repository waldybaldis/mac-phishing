import Foundation
import os.log

private let logger = Logger(subsystem: "com.phishguard", category: "SafeonwebUpdater")

/// Downloads and processes the Safeonweb RSS feed to extract active phishing campaign brands.
public final class SafeonwebUpdater: @unchecked Sendable {
    /// The Safeonweb phishing alerts RSS feed URLs (Dutch + English for maximum brand coverage).
    public static let feedURLs = [
        URL(string: "https://safeonweb.be/nl/rss")!,
        URL(string: "https://safeonweb.be/en/rss")!,
    ]

    /// Default refresh interval: 24 hours.
    public static let refreshInterval: TimeInterval = 24 * 60 * 60

    private let campaignStore: SafeonwebCampaignStore
    private let urlSession: URLSession
    private var refreshTimer: Timer?

    public init(campaignStore: SafeonwebCampaignStore, urlSession: URLSession = .shared) {
        self.campaignStore = campaignStore
        self.urlSession = urlSession
    }

    /// Downloads the RSS feeds, parses articles, extracts brands, and stores them.
    public func update() async throws -> Int {
        var totalBrands = 0
        var totalArticles = 0
        var lastError: Error?

        for feedURL in Self.feedURLs {
            do {
                let (data, response) = try await urlSession.data(from: feedURL)

                guard let httpResponse = response as? HTTPURLResponse,
                      httpResponse.statusCode == 200 else {
                    logger.warning("Safeonweb feed returned non-200: \(feedURL.absoluteString, privacy: .public)")
                    continue
                }

                let parser = SafeonwebRSSParser()
                let articles = parser.parse(data: data)
                totalArticles += articles.count

                for article in articles {
                    let brands = SafeonwebBrandExtractor.extractBrands(from: article.title)
                    if !brands.isEmpty {
                        try campaignStore.insertBrands(brands, publishedDate: article.pubDate, articleTitle: article.title)
                        totalBrands += brands.count
                        logger.info("Safeonweb campaign: \(article.title, privacy: .public) → brands: \(brands.joined(separator: ", "), privacy: .public)")
                    }
                }
            } catch {
                logger.error("Safeonweb feed fetch failed (\(feedURL.absoluteString, privacy: .public)): \(error.localizedDescription, privacy: .public)")
                lastError = error
            }
        }

        try campaignStore.purgeExpired()

        if totalArticles == 0, let error = lastError {
            throw error
        }

        logger.info("Safeonweb update complete: \(totalBrands) brands from \(totalArticles) articles")
        return totalBrands
    }

    /// Checks if the feed needs refreshing.
    public func needsRefresh() throws -> Bool {
        guard let lastFetched = try campaignStore.lastFetched() else {
            return true
        }
        return Date().timeIntervalSince(lastFetched) > Self.refreshInterval
    }

    /// Updates the feed if it needs refreshing.
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
}

/// Errors that can occur during Safeonweb feed operations.
public enum SafeonwebError: Error, LocalizedError {
    case downloadFailed

    public var errorDescription: String? {
        switch self {
        case .downloadFailed: return "Failed to download the Safeonweb RSS feed"
        }
    }
}
