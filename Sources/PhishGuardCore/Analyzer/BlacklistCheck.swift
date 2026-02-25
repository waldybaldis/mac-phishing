import Foundation
import SwiftSoup

/// Check #3: Checks sender domain and all link domains against the cached phishing blacklist.
/// Adds +5 points per blacklisted domain found.
public struct BlacklistCheck: PhishingCheck {
    public let name = "Known Phishing Domain Check"

    private let blacklistStore: BlacklistStore

    public init(blacklistStore: BlacklistStore) {
        self.blacklistStore = blacklistStore
    }

    public func analyze(email: ParsedEmail) -> [CheckResult] {
        var results: [CheckResult] = []

        // Collect all domains to check
        var domainsToCheck = Set<String>()

        // Add sender domain
        if !email.fromDomain.isEmpty {
            domainsToCheck.insert(email.fromDomain.lowercased())
        }

        // Add Return-Path domain
        if let rpDomain = email.returnPathDomain {
            domainsToCheck.insert(rpDomain.lowercased())
        }

        // Extract link domains from HTML body
        if let htmlBody = email.htmlBody {
            let linkDomains = extractLinkDomains(from: htmlBody)
            domainsToCheck.formUnion(linkDomains)
        }

        // Check all domains against the blacklist
        guard let blacklisted = try? blacklistStore.checkDomains(domainsToCheck) else {
            return []
        }

        for domain in blacklisted {
            results.append(CheckResult(
                checkName: name,
                points: 5,
                reason: "Domain \(domain) found in phishing blacklist"
            ))
        }

        return results
    }

    /// Extracts all unique domains from href attributes in HTML content.
    private func extractLinkDomains(from html: String) -> Set<String> {
        var domains = Set<String>()

        guard let doc = try? SwiftSoup.parse(html) else { return domains }
        guard let links = try? doc.select("a[href]") else { return domains }

        for link in links {
            guard let href = try? link.attr("href"),
                  let url = URL(string: href),
                  let host = url.host else { continue }
            domains.insert(host.lowercased())
        }

        return domains
    }
}
