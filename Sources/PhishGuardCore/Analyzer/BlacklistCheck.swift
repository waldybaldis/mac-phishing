import Foundation

/// Check #3: Checks sender domain and all link domains against the cached phishing blacklist.
/// Adds +5 points per blacklisted domain found.
public struct BlacklistCheck: PhishingCheck {
    public let name = "Known Phishing Domain Check"

    private let blacklistStore: BlacklistStore

    public init(blacklistStore: BlacklistStore) {
        self.blacklistStore = blacklistStore
    }

    public func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
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

        // Add link domains from pre-parsed context
        domainsToCheck.formUnion(context.linkDomains)

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
}
