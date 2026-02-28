import Foundation

/// Check #6: Flags emails with sender or link domains using suspicious TLDs.
/// Adds +2 points per suspicious TLD found.
public struct SuspiciousTLDCheck: PhishingCheck {
    public let name = "Suspicious TLD Check"

    /// TLDs commonly associated with phishing and abuse.
    public static let suspiciousTLDs: Set<String> = [
        "tk", "ml", "ga", "cf", "gq",    // Free TLDs, heavily abused
        "xyz", "top", "club", "work",      // Cheap TLDs, commonly used in phishing
        "buzz", "surf", "rest", "icu",     // Additional high-abuse TLDs
        "cam", "fit", "bid", "loan",       // More abuse-prone TLDs
    ]

    public init() {}

    public func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        var results: [CheckResult] = []
        var checkedDomains = Set<String>()

        // Check sender domain
        if !email.fromDomain.isEmpty {
            if let result = checkDomain(email.fromDomain, context: "sender") {
                results.append(result)
            }
            checkedDomains.insert(email.fromDomain.lowercased())
        }

        // Check link domains from pre-parsed context
        for domain in context.linkDomains {
            guard !checkedDomains.contains(domain) else { continue }
            checkedDomains.insert(domain)

            if let result = checkDomain(domain, context: "link") {
                results.append(result)
            }
        }

        return results
    }

    private func checkDomain(_ domain: String, context: String) -> CheckResult? {
        let tld = extractTLD(from: domain)
        guard Self.suspiciousTLDs.contains(tld) else { return nil }

        return CheckResult(
            checkName: name,
            points: 2,
            reason: "Suspicious TLD .\(tld) found in \(context) domain: \(domain)"
        )
    }

    /// Extracts the TLD from a domain name.
    private func extractTLD(from domain: String) -> String {
        let parts = domain.lowercased().split(separator: ".")
        return parts.last.map(String.init) ?? ""
    }
}
