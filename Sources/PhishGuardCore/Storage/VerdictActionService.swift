import Foundation

/// Shared service for verdict actions (mark safe, block sender, extract href domain).
/// Used by both macOS AlertsListView and iOS AlertsView to avoid duplication.
public final class VerdictActionService {
    private let verdictStore: VerdictStore
    private let allowlistStore: AllowlistStore
    private let trustedLinkDomainStore: TrustedLinkDomainStore
    private let userBlocklistStore: UserBlocklistStore

    public init(
        verdictStore: VerdictStore,
        allowlistStore: AllowlistStore,
        trustedLinkDomainStore: TrustedLinkDomainStore,
        userBlocklistStore: UserBlocklistStore
    ) {
        self.verdictStore = verdictStore
        self.allowlistStore = allowlistStore
        self.trustedLinkDomainStore = trustedLinkDomainStore
        self.userBlocklistStore = userBlocklistStore
    }

    /// Marks a verdict's sender as safe: adds domain to allowlist, marks existing verdicts,
    /// and trusts any link domains flagged in the verdict's reasons.
    public func markSafe(_ verdict: Verdict) {
        let senderDomain = ParsedEmail.extractDomain(from: verdict.from) ?? ""
        if !senderDomain.isEmpty {
            try? allowlistStore.add(domain: senderDomain)
            _ = try? verdictStore.markDomainSafe(domain: senderDomain)
        }

        for reason in verdict.reasons where reason.checkName == "Link Text vs URL Mismatch Check" {
            if let hrefDomain = Self.extractHrefDomain(from: reason.reason) {
                try? trustedLinkDomainStore.add(domain: hrefDomain)
            }
        }
    }

    /// Blocks the sender's domain: adds to blocklist and removes from allowlist.
    public func blockSender(_ verdict: Verdict) {
        let senderDomain = ParsedEmail.extractDomain(from: verdict.from) ?? ""
        guard !senderDomain.isEmpty else { return }
        try? userBlocklistStore.add(domain: senderDomain)
        try? allowlistStore.remove(domain: senderDomain)
    }

    /// Extracts the href domain from a link mismatch reason string.
    /// Expected format: `Link displays "X" but actually points to "Y"`
    public static func extractHrefDomain(from reason: String) -> String? {
        guard let range = reason.range(of: "points to \"") else { return nil }
        let after = reason[range.upperBound...]
        guard let endQuote = after.firstIndex(of: "\"") else { return nil }
        let domain = String(after[after.startIndex..<endQuote])
        let parts = domain.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return nil }
        return parts.suffix(2).joined(separator: ".")
    }
}
