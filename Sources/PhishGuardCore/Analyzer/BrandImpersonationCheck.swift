import Foundation

/// Check #7: Detects when the From display name suggests a brand that doesn't match the sender domain.
/// For example: `DPD <john@gmail.com>` — display name "DPD" has no relation to "gmail.com".
/// Adds +3 points when the display name doesn't appear in the sender domain or local part.
/// Adds +2 more points if no link in the email points to the brand's domain either.
public struct BrandImpersonationCheck: PhishingCheck {
    public let name = "Brand Impersonation Check"
    private let campaignStore: SafeonwebCampaignStore?

    public init(campaignStore: SafeonwebCampaignStore? = nil) {
        self.campaignStore = campaignStore
    }

    public func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        // Extract display name from "Name <email>" format
        guard let displayName = extractDisplayName(from: email.from) else { return [] }

        // Extract meaningful words (3+ chars, letters only)
        let words = displayName
            .lowercased()
            .components(separatedBy: CharacterSet.letters.inverted)
            .filter { $0.count >= 3 }

        guard !words.isEmpty else { return [] }

        let domain = email.fromDomain.lowercased()
        let localPart = extractLocalPart(from: email.from)?.lowercased() ?? ""

        // Check if any display name word appears in the domain
        for word in words {
            if domain.contains(word) {
                return [] // Brand name is in the domain — consistent
            }
        }

        // Check if any display name word appears in the local part.
        // This avoids false positives for personal emails:
        // "John Smith <john.smith@gmail.com>" — "john" is in "john.smith", it's their name.
        for word in words {
            if localPart.contains(word) {
                return [] // Name matches the local part — personal email, not impersonation
            }
        }

        var results: [CheckResult] = []

        // Display name doesn't match domain or local part — potential brand impersonation
        results.append(CheckResult(
            checkName: name,
            points: 3,
            reason: "Display name \"\(displayName)\" does not match sender domain \"\(domain)\""
        ))

        // Check if any link in the email points to a domain containing the brand name.
        // If not, the email claims to be from a brand but doesn't even link to it — highly suspicious.
        if !context.linkDomains.isEmpty {
            let brandInLinks = context.linkDomains.contains { linkDomain in
                words.contains { word in linkDomain.contains(word) }
            }
            if !brandInLinks {
                results.append(CheckResult(
                    checkName: name,
                    points: 2,
                    reason: "No links point to \"\(displayName)\" — all links go to unrelated domains"
                ))
            }
        }

        // Check if any display name word matches an active Safeonweb campaign brand.
        if let store = campaignStore {
            let hasCampaign = words.contains { word in
                (try? store.isActiveCampaignBrand(word)) ?? false
            }
            if hasCampaign {
                results.append(CheckResult(
                    checkName: name,
                    points: 2,
                    reason: "Active Safeonweb phishing campaign targets \"\(displayName)\""
                ))
            }
        }

        return results
    }

    /// Extracts the display name portion from a "Name <email>" string.
    /// Returns nil if there's no display name (bare email address).
    private func extractDisplayName(from: String) -> String? {
        let trimmed = from.trimmingCharacters(in: .whitespaces)
        guard let angleBracket = trimmed.lastIndex(of: "<") else { return nil }
        let name = String(trimmed[..<angleBracket])
            .trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        return name.isEmpty ? nil : name
    }

    /// Extracts the local part (before @) from the From header.
    private func extractLocalPart(from: String) -> String? {
        var email = from
        if let start = from.lastIndex(of: "<"), let end = from.lastIndex(of: ">") {
            email = String(from[from.index(after: start)..<end])
        }
        guard let at = email.lastIndex(of: "@") else { return nil }
        return String(email[..<at])
    }
}
