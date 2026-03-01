import Foundation

/// Check #7: Detects when the From display name matches a known brand but the sender domain doesn't.
/// Only flags when the display name word matches a brand from the user's watchlist or an active
/// Safeonweb campaign — personal names on any domain are not flagged.
/// Adds +3 points when a known brand is detected in the display name but not in the sender domain.
/// Adds +2 more points if no link in the email points to the brand's domain either.
/// Adds +2 more points if the brand has an active Safeonweb phishing campaign.
public struct BrandImpersonationCheck: PhishingCheck {
    public let name = "Brand Impersonation Check"
    private let campaignStore: SafeonwebCampaignStore?
    private let userBrandStore: UserBrandStore?

    public init(campaignStore: SafeonwebCampaignStore? = nil, userBrandStore: UserBrandStore? = nil) {
        self.campaignStore = campaignStore
        self.userBrandStore = userBrandStore
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

        // Check if any display name word appears in the domain — consistent, no impersonation
        for word in words {
            if domain.contains(word) {
                return []
            }
        }

        // Check if any display name word appears in the local part — personal email
        for word in words {
            if localPart.contains(word) {
                return []
            }
        }

        // Only flag if at least one word matches a known brand
        let matchedBrand = words.first { word in
            let isUserBrand = (try? userBrandStore?.isWatched(word)) ?? false
            let isCampaignBrand = (try? campaignStore?.isActiveCampaignBrand(word)) ?? false
            return isUserBrand || isCampaignBrand
        }

        guard let brand = matchedBrand else { return [] }
        _ = brand // brand identified — proceed with flagging

        var results: [CheckResult] = []

        // Known brand in display name doesn't match domain — brand impersonation
        results.append(CheckResult(
            checkName: name,
            points: 3,
            reason: "Display name \"\(displayName)\" does not match sender domain \"\(domain)\""
        ))

        // Check if any link in the email points to a domain containing the brand name.
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
