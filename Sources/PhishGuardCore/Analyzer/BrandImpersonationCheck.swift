import Foundation

/// Check #7: Detects when the From display name suggests a brand that doesn't match the sender domain.
/// For example: `DPD <john@gmail.com>` — display name "DPD" has no relation to "gmail.com".
/// Adds +2 points when the display name doesn't appear in the sender domain or local part.
public struct BrandImpersonationCheck: PhishingCheck {
    public let name = "Brand Impersonation Check"

    public init() {}

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

        // Display name doesn't match domain or local part — potential brand impersonation
        return [CheckResult(
            checkName: name,
            points: 2,
            reason: "Display name \"\(displayName)\" does not match sender domain \"\(domain)\""
        )]
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
