import Foundation
import SwiftSoup

/// Check #4: Detects links where the display text shows a different domain than the actual href.
/// Adds +4 points per mismatched link.
public struct LinkMismatchCheck: PhishingCheck {
    public let name = "Link Text vs URL Mismatch Check"

    public init() {}

    public func analyze(email: ParsedEmail) -> [CheckResult] {
        guard let htmlBody = email.htmlBody, !htmlBody.isEmpty else {
            return []
        }

        var results: [CheckResult] = []

        guard let doc = try? SwiftSoup.parse(htmlBody),
              let links = try? doc.select("a[href]") else {
            return []
        }

        for link in links {
            guard let href = try? link.attr("href"),
                  let displayText = try? link.text() else { continue }

            // Only check links where display text looks like a URL
            guard looksLikeURL(displayText) else { continue }

            let hrefDomain = extractDomainFromURL(href)
            let displayDomain = extractDomainFromURL(displayText)

            guard let hDomain = hrefDomain, let dDomain = displayDomain else { continue }

            // Compare base domains
            if baseDomain(hDomain) != baseDomain(dDomain) {
                results.append(CheckResult(
                    checkName: name,
                    points: 4,
                    reason: "Link displays \"\(dDomain)\" but actually points to \"\(hDomain)\""
                ))
            }
        }

        return results
    }

    /// Checks if a string looks like a URL or domain name.
    private func looksLikeURL(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
            return true
        }
        // Check if it looks like a domain (contains a dot and no spaces)
        if trimmed.contains(".") && !trimmed.contains(" ") && trimmed.count > 4 {
            return true
        }
        return false
    }

    /// Extracts the host domain from a URL string.
    private func extractDomainFromURL(_ urlString: String) -> String? {
        var cleaned = urlString.trimmingCharacters(in: .whitespacesAndNewlines)

        // Add scheme if missing so URL parsing works
        if !cleaned.hasPrefix("http://") && !cleaned.hasPrefix("https://") {
            cleaned = "https://" + cleaned
        }

        guard let url = URL(string: cleaned) else { return nil }
        return url.host?.lowercased()
    }

    /// Extracts the base (registrable) domain from a full domain.
    private func baseDomain(_ domain: String) -> String {
        let parts = domain.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return domain }

        let twoPartTLDs = ["co.uk", "com.au", "co.nz", "co.za", "com.br", "co.jp", "co.in"]
        if parts.count >= 3 {
            let lastTwo = "\(parts[parts.count - 2]).\(parts[parts.count - 1])"
            if twoPartTLDs.contains(lastTwo) {
                return parts.suffix(3).joined(separator: ".")
            }
        }

        return parts.suffix(2).joined(separator: ".")
    }
}
