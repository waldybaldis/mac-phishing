import Foundation
import SwiftSoup

/// Check #5: Detects URLs containing raw IP addresses instead of domain names.
/// Adds +4 points per IP-based URL found.
public struct IPURLCheck: PhishingCheck {
    public let name = "IP Address in URL Check"

    private static let ipPattern = try! NSRegularExpression(
        pattern: "https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
        options: .caseInsensitive
    )

    public init() {}

    public func analyze(email: ParsedEmail) -> [CheckResult] {
        var results: [CheckResult] = []

        // Check HTML body links
        if let htmlBody = email.htmlBody {
            let ipURLs = findIPURLsInHTML(htmlBody)
            for url in ipURLs {
                results.append(CheckResult(
                    checkName: name,
                    points: 4,
                    reason: "Link uses raw IP address: \(url)"
                ))
            }
        }

        // Also check plain text body
        if let textBody = email.textBody, results.isEmpty {
            let ipURLs = findIPURLsInText(textBody)
            for url in ipURLs {
                results.append(CheckResult(
                    checkName: name,
                    points: 4,
                    reason: "URL with raw IP address found: \(url)"
                ))
            }
        }

        return results
    }

    /// Extracts IP-based URLs from HTML link href attributes.
    private func findIPURLsInHTML(_ html: String) -> Set<String> {
        var ipURLs = Set<String>()

        guard let doc = try? SwiftSoup.parse(html),
              let links = try? doc.select("a[href]") else {
            return ipURLs
        }

        for link in links {
            guard let href = try? link.attr("href") else { continue }
            if containsIPURL(href) {
                ipURLs.insert(truncateURL(href))
            }
        }

        return ipURLs
    }

    /// Finds IP-based URLs in plain text.
    private func findIPURLsInText(_ text: String) -> Set<String> {
        var ipURLs = Set<String>()
        let range = NSRange(text.startIndex..., in: text)
        let matches = Self.ipPattern.matches(in: text, options: [], range: range)

        for match in matches {
            guard let matchRange = Range(match.range, in: text) else { continue }
            ipURLs.insert(truncateURL(String(text[matchRange])))
        }

        return ipURLs
    }

    private func containsIPURL(_ string: String) -> Bool {
        let range = NSRange(string.startIndex..., in: string)
        return Self.ipPattern.firstMatch(in: string, options: [], range: range) != nil
    }

    /// Truncates a URL for display in reason text.
    private func truncateURL(_ url: String) -> String {
        if url.count > 60 {
            return String(url.prefix(57)) + "..."
        }
        return url
    }
}
