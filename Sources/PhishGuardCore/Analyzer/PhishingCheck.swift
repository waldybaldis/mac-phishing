import Foundation
import SwiftSoup

/// Pre-parsed data shared across all checks to avoid redundant HTML parsing.
public struct AnalysisContext: Sendable {
    /// A link extracted from the email's HTML body.
    public struct LinkInfo: Sendable {
        public let href: String
        public let displayText: String
        public let domain: String?
    }

    /// All <a href> links extracted from the HTML body (parsed once).
    public let links: [LinkInfo]

    /// All unique link domains (lowercased).
    public let linkDomains: Set<String>

    public static let empty = AnalysisContext(links: [], linkDomains: [])

    /// Builds context by parsing the email's HTML body once.
    public static func from(email: ParsedEmail) -> AnalysisContext {
        guard let htmlBody = email.htmlBody, !htmlBody.isEmpty,
              let doc = try? SwiftSoup.parse(htmlBody),
              let anchors = try? doc.select("a[href]") else {
            return .empty
        }

        var links: [LinkInfo] = []
        var domains = Set<String>()

        for anchor in anchors {
            guard let href = try? anchor.attr("href") else { continue }
            let displayText = (try? anchor.text()) ?? ""
            let domain = URL(string: href)?.host?.lowercased()

            links.append(LinkInfo(href: href, displayText: displayText, domain: domain))
            if let domain = domain { domains.insert(domain) }
        }

        return AnalysisContext(links: links, linkDomains: domains)
    }
}

/// Protocol for individual phishing detection checks.
public protocol PhishingCheck: Sendable {
    /// A human-readable name for this check.
    var name: String { get }

    /// Analyzes an email and returns check results (empty if check passes).
    func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult]
}
