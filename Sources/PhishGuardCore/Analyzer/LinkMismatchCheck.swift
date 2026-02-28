import Foundation

/// Check #4: Detects links where the display text shows a different domain than the actual href.
/// Adds +4 points per mismatched link.
public struct LinkMismatchCheck: PhishingCheck {
    private let trustedLinkDomainStore: TrustedLinkDomainStore?

    /// Known email service provider (ESP) tracking domains.
    /// Links routed through these are normal for marketing/transactional emails.
    private static let espTrackingDomains: Set<String> = [
        // Mailchimp
        "list-manage.com", "mailchimp.com",
        // Mailjet
        "mjt.lu", "mailjet.com",
        // SendGrid / Twilio
        "sendgrid.net", "sendgrid.com",
        // Mandrill (Mailchimp transactional)
        "mandrillapp.com",
        // Mailgun
        "mailgun.org", "mailgun.net",
        // MailerLite
        "mlsend.com",
        // Campaign Monitor
        "cmail19.com", "cmail20.com", "createsend.com",
        // Constant Contact
        "constantcontact.com",
        // HubSpot
        "hubspot.com", "hs-analytics.net", "hsforms.com",
        // Brevo (ex-Sendinblue)
        "sendinblue.com", "brevo.com", "sibforms.com",
        // Amazon SES
        "amazonses.com",
        // Microsoft Safe Links
        "safelinks.protection.outlook.com",
        // Google (including URL shorteners)
        "google.com", "goo.gl", "c.gle",
        // Retarus (email security gateway)
        "retarus.com",
        // Proofpoint (email security gateway)
        "urldefense.proofpoint.com", "urldefense.com",
        // Barracuda
        "barracuda.com",
        // Mimecast
        "mimecast.com", "mimecastprotect.com",
    ]

    public let name = "Link Text vs URL Mismatch Check"

    public init(trustedLinkDomainStore: TrustedLinkDomainStore? = nil) {
        self.trustedLinkDomainStore = trustedLinkDomainStore
    }

    public func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        var results: [CheckResult] = []
        let senderBase = baseDomain(email.fromDomain)

        for link in context.links {
            // Only check links where display text looks like a URL
            guard looksLikeURL(link.displayText) else { continue }

            let hrefDomain = extractDomainFromURL(link.href)
            let displayDomain = extractDomainFromURL(link.displayText)

            guard let hDomain = hrefDomain, let dDomain = displayDomain else { continue }

            // Skip if either domain looks invalid (no dot = not a real domain,
            // catches quoted-printable artifacts like "3dhttps" or "me.=")
            guard isValidDomain(hDomain), isValidDomain(dDomain) else { continue }

            // Skip if the href points to a known ESP tracking domain
            let hBase = baseDomain(hDomain)
            if Self.espTrackingDomains.contains(hBase) { continue }

            // Skip if the user has marked this href domain as trusted
            if let store = trustedLinkDomainStore,
               (try? store.isTrusted(domain: hBase)) == true { continue }

            // Skip if the href domain matches the sender's domain.
            // e.g., email from mail@ing.com linking to mailing.ing.com — same org's infrastructure.
            if hBase == senderBase { continue }

            // Compare base (registrable) domains.
            // Subdomains of the same base domain are fine (e.g., ing.be vs mailing.ing.be).
            // Different TLDs are flagged (e.g., ing.be vs ing.com) since they could be different entities.
            if hBase != baseDomain(dDomain) {
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

        // Strip common quoted-printable artifacts (=3D prefix from href="..." encoding)
        if cleaned.hasPrefix("3D") || cleaned.hasPrefix("3d") {
            cleaned = String(cleaned.dropFirst(2))
        }

        // Add scheme if missing so URL parsing works
        if !cleaned.hasPrefix("http://") && !cleaned.hasPrefix("https://") {
            cleaned = "https://" + cleaned
        }

        guard let url = URL(string: cleaned) else { return nil }
        return url.host?.lowercased()
    }

    /// Checks if a string looks like a valid domain (has at least one dot with valid parts).
    private func isValidDomain(_ domain: String) -> Bool {
        let parts = domain.split(separator: ".")
        guard parts.count >= 2 else { return false }
        // Each part should be alphanumeric/hyphen only
        return parts.allSatisfy { part in
            !part.isEmpty && part.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
        }
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
