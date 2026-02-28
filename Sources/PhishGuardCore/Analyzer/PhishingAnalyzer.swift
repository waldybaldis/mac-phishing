import Foundation

/// The main phishing analysis engine. Runs all configured checks against an email
/// and produces a scored verdict.
public final class PhishingAnalyzer: @unchecked Sendable {
    private let checks: [PhishingCheck]
    private let allowlistStore: AllowlistStore?

    /// Creates an analyzer with the specified checks.
    /// - Parameters:
    ///   - checks: The phishing checks to run. If empty, uses default Tier 1 checks.
    ///   - allowlistStore: Optional allowlist store to skip analysis for trusted domains.
    public init(checks: [PhishingCheck], allowlistStore: AllowlistStore? = nil) {
        self.checks = checks
        self.allowlistStore = allowlistStore
    }

    /// Creates an analyzer with all default Tier 1 checks.
    /// - Parameters:
    ///   - blacklistStore: The blacklist store for domain lookups.
    ///   - allowlistStore: Optional allowlist store for trusted domains.
    ///   - trustedLinkDomainStore: Optional store for user-trusted link domains.
    ///   - campaignStore: Optional Safeonweb campaign store for active phishing campaign detection.
    public convenience init(blacklistStore: BlacklistStore, allowlistStore: AllowlistStore? = nil, trustedLinkDomainStore: TrustedLinkDomainStore? = nil, campaignStore: SafeonwebCampaignStore? = nil) {
        let checks: [PhishingCheck] = [
            AuthHeaderCheck(),
            ReturnPathCheck(),
            BlacklistCheck(blacklistStore: blacklistStore),
            LinkMismatchCheck(trustedLinkDomainStore: trustedLinkDomainStore),
            IPURLCheck(),
            SuspiciousTLDCheck(),
            BrandImpersonationCheck(campaignStore: campaignStore),
        ]
        self.init(checks: checks, allowlistStore: allowlistStore)
    }

    /// Analyzes an email and produces a verdict.
    public func analyze(email: ParsedEmail, imapUID: UInt32? = nil) -> Verdict {
        // Check allowlist first — skip analysis for trusted sender domains
        if let allowlist = allowlistStore {
            if let isAllowed = try? allowlist.isAllowed(domain: email.fromDomain), isAllowed {
                return Verdict(
                    messageId: email.messageId,
                    score: 0,
                    reasons: [],
                    actionTaken: Optional<ActionType>.none,
                    from: email.from,
                    subject: email.subject,
                    receivedDate: email.receivedDate,
                    imapUID: imapUID
                )
            }
        }

        // Parse HTML once and share across all checks
        let context = AnalysisContext.from(email: email)

        // Run all checks
        var allResults: [CheckResult] = []
        for check in checks {
            let results = check.analyze(email: email, context: context)
            allResults.append(contentsOf: results)
        }

        // Aggregate score
        let totalScore = allResults.reduce(0) { $0 + $1.points }

        return Verdict(
            messageId: email.messageId,
            score: totalScore,
            reasons: allResults,
            from: email.from,
            subject: email.subject,
            receivedDate: email.receivedDate,
            imapUID: imapUID
        )
    }
}
