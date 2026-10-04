import Foundation

/// The main phishing analysis engine. Runs the local checks against an email and, when
/// warranted, asks Jev for signals the local checks can't see. Produces a scored verdict.
/// @unchecked Sendable: all state (checks array, stores, jev) is immutable after init.
public final class PhishingAnalyzer: @unchecked Sendable {
    private let checks: [PhishingCheck]
    private let allowlistStore: AllowlistStore?
    private let jev: JevSignalCheck?

    /// Creates an analyzer with the specified checks.
    /// - Parameters:
    ///   - checks: The local phishing checks to run.
    ///   - allowlistStore: Optional allowlist store to skip analysis for trusted domains.
    ///   - jev: Optional AI signal check, consulted only by `evaluate`.
    public init(checks: [PhishingCheck], allowlistStore: AllowlistStore? = nil, jev: JevSignalCheck? = nil) {
        self.checks = checks
        self.allowlistStore = allowlistStore
        self.jev = jev
    }

    /// Creates an analyzer with all default Tier 1 checks.
    /// - Parameters:
    ///   - blacklistStore: The blacklist store for domain lookups.
    ///   - allowlistStore: Optional allowlist store for trusted domains.
    ///   - trustedLinkDomainStore: Optional store for user-trusted link domains.
    ///   - campaignStore: Optional Safeonweb campaign store for active phishing campaign detection.
    ///   - jev: Optional AI signal check, consulted only by `evaluate`.
    public convenience init(blacklistStore: BlacklistStore, allowlistStore: AllowlistStore? = nil, trustedLinkDomainStore: TrustedLinkDomainStore? = nil, campaignStore: SafeonwebCampaignStore? = nil, userBrandStore: UserBrandStore? = nil, userBlocklistStore: UserBlocklistStore? = nil, jev: JevSignalCheck? = nil) {
        var checks: [PhishingCheck] = [
            AuthHeaderCheck(),
            ReturnPathCheck(),
            BlacklistCheck(blacklistStore: blacklistStore),
            LinkMismatchCheck(trustedLinkDomainStore: trustedLinkDomainStore),
            IPURLCheck(),
            SuspiciousTLDCheck(),
            BrandImpersonationCheck(campaignStore: campaignStore, userBrandStore: userBrandStore),
        ]
        if let userBlocklistStore = userBlocklistStore {
            checks.append(UserBlocklistCheck(userBlocklistStore: userBlocklistStore))
        }
        self.init(checks: checks, allowlistStore: allowlistStore, jev: jev)
    }

    /// Analyzes an email with the local checks only (no network).
    public func analyze(email: ParsedEmail, imapUID: UInt32? = nil, accountId: String? = nil) -> Verdict {
        if isAllowlisted(email) {
            return makeVerdict(email: email, reasons: [], imapUID: imapUID, accountId: accountId)
        }
        let results = runLocalChecks(email: email, context: AnalysisContext.from(email: email))
        return makeVerdict(email: email, reasons: results, imapUID: imapUID, accountId: accountId)
    }

    /// Analyzes an email with the local checks, then asks Jev when it could change the outcome.
    /// Never fails: if Jev is off, not needed, over budget or unreachable, this equals `analyze`.
    public func evaluate(email: ParsedEmail, imapUID: UInt32? = nil, accountId: String? = nil) async -> Verdict {
        guard let jev = jev, !isAllowlisted(email) else {
            return analyze(email: email, imapUID: imapUID, accountId: accountId)
        }

        let context = AnalysisContext.from(email: email)
        var results = runLocalChecks(email: email, context: context)
        let localScore = results.reduce(0) { $0 + $1.points }

        if let signals = await jev.signals(for: email, context: context, localScore: localScore) {
            // Jev's impersonation signal supersedes the keyword-list brand check.
            results.removeAll { $0.checkName == BrandImpersonationCheck.checkName }
            results.append(contentsOf: signals)
        }
        return makeVerdict(email: email, reasons: results, imapUID: imapUID, accountId: accountId)
    }

    /// Evaluates a batch (e.g. a mailbox scan) with a few Jev calls in flight at once,
    /// so a scan isn't serialized on network round-trips. Verdicts keep the input order.
    public func evaluate(_ items: [(email: ParsedEmail, imapUID: UInt32?)], accountId: String? = nil, maxConcurrent: Int = 4) async -> [Verdict] {
        var verdicts = [Verdict?](repeating: nil, count: items.count)
        await withTaskGroup(of: (Int, Verdict).self) { group in
            for (index, item) in items.enumerated() {
                if index >= maxConcurrent, let finished = await group.next() {
                    verdicts[finished.0] = finished.1
                }
                group.addTask {
                    (index, await self.evaluate(email: item.email, imapUID: item.imapUID, accountId: accountId))
                }
            }
            for await finished in group {
                verdicts[finished.0] = finished.1
            }
        }
        return verdicts.compactMap { $0 }
    }

    // MARK: - Private

    private func isAllowlisted(_ email: ParsedEmail) -> Bool {
        guard let allowlist = allowlistStore else { return false }
        return (try? allowlist.isAllowed(domain: email.fromDomain)) ?? false
    }

    private func runLocalChecks(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        checks.flatMap { $0.analyze(email: email, context: context) }
    }

    private func makeVerdict(email: ParsedEmail, reasons: [CheckResult], imapUID: UInt32?, accountId: String?) -> Verdict {
        Verdict(
            messageId: email.messageId,
            score: reasons.reduce(0) { $0 + $1.points },
            reasons: reasons,
            from: email.from,
            subject: email.subject,
            receivedDate: email.receivedDate,
            imapUID: imapUID,
            accountId: accountId
        )
    }
}
