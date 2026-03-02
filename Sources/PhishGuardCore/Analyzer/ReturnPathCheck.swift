import Foundation

/// Check #2: Detects mismatch between Return-Path (envelope sender) and From domain.
/// Adds +3 points when domains don't match.
public struct ReturnPathCheck: PhishingCheck {
    public let name = "Return-Path Mismatch Check"

    public init() {}

    public func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        guard let returnPathDomain = email.returnPathDomain, !returnPathDomain.isEmpty else {
            return []
        }

        let fromDomain = email.fromDomain.lowercased()
        let rpDomain = returnPathDomain.lowercased()

        guard !fromDomain.isEmpty else { return [] }

        // Compare base domains (handles subdomains)
        let fromBase = DomainUtils.baseDomain(fromDomain)
        let rpBase = DomainUtils.baseDomain(rpDomain)

        if fromBase != rpBase {
            return [CheckResult(
                checkName: name,
                points: 3,
                reason: "Return-Path domain (\(rpDomain)) does not match From domain (\(fromDomain))"
            )]
        }

        return []
    }
}
