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
        let fromBase = baseDomain(fromDomain)
        let rpBase = baseDomain(rpDomain)

        if fromBase != rpBase {
            return [CheckResult(
                checkName: name,
                points: 3,
                reason: "Return-Path domain (\(rpDomain)) does not match From domain (\(fromDomain))"
            )]
        }

        return []
    }

    /// Extracts the base domain (registrable domain) from a full domain.
    /// Simple heuristic: takes last two components (or three for known ccTLDs).
    private func baseDomain(_ domain: String) -> String {
        let parts = domain.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return domain }

        // Common two-part TLDs
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
