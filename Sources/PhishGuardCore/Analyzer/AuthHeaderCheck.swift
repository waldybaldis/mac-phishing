import Foundation

/// Check #1: Detects SPF, DKIM, and DMARC failures from the Authentication-Results header.
/// Each failure adds +3 points.
public struct AuthHeaderCheck: PhishingCheck {
    public let name = "Authentication Header Check"

    private static let spfRegex = try! NSRegularExpression(
        pattern: "\\bspf\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)", options: [])
    private static let dkimRegex = try! NSRegularExpression(
        pattern: "\\bdkim\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)", options: [])
    private static let dmarcRegex = try! NSRegularExpression(
        pattern: "\\bdmarc\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)", options: [])

    private static let protocols: [(regex: NSRegularExpression, display: String)] = [
        (spfRegex, "SPF"),
        (dkimRegex, "DKIM"),
        (dmarcRegex, "DMARC"),
    ]

    public init() {}

    public func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        guard let authResults = email.authenticationResults, !authResults.isEmpty else {
            return []
        }

        var results: [CheckResult] = []
        let lowered = authResults.lowercased()
        let range = NSRange(lowered.startIndex..., in: lowered)

        for proto in Self.protocols {
            guard let match = proto.regex.firstMatch(in: lowered, options: [], range: range),
                  let statusRange = Range(match.range(at: 1), in: lowered) else { continue }

            let status = String(lowered[statusRange])
            switch status {
            case "fail", "softfail":
                results.append(CheckResult(
                    checkName: name,
                    points: 3,
                    reason: "\(proto.display) \(status) — sender authentication failed"
                ))
            case "none":
                results.append(CheckResult(
                    checkName: name,
                    points: 3,
                    reason: "\(proto.display) record not found (none) — no sender authentication"
                ))
            case "temperror", "permerror":
                results.append(CheckResult(
                    checkName: name,
                    points: 2,
                    reason: "\(proto.display) \(status) — authentication could not be verified"
                ))
            default:
                break // "pass" or "neutral" — no points
            }
        }

        return results
    }
}
