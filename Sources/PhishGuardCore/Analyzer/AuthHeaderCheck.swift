import Foundation

/// Check #1: Detects SPF, DKIM, and DMARC failures from the Authentication-Results header.
/// Each failure adds +3 points.
public struct AuthHeaderCheck: PhishingCheck {
    public let name = "Authentication Header Check"

    public init() {}

    public func analyze(email: ParsedEmail) -> [CheckResult] {
        guard let authResults = email.authenticationResults, !authResults.isEmpty else {
            return []
        }

        var results: [CheckResult] = []
        let lowered = authResults.lowercased()

        // Parse individual protocol results
        let protocols: [(protocol: String, display: String)] = [
            ("spf", "SPF"),
            ("dkim", "DKIM"),
            ("dmarc", "DMARC"),
        ]

        for proto in protocols {
            if let status = extractStatus(for: proto.protocol, in: lowered) {
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
        }

        return results
    }

    /// Extracts the result status for a given protocol from Authentication-Results.
    /// Matches patterns like "spf=fail", "dkim=pass", "dmarc=fail".
    private func extractStatus(for protocol: String, in header: String) -> String? {
        // Pattern: protocol=status (possibly with surrounding whitespace or semicolons)
        let pattern = "\\b\(`protocol`)\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return nil }

        let range = NSRange(header.startIndex..., in: header)
        guard let match = regex.firstMatch(in: header, options: [], range: range) else { return nil }

        guard let statusRange = Range(match.range(at: 1), in: header) else { return nil }
        return String(header[statusRange])
    }
}
