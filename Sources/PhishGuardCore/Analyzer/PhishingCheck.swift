import Foundation

/// Protocol for individual phishing detection checks.
public protocol PhishingCheck: Sendable {
    /// A human-readable name for this check.
    var name: String { get }

    /// Analyzes an email and returns check results (empty if check passes).
    func analyze(email: ParsedEmail) -> [CheckResult]
}
