import Foundation

/// Central threshold constants for phishing score classification.
/// All UI and engine code should reference these instead of hardcoding score boundaries.
public enum PhishGuardThresholds {
    /// Minimum score to classify an email as suspicious (inclusive).
    public static let suspicious = 3
    /// Minimum score to classify an email as likely phishing (inclusive).
    public static let phishing = 6
}
