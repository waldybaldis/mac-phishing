import Foundation

/// Shared domain utility functions used by multiple phishing checks.
public enum DomainUtils {
    /// Known two-part country-code TLDs.
    private static let twoPartTLDs: Set<String> = [
        "co.uk", "com.au", "co.nz", "co.za", "com.br", "co.jp", "co.in"
    ]

    /// Extracts the base (registrable) domain from a full domain.
    /// Simple heuristic: takes last two components (or three for known ccTLDs).
    public static func baseDomain(_ domain: String) -> String {
        let parts = domain.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return domain }

        if parts.count >= 3 {
            let lastTwo = "\(parts[parts.count - 2]).\(parts[parts.count - 1])"
            if twoPartTLDs.contains(lastTwo) {
                return parts.suffix(3).joined(separator: ".")
            }
        }

        return parts.suffix(2).joined(separator: ".")
    }
}
