import Foundation

/// Extracts brand names from Safeonweb RSS article titles.
///
/// Supports Dutch and English patterns like:
/// - "Phishing in naam van Argenta"
/// - "Phishing in naam van de Watergroep en Farys"
/// - "Valse sms namens itsme"
/// - "Phishing in the name of NMBS"
public enum SafeonwebBrandExtractor {

    // MARK: - Pre-compiled Regex Patterns

    private static let brandPatterns: [NSRegularExpression] = [
        // Dutch: "in naam van (de|het)? X"
        try! NSRegularExpression(pattern: #"in naam van\s+(?:de\s+|het\s+)?(.+)"#, options: .caseInsensitive),
        // Dutch: "namens X"
        try! NSRegularExpression(pattern: #"namens\s+(?:de\s+|het\s+)?(.+)"#, options: .caseInsensitive),
        // English: "in the name of (the)? X"
        try! NSRegularExpression(pattern: #"in the name of\s+(?:the\s+)?(.+)"#, options: .caseInsensitive),
        // Dutch: "die van X lijken te komen" / "die van X komen"
        try! NSRegularExpression(pattern: #"(?:die\s+)?van\s+(?:de\s+|het\s+)?(.+?)\s+(?:lijken\s+te\s+komen|te\s+komen|komen)"#, options: .caseInsensitive),
        // English: "appear to come from (the)? X"
        try! NSRegularExpression(pattern: #"(?:appear|seem)\s+to\s+come\s+from\s+(?:the\s+)?(.+)"#, options: .caseInsensitive),
    ]

    private static let stopPatterns: [NSRegularExpression] = [
        try! NSRegularExpression(pattern: #"\s+(?:are|is|was|were|has|have|had)\s+"#, options: .caseInsensitive),
        try! NSRegularExpression(pattern: #"\s+(?:worden|wordt|zijn|gaan|komt)\s+"#, options: .caseInsensitive),
        try! NSRegularExpression(pattern: #"\s*[:\-–—]\s+"#, options: .caseInsensitive),
    ]

    private static let splitRegex = try! NSRegularExpression(pattern: #"\s+(?:en|and)\s+"#, options: .caseInsensitive)

    // MARK: - Public API

    /// Extracts brand names from an article title.
    /// Returns an array of lowercased brand names.
    public static func extractBrands(from title: String) -> [String] {
        for regex in brandPatterns {
            let range = NSRange(title.startIndex..., in: title)
            guard let match = regex.firstMatch(in: title, range: range),
                  match.numberOfRanges > 1,
                  let brandRange = Range(match.range(at: 1), in: title) else { continue }

            var rawBrands = String(title[brandRange])

            // Truncate at sentence continuations that follow the brand name
            for stopRegex in stopPatterns {
                let searchRange = NSRange(rawBrands.startIndex..., in: rawBrands)
                if let stopMatch = stopRegex.firstMatch(in: rawBrands, range: searchRange) {
                    rawBrands = String(rawBrands[..<rawBrands.index(rawBrands.startIndex, offsetBy: stopMatch.range.location)])
                }
            }

            rawBrands = rawBrands
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: .punctuationCharacters)

            // Split multi-brand titles on " en " / " and "
            let brandString = rawBrands as NSString
            let splits = splitRegex.matches(in: rawBrands, range: NSRange(location: 0, length: brandString.length))
            let parts: [String]
            if splits.isEmpty {
                parts = [rawBrands]
            } else {
                var result: [String] = []
                var lastEnd = 0
                for m in splits {
                    result.append(brandString.substring(with: NSRange(location: lastEnd, length: m.range.location - lastEnd)))
                    lastEnd = m.range.location + m.range.length
                }
                result.append(brandString.substring(from: lastEnd))
                parts = result
            }

            return parts.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                .filter { !$0.isEmpty }
        }

        return []
    }
}
