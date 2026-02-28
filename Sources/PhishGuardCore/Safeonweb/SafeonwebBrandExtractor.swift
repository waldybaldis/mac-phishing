import Foundation

/// Extracts brand names from Safeonweb RSS article titles.
///
/// Supports Dutch and English patterns like:
/// - "Phishing in naam van Argenta"
/// - "Phishing in naam van de Watergroep en Farys"
/// - "Valse sms namens itsme"
/// - "Phishing in the name of NMBS"
public enum SafeonwebBrandExtractor {

    /// Extracts brand names from an article title.
    /// Returns an array of lowercased brand names.
    public static func extractBrands(from title: String) -> [String] {
        let patterns: [String] = [
            // Dutch: "in naam van (de|het)? X"
            #"in naam van\s+(?:de\s+|het\s+)?(.+)"#,
            // Dutch: "namens X"
            #"namens\s+(?:de\s+|het\s+)?(.+)"#,
            // English: "in the name of (the)? X"
            #"in the name of\s+(?:the\s+)?(.+)"#,
            // Dutch: "die van X lijken te komen" / "die van X komen"
            #"(?:die\s+)?van\s+(?:de\s+|het\s+)?(.+?)\s+(?:lijken\s+te\s+komen|te\s+komen|komen)"#,
            // English: "appear to come from (the)? X"
            #"(?:appear|seem)\s+to\s+come\s+from\s+(?:the\s+)?(.+)"#,
        ]

        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { continue }
            let range = NSRange(title.startIndex..., in: title)
            guard let match = regex.firstMatch(in: title, range: range),
                  match.numberOfRanges > 1,
                  let brandRange = Range(match.range(at: 1), in: title) else { continue }

            var rawBrands = String(title[brandRange])

            // Truncate at sentence continuations that follow the brand name
            // e.g., "mypension are circulating again" → "mypension"
            let stopPatterns = [
                #"\s+(?:are|is|was|were|has|have|had)\s+"#,   // English verb continuations
                #"\s+(?:worden|wordt|zijn|gaan|komt)\s+"#,    // Dutch verb continuations
                #"\s*[:\-–—]\s+"#,                            // Punctuation separators
            ]
            for stop in stopPatterns {
                if let stopRegex = try? NSRegularExpression(pattern: stop, options: .caseInsensitive) {
                    let searchRange = NSRange(rawBrands.startIndex..., in: rawBrands)
                    if let stopMatch = stopRegex.firstMatch(in: rawBrands, range: searchRange) {
                        rawBrands = String(rawBrands[..<rawBrands.index(rawBrands.startIndex, offsetBy: stopMatch.range.location)])
                    }
                }
            }

            rawBrands = rawBrands
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: .punctuationCharacters)

            // Split multi-brand titles on " en " / " and "
            let splitRegex = try? NSRegularExpression(pattern: #"\s+(?:en|and)\s+"#, options: .caseInsensitive)
            let brandString = rawBrands as NSString
            let parts: [String]
            if let splitRegex = splitRegex {
                let splits = splitRegex.matches(in: rawBrands, range: NSRange(location: 0, length: brandString.length))
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
            } else {
                parts = [rawBrands]
            }

            return parts.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                .filter { !$0.isEmpty }
        }

        return []
    }
}
