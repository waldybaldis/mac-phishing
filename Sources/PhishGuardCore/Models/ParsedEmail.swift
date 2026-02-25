import Foundation

/// Represents a parsed email with all fields needed for phishing analysis.
public struct ParsedEmail: Sendable {
    public let messageId: String
    public let from: String
    public let fromDomain: String
    public let returnPath: String?
    public let returnPathDomain: String?
    public let authenticationResults: String?
    public let subject: String
    public let htmlBody: String?
    public let textBody: String?
    public let receivedDate: Date
    public let headers: [String: String]

    public init(
        messageId: String,
        from: String,
        returnPath: String?,
        authenticationResults: String?,
        subject: String,
        htmlBody: String?,
        textBody: String?,
        receivedDate: Date,
        headers: [String: String] = [:]
    ) {
        self.messageId = messageId
        self.from = from
        self.fromDomain = Self.extractDomain(from: from) ?? ""
        self.returnPath = returnPath
        self.returnPathDomain = returnPath.flatMap { Self.extractDomain(from: $0) }
        self.authenticationResults = authenticationResults
        self.subject = subject
        self.htmlBody = htmlBody
        self.textBody = textBody
        self.receivedDate = receivedDate
        self.headers = headers
    }

    /// Extracts the domain part from an email address string.
    /// Handles formats like "Name <user@domain.com>" and "user@domain.com".
    public static func extractDomain(from emailString: String) -> String? {
        let trimmed = emailString.trimmingCharacters(in: .whitespaces)

        // Handle "Name <email@domain.com>" format
        if let angleBracketStart = trimmed.lastIndex(of: "<"),
           let angleBracketEnd = trimmed.lastIndex(of: ">") {
            let email = String(trimmed[trimmed.index(after: angleBracketStart)..<angleBracketEnd])
            return extractDomainFromAddress(email)
        }

        return extractDomainFromAddress(trimmed)
    }

    private static func extractDomainFromAddress(_ address: String) -> String? {
        guard let atIndex = address.lastIndex(of: "@") else { return nil }
        let domain = String(address[address.index(after: atIndex)...])
            .trimmingCharacters(in: .whitespaces)
            .lowercased()
        return domain.isEmpty ? nil : domain
    }
}
