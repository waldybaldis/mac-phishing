import Foundation

/// How an account authenticates with its IMAP server.
public enum AuthMethod: String, Codable, Sendable {
    case password
    case oauth2
}

/// Configuration for an IMAP mail account.
public struct AccountConfig: Sendable, Codable, Identifiable {
    public let id: UUID
    public var displayName: String
    public var imapServer: String
    public var imapPort: Int
    public var username: String
    public var useTLS: Bool
    public var authMethod: AuthMethod

    public init(
        id: UUID = UUID(),
        displayName: String,
        imapServer: String,
        imapPort: Int = 993,
        username: String,
        useTLS: Bool = true,
        authMethod: AuthMethod = .password
    ) {
        self.id = id
        self.displayName = displayName
        self.imapServer = imapServer
        self.imapPort = imapPort
        self.username = username
        self.useTLS = useTLS
        self.authMethod = authMethod
    }
}

/// Well-known IMAP server presets.
public enum MailProvider: String, CaseIterable, Sendable {
    case icloud = "iCloud"
    case outlook = "Outlook"
    case gmail = "Gmail"
    case custom = "Custom"

    public var defaultServer: String {
        switch self {
        case .icloud: return "imap.mail.me.com"
        case .outlook: return "outlook.office365.com"
        case .gmail: return "imap.gmail.com"
        case .custom: return ""
        }
    }

    public var defaultPort: Int { 993 }

    /// The authentication method appropriate for this provider.
    public var authMethod: AuthMethod {
        switch self {
        case .gmail, .outlook: return .oauth2
        case .icloud, .custom: return .password
        }
    }
}
