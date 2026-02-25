import Foundation

/// Configuration for an IMAP mail account.
public struct AccountConfig: Sendable, Codable, Identifiable {
    public let id: UUID
    public var displayName: String
    public var imapServer: String
    public var imapPort: Int
    public var username: String
    public var useTLS: Bool

    public init(
        id: UUID = UUID(),
        displayName: String,
        imapServer: String,
        imapPort: Int = 993,
        username: String,
        useTLS: Bool = true
    ) {
        self.id = id
        self.displayName = displayName
        self.imapServer = imapServer
        self.imapPort = imapPort
        self.username = username
        self.useTLS = useTLS
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
}
