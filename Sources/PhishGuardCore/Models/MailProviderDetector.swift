import Foundation

/// Maps an email address domain to its corresponding mail provider.
public enum MailProviderDetector {

    /// Detects the mail provider from an email address.
    public static func detect(email: String) -> MailProvider {
        let domain = email.lowercased().components(separatedBy: "@").last ?? ""
        return detect(domain: domain)
    }

    /// Detects the mail provider from a domain string.
    public static func detect(domain: String) -> MailProvider {
        let d = domain.lowercased()
        switch d {
        case "gmail.com", "googlemail.com":
            return .gmail
        case "outlook.com", "hotmail.com", "live.com":
            return .outlook
        case "yahoo.com", "ymail.com":
            return .yahoo
        case "icloud.com", "me.com", "mac.com":
            return .icloud
        default:
            return .custom
        }
    }

    /// Detects the mail provider from an IMAP server hostname.
    public static func detect(server: String) -> MailProvider {
        let s = server.lowercased()
        if s.contains("gmail") || s.contains("google") {
            return .gmail
        } else if s.contains("outlook") || s.contains("office365") || s.contains("hotmail") {
            return .outlook
        } else if s.contains("yahoo") || s.contains("ymail") {
            return .yahoo
        } else if s.contains("icloud") || s.contains("mail.me.com") || s.contains("mac.com") {
            return .icloud
        }
        return .custom
    }
}
