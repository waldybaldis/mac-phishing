import Foundation

/// An email account discovered from Mail.app via AppleScript.
struct DiscoveredAccount: Identifiable, Hashable {
    let id: String // account name as unique key
    let name: String
    let email: String
    let server: String
    let port: Int
    let usesSSL: Bool

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    static func == (lhs: DiscoveredAccount, rhs: DiscoveredAccount) -> Bool {
        lhs.id == rhs.id
    }
}

/// Discovers IMAP accounts configured in Mail.app using AppleScript.
enum MailAccountDiscovery {

    enum DiscoveryError: LocalizedError {
        case scriptFailed(String)
        case permissionDenied
        case mailNotAvailable

        var errorDescription: String? {
            switch self {
            case .scriptFailed(let msg): return "AppleScript error: \(msg)"
            case .permissionDenied: return "Permission denied. Allow PhishGuard to access Mail in System Settings > Privacy & Security > Automation."
            case .mailNotAvailable: return "Mail.app is not available."
            }
        }
    }

    /// Queries Mail.app for all configured IMAP accounts.
    static func discover() async throws -> [DiscoveredAccount] {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let source = """
                set output to ""
                tell application "Mail"
                    repeat with acct in every imap account
                        set acctName to name of acct
                        set serverHost to server name of acct
                        set portNum to port of acct
                        set sslEnabled to uses ssl of acct
                        set emailAddrs to email addresses of acct
                        set firstEmail to ""
                        if (count of emailAddrs) > 0 then
                            set firstEmail to item 1 of emailAddrs
                        end if
                        set output to output & acctName & "||" & serverHost & "||" & (portNum as string) & "||" & firstEmail & "||" & (sslEnabled as string) & linefeed
                    end repeat
                end tell
                return output
                """

                var error: NSDictionary?
                guard let script = NSAppleScript(source: source) else {
                    continuation.resume(throwing: DiscoveryError.mailNotAvailable)
                    return
                }

                let result = script.executeAndReturnError(&error)

                if let error = error {
                    let errorNum = error[NSAppleScript.errorNumber] as? Int ?? 0
                    let errorMsg = error[NSAppleScript.errorMessage] as? String ?? "Unknown error"
                    if errorNum == -1743 || errorNum == -1744 {
                        continuation.resume(throwing: DiscoveryError.permissionDenied)
                    } else {
                        continuation.resume(throwing: DiscoveryError.scriptFailed(errorMsg))
                    }
                    return
                }

                guard let output = result.stringValue else {
                    continuation.resume(returning: [])
                    return
                }

                let accounts = output
                    .split(separator: "\n", omittingEmptySubsequences: true)
                    .compactMap { line -> DiscoveredAccount? in
                        let parts = line.components(separatedBy: "||")
                        guard parts.count >= 5 else { return nil }
                        let name = parts[0].trimmingCharacters(in: .whitespaces)
                        let server = parts[1].trimmingCharacters(in: .whitespaces)
                        let port = Int(parts[2].trimmingCharacters(in: .whitespaces)) ?? 993
                        let email = parts[3].trimmingCharacters(in: .whitespaces)
                        let ssl = parts[4].trimmingCharacters(in: .whitespaces).lowercased() == "true"
                        guard !name.isEmpty, !server.isEmpty else { return nil }
                        return DiscoveredAccount(
                            id: name,
                            name: name,
                            email: email,
                            server: server,
                            port: port,
                            usesSSL: ssl
                        )
                    }

                continuation.resume(returning: accounts)
            }
        }
    }
}
