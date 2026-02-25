import Foundation
#if canImport(MailKit)
import MailKit

/// Mail Extension handler that applies visual labels to emails based on PhishGuard verdicts.
///
/// This is the thin client that reads from the shared SQLite database.
/// All heavy analysis is done by the menu bar app — the extension only reads verdicts
/// and falls back to a lightweight Authentication-Results check if no verdict exists yet.
final class MessageActionHandler: MEMessageActionHandler {

    /// Decides what action to take for a message.
    override func decideAction(for message: MEMessage, completionHandler: @escaping (MEMessageActionDecision?) -> Void) {
        guard let messageId = extractMessageId(from: message) else {
            completionHandler(nil)
            return
        }

        // 1. Look up verdict in shared SQLite
        if let verdict = lookupVerdict(messageId: messageId) {
            let action = actionForVerdict(verdict)
            completionHandler(action)
            return
        }

        // 2. Fallback: lightweight local check on Authentication-Results
        if let authResults = message.headers?["Authentication-Results"] as? String {
            let fallbackAction = fallbackAuthCheck(authResults: authResults)
            completionHandler(fallbackAction)
            return
        }

        // 3. No verdict, no auth header — take no action
        completionHandler(nil)
    }

    // MARK: - Verdict Lookup

    private func lookupVerdict(messageId: String) -> StoredVerdict? {
        // Open shared SQLite from App Group container
        // In production:
        // guard let containerURL = FileManager.default.containerURL(
        //     forSecurityApplicationGroupIdentifier: "group.com.phishguard"
        // ) else { return nil }
        //
        // let dbPath = containerURL.appendingPathComponent("verdicts.sqlite").path
        // guard let db = try? Connection(dbPath) else { return nil }
        //
        // let verdicts = Table("verdicts")
        // let msgId = Expression<String>("message_id")
        // let score = Expression<Int>("score")
        // let query = verdicts.filter(msgId == messageId)
        //
        // guard let row = try? db.pluck(query) else { return nil }
        // return StoredVerdict(messageId: messageId, score: row[score])

        return nil
    }

    // MARK: - Action Mapping

    private func actionForVerdict(_ verdict: StoredVerdict) -> MEMessageActionDecision? {
        switch verdict.score {
        case 6...:
            // High threat — move to junk
            return MEMessageActionDecision(action: .moveToJunk)
        case 3...5:
            // Suspicious — flag with orange color
            return MEMessageActionDecision(action: .setFlag(.orange))
        default:
            return nil
        }
    }

    // MARK: - Fallback Auth Check

    /// Lightweight fallback: only parse Authentication-Results when no verdict exists.
    /// Checks for SPF/DKIM/DMARC failures and flags accordingly.
    private func fallbackAuthCheck(authResults: String) -> MEMessageActionDecision? {
        let lowered = authResults.lowercased()

        let failurePatterns = [
            "spf=fail",
            "dkim=fail",
            "dmarc=fail",
        ]

        let failures = failurePatterns.filter { lowered.contains($0) }

        if failures.count >= 2 {
            // Multiple auth failures — flag red
            return MEMessageActionDecision(action: .setFlag(.red))
        } else if failures.count == 1 {
            // Single auth failure — flag orange
            return MEMessageActionDecision(action: .setFlag(.orange))
        }

        return nil
    }

    // MARK: - Helpers

    private func extractMessageId(from message: MEMessage) -> String? {
        // MailKit provides headers as a dictionary
        return message.headers?["Message-ID"] as? String
    }
}

/// Lightweight struct for verdict data read from shared storage.
struct StoredVerdict {
    let messageId: String
    let score: Int
}

// MARK: - Extension Entry Point

/// The principal class for the Mail Extension bundle.
final class PhishGuardMailExtension: MEExtension {
    func handler(for session: MEExtensionSession) -> MEExtensionHandler {
        return MessageActionHandler()
    }
}
#else
// Stub for non-MailKit environments (e.g., SPM builds without macOS SDK)
// This file compiles only when building with the full macOS SDK in Xcode.
#endif
