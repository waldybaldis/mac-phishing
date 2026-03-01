import Foundation
#if canImport(MailKit)
import MailKit
import SQLite
import os.log

private let logger = Logger(subsystem: "com.phishguard.mailextension", category: "MessageAction")

/// Mail Extension handler that applies visual labels to emails based on PhishGuard verdicts.
///
/// This is the thin client that reads from the shared SQLite database.
/// All heavy analysis is done by the menu bar app — the extension only reads verdicts
/// and falls back to a lightweight Authentication-Results check if no verdict exists yet.
final class MessageActionHandler: NSObject, MEMessageActionHandler {

    /// Headers the extension needs Mail to provide.
    var requiredHeaders: [String] {
        ["Message-ID", "Authentication-Results"]
    }

    /// Decides what action to take for a message.
    func decideAction(for message: MEMessage, completionHandler: @escaping @Sendable (MEMessageActionDecision?) -> Void) {
        logger.info("decideAction called for subject: \(message.subject ?? "nil", privacy: .public)")
        logger.info("  headers: \(String(describing: message.headers), privacy: .public)")

        guard let messageId = extractMessageId(from: message) else {
            logger.warning("  No Message-ID found — skipping")
            completionHandler(nil)
            return
        }

        logger.info("  Message-ID: \(messageId, privacy: .public)")

        // 1. Look up verdict in shared SQLite
        if let verdict = lookupVerdict(messageId: messageId) {
            logger.info("  Verdict found: score=\(verdict.score)")
            let action = actionForVerdict(verdict)
            logger.info("  Action: \(String(describing: action), privacy: .public)")
            completionHandler(action)
            return
        }

        logger.info("  No verdict in database")

        // 2. Fallback: lightweight local check on Authentication-Results
        if let authResults = message.headers?["Authentication-Results"] as? String {
            logger.info("  Auth-Results: \(authResults, privacy: .public)")
            let fallbackAction = fallbackAuthCheck(authResults: authResults)
            logger.info("  Fallback action: \(String(describing: fallbackAction), privacy: .public)")
            completionHandler(fallbackAction)
            return
        }

        // 3. No verdict, no auth header — take no action
        logger.info("  No auth header either — no action")
        completionHandler(nil)
    }

    // MARK: - Verdict Lookup

    private func lookupVerdict(messageId: String) -> StoredVerdict? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.phishguard"
        ) else {
            logger.error("  App Group container not available")
            return nil
        }

        let dbPath = containerURL.appendingPathComponent("verdicts.sqlite").path
        logger.info("  DB path: \(dbPath, privacy: .public)")

        guard let db = try? Connection(dbPath, readonly: true) else {
            logger.error("  Failed to open database")
            return nil
        }

        let verdicts = Table("verdicts")
        let msgId = SQLite.Expression<String>("message_id")
        let score = SQLite.Expression<Int>("score")

        // Try exact match first, then try with/without angle brackets
        let candidates = [
            messageId,
            messageId.hasPrefix("<") ? String(messageId.dropFirst().dropLast()) : "<\(messageId)>",
        ]

        for candidate in candidates {
            let query = verdicts.filter(msgId == candidate)
            if let row = try? db.pluck(query) {
                logger.info("  Found verdict for: \(candidate, privacy: .public)")
                return StoredVerdict(messageId: candidate, score: row[score])
            }
        }

        logger.info("  No verdict for any ID variant")
        return nil
    }

    // MARK: - Action Mapping

    private func actionForVerdict(_ verdict: StoredVerdict) -> MEMessageActionDecision? {
        switch verdict.score {
        case 6...:
            // High threat — move to junk
            return .action(.moveToJunk)
        case 3...5:
            // Suspicious — flag with orange color
            return .action(.flag(.orange))
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
            return .action(.flag(.red))
        } else if failures.count == 1 {
            // Single auth failure — flag orange
            return .action(.flag(.orange))
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
final class PhishGuardMailExtension: NSObject, MEExtension {
    func handlerForMessageActions() -> MEMessageActionHandler {
        return MessageActionHandler()
    }
}
#else
// Stub for non-MailKit environments (e.g., SPM builds without macOS SDK)
// This file compiles only when building with the full macOS SDK in Xcode.
#endif
