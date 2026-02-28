import Foundation
import SQLite

/// Manages verdict CRUD operations in the shared database.
public final class VerdictStore: @unchecked Sendable {
    private let db: DatabaseManager

    public init(database: DatabaseManager) {
        self.db = database
    }

    /// Saves a verdict for a processed email.
    public func save(_ verdict: Verdict) throws {
        let encoder = JSONEncoder()
        let reasonsData = try encoder.encode(verdict.reasons)
        let reasonsJSON = String(data: reasonsData, encoding: .utf8) ?? "[]"

        try db.connection.run(
            DatabaseManager.verdicts.insert(or: .replace,
                DatabaseManager.verdictMessageId <- verdict.messageId,
                DatabaseManager.verdictScore <- verdict.score,
                DatabaseManager.verdictReasons <- reasonsJSON,
                DatabaseManager.verdictTimestamp <- verdict.timestamp.timeIntervalSince1970,
                DatabaseManager.verdictActionTaken <- verdict.actionTaken?.rawValue,
                DatabaseManager.verdictFrom <- verdict.from,
                DatabaseManager.verdictSubject <- verdict.subject,
                DatabaseManager.verdictReceivedDate <- verdict.receivedDate.timeIntervalSince1970,
                DatabaseManager.verdictImapUID <- verdict.imapUID.map { Int($0) }
            )
        )
    }

    /// Looks up a verdict by message ID.
    public func lookup(messageId: String) throws -> Verdict? {
        let query = DatabaseManager.verdicts.filter(DatabaseManager.verdictMessageId == messageId)
        guard let row = try db.connection.pluck(query) else { return nil }
        return try verdictFromRow(row)
    }

    /// Returns recent verdicts ordered by timestamp (most recent first).
    /// Excludes verdicts that have been acted on (marked safe, deleted, etc.).
    public func recentVerdicts(limit: Int = 20, minimumScore: Int = 3) throws -> [Verdict] {
        let query = DatabaseManager.verdicts
            .filter(DatabaseManager.verdictScore >= minimumScore)
            .filter(DatabaseManager.verdictActionTaken == nil)
            .order(DatabaseManager.verdictTimestamp.desc)
            .limit(limit)

        return try db.connection.prepare(query).map { try verdictFromRow($0) }
    }

    /// Updates the action taken for a verdict.
    public func updateAction(messageId: String, action: ActionType) throws {
        let target = DatabaseManager.verdicts.filter(DatabaseManager.verdictMessageId == messageId)
        try db.connection.run(target.update(
            DatabaseManager.verdictActionTaken <- action.rawValue
        ))
    }

    /// Marks all verdicts from a sender domain as safe.
    /// Uses SQL LIKE to match the domain in the sender field (e.g., "%@example.com>").
    @discardableResult
    public func markDomainSafe(domain: String) throws -> Int {
        let pattern = "%@\(domain)%"
        let target = DatabaseManager.verdicts
            .filter(DatabaseManager.verdictFrom.like(pattern))
            .filter(DatabaseManager.verdictActionTaken == nil)
        return try db.connection.run(target.update(
            DatabaseManager.verdictActionTaken <- ActionType.markedSafe.rawValue
        ))
    }

    /// Deletes verdicts older than the specified number of days.
    @discardableResult
    public func purgeOld(olderThanDays: Int = 30) throws -> Int {
        let cutoff = Date().addingTimeInterval(-Double(olderThanDays) * 86400)
        let old = DatabaseManager.verdicts.filter(DatabaseManager.verdictTimestamp < cutoff.timeIntervalSince1970)
        return try db.connection.run(old.delete())
    }

    // MARK: - Private

    /// Deletes a verdict by message ID.
    public func delete(messageId: String) throws {
        let target = DatabaseManager.verdicts.filter(DatabaseManager.verdictMessageId == messageId)
        try db.connection.run(target.delete())
    }

    private func verdictFromRow(_ row: Row) throws -> Verdict {
        let decoder = JSONDecoder()
        let reasonsJSON = row[DatabaseManager.verdictReasons]
        let reasons = try decoder.decode([CheckResult].self, from: Data(reasonsJSON.utf8))

        let actionStr = row[DatabaseManager.verdictActionTaken]
        let action = actionStr.flatMap { ActionType(rawValue: $0) }

        let receivedTs = row[DatabaseManager.verdictReceivedDate]

        return Verdict(
            messageId: row[DatabaseManager.verdictMessageId],
            score: row[DatabaseManager.verdictScore],
            reasons: reasons,
            timestamp: Date(timeIntervalSince1970: row[DatabaseManager.verdictTimestamp]),
            actionTaken: action,
            from: row[DatabaseManager.verdictFrom],
            subject: row[DatabaseManager.verdictSubject],
            receivedDate: receivedTs > 0 ? Date(timeIntervalSince1970: receivedTs) : Date(timeIntervalSince1970: row[DatabaseManager.verdictTimestamp]),
            imapUID: row[DatabaseManager.verdictImapUID].map { UInt32($0) }
        )
    }
}
