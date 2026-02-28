import Foundation

/// The result of phishing analysis on a single email.
public struct Verdict: Sendable, Codable {
    public let messageId: String
    public let score: Int
    public let reasons: [CheckResult]
    public let timestamp: Date
    public var actionTaken: ActionType?

    // Email metadata for display
    public let from: String
    public let subject: String
    public let receivedDate: Date
    public let imapUID: UInt32?

    public var threatLevel: ThreatLevel {
        ThreatLevel(score: score)
    }

    /// Display name extracted from the From header (e.g. "FedEx Support" from "FedEx Support <foo@bar>").
    public var senderName: String {
        let trimmed = from.trimmingCharacters(in: .whitespaces)
        if let angleBracket = trimmed.firstIndex(of: "<") {
            let name = trimmed[trimmed.startIndex..<angleBracket].trimmingCharacters(in: .whitespaces)
            // Strip surrounding quotes
            let unquoted = name.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            return unquoted.isEmpty ? senderEmail : unquoted
        }
        return trimmed
    }

    /// Email address extracted from the From header.
    public var senderEmail: String {
        let trimmed = from.trimmingCharacters(in: .whitespaces)
        if let start = trimmed.firstIndex(of: "<"),
           let end = trimmed.firstIndex(of: ">") {
            return String(trimmed[trimmed.index(after: start)..<end])
        }
        return trimmed
    }

    public init(
        messageId: String,
        score: Int,
        reasons: [CheckResult],
        timestamp: Date = Date(),
        actionTaken: ActionType? = nil,
        from: String = "",
        subject: String = "",
        receivedDate: Date = Date(),
        imapUID: UInt32? = nil
    ) {
        self.messageId = messageId
        self.score = score
        self.reasons = reasons
        self.timestamp = timestamp
        self.actionTaken = actionTaken
        self.from = from
        self.subject = subject
        self.receivedDate = receivedDate
        self.imapUID = imapUID
    }
}

/// Threat level based on aggregate score.
public enum ThreatLevel: String, Sendable, Codable {
    case clean       // 0-2
    case suspicious  // 3-5
    case phishing    // 6+

    public init(score: Int) {
        switch score {
        case 0...2: self = .clean
        case 3...5: self = .suspicious
        default:    self = .phishing
        }
    }

    public var displayName: String {
        switch self {
        case .clean: return "Clean"
        case .suspicious: return "Suspicious"
        case .phishing: return "Likely Phishing"
        }
    }
}

/// The action taken on a suspicious email.
public enum ActionType: String, Sendable, Codable {
    case none
    case flagged
    case movedToJunk
    case markedSafe
}

/// Result from a single phishing check.
public struct CheckResult: Sendable, Codable {
    public let checkName: String
    public let points: Int
    public let reason: String

    public init(checkName: String, points: Int, reason: String) {
        self.checkName = checkName
        self.points = points
        self.reason = reason
    }
}
