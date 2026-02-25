import Foundation

/// The result of phishing analysis on a single email.
public struct Verdict: Sendable, Codable {
    public let messageId: String
    public let score: Int
    public let reasons: [CheckResult]
    public let timestamp: Date
    public var actionTaken: ActionType?

    public var threatLevel: ThreatLevel {
        ThreatLevel(score: score)
    }

    public init(
        messageId: String,
        score: Int,
        reasons: [CheckResult],
        timestamp: Date = Date(),
        actionTaken: ActionType? = nil
    ) {
        self.messageId = messageId
        self.score = score
        self.reasons = reasons
        self.timestamp = timestamp
        self.actionTaken = actionTaken
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
