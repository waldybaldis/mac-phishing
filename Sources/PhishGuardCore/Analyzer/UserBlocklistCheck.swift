import Foundation

/// Checks the sender domain against the user's personal blocklist.
/// Adds +6 points if the sender domain is blocked by the user.
public struct UserBlocklistCheck: PhishingCheck {
    public let name = "User Blocked Sender Check"

    private let userBlocklistStore: UserBlocklistStore

    public init(userBlocklistStore: UserBlocklistStore) {
        self.userBlocklistStore = userBlocklistStore
    }

    public func analyze(email: ParsedEmail, context: AnalysisContext) -> [CheckResult] {
        guard !email.fromDomain.isEmpty else { return [] }

        let isBlocked = (try? userBlocklistStore.isBlocked(domain: email.fromDomain)) ?? false
        guard isBlocked else { return [] }

        return [CheckResult(
            checkName: name,
            points: 6,
            reason: "Sender domain \(email.fromDomain) is on your block list"
        )]
    }
}
