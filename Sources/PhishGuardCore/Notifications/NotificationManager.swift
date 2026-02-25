import Foundation
#if canImport(UserNotifications)
import UserNotifications

/// Manages macOS notifications for phishing alerts.
public final class NotificationManager: NSObject, @unchecked Sendable {
    public static let shared = NotificationManager()

    /// Notification action identifiers.
    private enum Action {
        static let view = "VIEW_EMAIL"
        static let markSafe = "MARK_SAFE"
    }

    /// Notification category identifier.
    private static let phishingCategory = "PHISHING_ALERT"

    private let center = UNUserNotificationCenter.current()
    private var onMarkSafe: ((String) -> Void)?

    private override init() {
        super.init()
    }

    /// Requests notification permission and configures categories.
    public func setup(onMarkSafe: @escaping (String) -> Void) {
        self.onMarkSafe = onMarkSafe

        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error {
                print("Notification permission error: \(error.localizedDescription)")
            }
        }

        // Register notification actions
        let viewAction = UNNotificationAction(
            identifier: Action.view,
            title: "View",
            options: .foreground
        )

        let markSafeAction = UNNotificationAction(
            identifier: Action.markSafe,
            title: "Mark Safe",
            options: .destructive
        )

        let category = UNNotificationCategory(
            identifier: Self.phishingCategory,
            actions: [viewAction, markSafeAction],
            intentIdentifiers: [],
            options: []
        )

        center.setNotificationCategories([category])
        center.delegate = self
    }

    /// Sends a notification for a suspicious email verdict.
    public func notify(verdict: Verdict, senderDomain: String, subject: String) {
        let content = UNMutableNotificationContent()
        content.categoryIdentifier = Self.phishingCategory

        switch verdict.threatLevel {
        case .suspicious:
            content.title = "Suspicious Email Detected"
            content.sound = .default
        case .phishing:
            content.title = "⚠ Likely Phishing Email"
            content.sound = .defaultCritical
        case .clean:
            return // No notification for clean emails
        }

        content.body = buildNotificationBody(
            senderDomain: senderDomain,
            subject: subject,
            reasons: verdict.reasons
        )
        content.userInfo = ["messageId": verdict.messageId]

        let request = UNNotificationRequest(
            identifier: verdict.messageId,
            content: content,
            trigger: nil // Deliver immediately
        )

        center.add(request) { error in
            if let error {
                print("Failed to deliver notification: \(error.localizedDescription)")
            }
        }
    }

    private func buildNotificationBody(senderDomain: String, subject: String, reasons: [CheckResult]) -> String {
        var body = "From: \(senderDomain)"
        if !subject.isEmpty {
            let truncatedSubject = subject.count > 50 ? String(subject.prefix(47)) + "..." : subject
            body += "\nSubject: \(truncatedSubject)"
        }
        if let firstReason = reasons.first {
            body += "\n\(firstReason.reason)"
        }
        return body
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension NotificationManager: UNUserNotificationCenterDelegate {
    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let messageId = response.notification.request.content.userInfo["messageId"] as? String ?? ""

        switch response.actionIdentifier {
        case Action.markSafe:
            onMarkSafe?(messageId)
        case Action.view:
            // Open the app and show details for this email
            NotificationCenter.default.post(
                name: .phishGuardShowEmail,
                object: nil,
                userInfo: ["messageId": messageId]
            )
        default:
            break
        }

        completionHandler()
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Show notification even when app is in foreground
        completionHandler([.banner, .sound])
    }
}

// MARK: - Notification Names

extension Notification.Name {
    public static let phishGuardShowEmail = Notification.Name("com.phishguard.showEmail")
}
#endif
