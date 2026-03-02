import BackgroundTasks
import Foundation
import os.log
import UserNotifications
import PhishGuardCore

private let logger = Logger(subsystem: "com.phishguard.mobile", category: "BackgroundMonitor")

/// Manages background email checking using BGAppRefreshTask on iOS.
final class BackgroundMonitor {
    static let taskIdentifier = "com.phishguard.mobile.mail-check"

    private let accountManager: MobileAccountManager

    init(accountManager: MobileAccountManager) {
        self.accountManager = accountManager
    }

    /// Registers the background task with the system. Call once at app launch.
    func register() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: Self.taskIdentifier,
            using: nil
        ) { [weak self] task in
            guard let task = task as? BGAppRefreshTask else { return }
            self?.handleBackgroundRefresh(task: task)
        }
    }

    /// Schedules the next background refresh. Call after each check completes.
    func scheduleNextRefresh() {
        let request = BGAppRefreshTaskRequest(identifier: Self.taskIdentifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60) // ~15 minutes
        do {
            try BGTaskScheduler.shared.submit(request)
            logger.info("Scheduled next background refresh")
        } catch {
            logger.error("Failed to schedule background refresh: \(error.localizedDescription)")
        }
    }

    /// Handles a background refresh task.
    private func handleBackgroundRefresh(task: BGAppRefreshTask) {
        scheduleNextRefresh()

        let checkTask = Task {
            await performBackgroundCheck()
        }

        task.expirationHandler = {
            checkTask.cancel()
        }

        Task {
            await checkTask.value
            task.setTaskCompleted(success: !checkTask.isCancelled)
        }
    }

    /// Checks for new emails and sends notifications for phishing verdicts.
    @MainActor
    private func performBackgroundCheck() async {
        logger.info("Starting background email check")

        // Set up notification observer for new alerts
        let observer = NotificationCenter.default.addObserver(
            forName: .phishGuardNewAlert,
            object: nil,
            queue: .main
        ) { notification in
            guard let verdict = notification.object as? Verdict else { return }
            Self.sendNotification(for: verdict)
        }

        await accountManager.checkNewEmails()

        NotificationCenter.default.removeObserver(observer)
        logger.info("Background email check complete")
    }

    /// Sends a local notification for a phishing/suspicious verdict.
    static func sendNotification(for verdict: Verdict) {
        let content = UNMutableNotificationContent()

        if verdict.score >= PhishGuardThresholds.phishing {
            content.title = "Phishing Alert"
            content.sound = .defaultCritical
        } else {
            content.title = "Suspicious Email"
            content.sound = .default
        }

        content.subtitle = verdict.senderName
        content.body = verdict.subject.isEmpty ? "(No Subject)" : verdict.subject

        let request = UNNotificationRequest(
            identifier: verdict.messageId,
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request)
    }

    /// Requests notification permission from the user.
    static func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                logger.error("Notification permission error: \(error.localizedDescription)")
            }
            logger.info("Notification permission granted: \(granted)")
        }
    }
}
