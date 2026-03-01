import AppKit
import SwiftUI
import UserNotifications
import PhishGuardCore

/// App delegate that sets up the menu bar status item and manages the app lifecycle.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private let accountManager = AccountManager()
    private var alertTimer: Timer?
    private var alertObserver: Any?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenuBar()
        startAlertPolling()
        setupNotifications()
    }

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "PhishGuard")
            button.action = #selector(togglePopover)
            button.target = self
        }

        let popover = NSPopover()
        popover.contentSize = NSSize(width: 360, height: 480)
        popover.behavior = .transient
        let hostingController = NSHostingController(rootView: MenuBarView(accountManager: accountManager))
        hostingController.view.wantsLayer = true
        hostingController.view.layer?.backgroundColor = NSColor.white.cgColor
        popover.contentViewController = hostingController
        self.popover = popover
    }

    @objc private func togglePopover() {
        guard let popover, let button = statusItem?.button else { return }

        if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }

    // MARK: - Alert Icon Updates

    private func startAlertPolling() {
        alertTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            self?.updateStatusIcon()
        }
        updateStatusIcon()
    }

    private func updateStatusIcon() {
        guard let button = statusItem?.button else { return }

        let threshold = Int(UserDefaults.standard.double(forKey: "sensitivityThreshold"))
        let effectiveThreshold = threshold > 0 ? threshold : 3

        let redCount = (try? accountManager.verdictStore.alertCount(minimumScore: 6)) ?? 0
        let orangeCount = (try? accountManager.verdictStore.alertCount(minimumScore: effectiveThreshold)) ?? 0

        if redCount > 0 {
            let config = NSImage.SymbolConfiguration(paletteColors: [.systemRed])
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "PhishGuard — alerts")?
                .withSymbolConfiguration(config)
        } else if orangeCount > 0 {
            let config = NSImage.SymbolConfiguration(paletteColors: [.systemOrange])
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "PhishGuard — warnings")?
                .withSymbolConfiguration(config)
        } else {
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "PhishGuard")
        }
    }

    // MARK: - Notifications

    private func setupNotifications() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }

        alertObserver = NotificationCenter.default.addObserver(
            forName: .phishGuardNewAlert,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let verdict = notification.object as? Verdict else { return }
            self?.sendUserNotification(for: verdict)
            self?.updateStatusIcon()
        }
    }

    private func sendUserNotification(for verdict: Verdict) {
        let content = UNMutableNotificationContent()

        if verdict.score >= 6 {
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
}
