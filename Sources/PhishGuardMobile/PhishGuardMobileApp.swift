import SwiftUI
import UserNotifications
import PhishGuardCore

@main
struct PhishGuardMobileApp: App {
    @StateObject private var accountManager = MobileAccountManager()
    @Environment(\.scenePhase) private var scenePhase

    private let backgroundMonitor: BackgroundMonitor
    private let alertObserver: Any

    init() {
        let manager = MobileAccountManager()
        _accountManager = StateObject(wrappedValue: manager)
        backgroundMonitor = BackgroundMonitor(accountManager: manager)
        backgroundMonitor.register()
        BackgroundMonitor.requestNotificationPermission()

        // Listen for new phishing alerts — only send notifications when backgrounded
        alertObserver = NotificationCenter.default.addObserver(
            forName: .phishGuardNewAlert,
            object: nil,
            queue: .main
        ) { notification in
            guard UIApplication.shared.applicationState != .active else { return }
            guard let verdict = notification.object as? Verdict else { return }
            BackgroundMonitor.sendNotification(for: verdict)
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView(accountManager: accountManager)
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active:
                Task { await accountManager.reconnectAll() }
                backgroundMonitor.scheduleNextRefresh()
            case .background:
                backgroundMonitor.scheduleNextRefresh()
            default:
                break
            }
        }
    }
}
