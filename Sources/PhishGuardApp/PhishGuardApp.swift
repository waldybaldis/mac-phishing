import SwiftUI

/// PhishGuard — macOS menu bar app for phishing detection.
@main
struct PhishGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // Menu bar app — no main window
        Settings {
            SettingsView()
        }
    }
}
