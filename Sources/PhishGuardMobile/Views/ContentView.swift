import SwiftUI

/// Tab-based root view for the iOS app.
struct ContentView: View {
    @ObservedObject var accountManager: MobileAccountManager

    var body: some View {
        TabView {
            AlertsView(accountManager: accountManager)
                .tabItem {
                    Label("Alerts", systemImage: "exclamationmark.shield")
                }

            AccountsView(accountManager: accountManager)
                .tabItem {
                    Label("Accounts", systemImage: "person.crop.circle")
                }

            MobileSettingsView(accountManager: accountManager)
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
        }
    }
}
