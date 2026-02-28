import SwiftUI

/// The main popover view shown from the menu bar icon.
struct MenuBarView: View {
    @StateObject private var accountManager = AccountManager()
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 8) {
                Image(systemName: "shield.checkered")
                    .font(.title3)
                    .foregroundStyle(.tint)
                Text("PhishGuard")
                    .font(.system(.headline, weight: .semibold))
                Spacer()
                StatusIndicatorView(isMonitoring: accountManager.isAnyMonitoring)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)

            // Tab selector
            Picker("", selection: $selectedTab) {
                Text("Alerts").tag(0)
                Text("Accounts").tag(1)
                Text("Settings").tag(2)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 14)
            .padding(.bottom, 8)

            Divider()

            // Content
            switch selectedTab {
            case 0:
                AlertsListView(accountManager: accountManager)
            case 1:
                AccountSetupView(accountManager: accountManager)
            case 2:
                SettingsView(accountManager: accountManager)
            default:
                AlertsListView(accountManager: accountManager)
            }

            Divider()

            // Footer
            HStack {
                let activeCount = accountManager.accounts.filter(\.isActivated).count
                if activeCount > 0 {
                    Text("\(activeCount) account\(activeCount == 1 ? "" : "s") active")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                } else {
                    Text("No accounts active")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Spacer()
                Button("Quit") {
                    NSApplication.shared.terminate(nil)
                }
                .font(.caption2)
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
        }
        .frame(width: 360, height: 480)
    }
}

/// Indicator showing whether monitoring is active.
struct StatusIndicatorView: View {
    let isMonitoring: Bool

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(isMonitoring ? Color.green : Color.red)
                .frame(width: 8, height: 8)
            Text(isMonitoring ? "Monitoring" : "Stopped")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
