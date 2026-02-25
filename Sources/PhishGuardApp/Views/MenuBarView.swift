import SwiftUI

/// The main popover view shown from the menu bar icon.
struct MenuBarView: View {
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "shield.checkered")
                    .font(.title2)
                Text("PhishGuard")
                    .font(.headline)
                Spacer()
                StatusIndicatorView(isMonitoring: true)
            }
            .padding(.horizontal)
            .padding(.vertical, 10)

            Divider()

            // Tab selector
            Picker("", selection: $selectedTab) {
                Text("Alerts").tag(0)
                Text("Accounts").tag(1)
                Text("Settings").tag(2)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)
            .padding(.vertical, 8)

            // Content
            switch selectedTab {
            case 0:
                AlertsListView()
            case 1:
                AccountSetupView()
            case 2:
                SettingsView()
            default:
                AlertsListView()
            }

            Divider()

            // Footer
            HStack {
                Text("Blacklist: 48,231 domains")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Quit") {
                    NSApplication.shared.terminate(nil)
                }
                .font(.caption)
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal)
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
