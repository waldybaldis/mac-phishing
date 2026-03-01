import SwiftUI
import PhishGuardCore

/// Displays the list of monitored accounts with status and an "Add Account" button.
struct AccountsView: View {
    @ObservedObject var accountManager: MobileAccountManager
    @State private var showAddAccount = false

    var body: some View {
        NavigationStack {
            List {
                if accountManager.accounts.isEmpty {
                    ContentUnavailableView(
                        "No Accounts",
                        systemImage: "envelope.badge.shield.half.filled",
                        description: Text("Add an email account to start monitoring")
                    )
                    .listRowSeparator(.hidden)
                } else {
                    ForEach(accountManager.accounts) { account in
                        AccountRow(account: account, status: accountManager.status(for: account.id))
                    }
                    .onDelete { indexSet in
                        for index in indexSet {
                            accountManager.removeAccount(id: accountManager.accounts[index].id)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Accounts")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showAddAccount = true
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showAddAccount) {
                AddAccountView(accountManager: accountManager)
            }
        }
    }
}

/// A single account row showing email, provider, and connection status.
struct AccountRow: View {
    let account: MobileMonitoredAccount
    let status: AccountConnectionStatus

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(account.email)
                    .font(.body)
                    .fontWeight(.medium)
                HStack(spacing: 4) {
                    Text(account.provider.rawValue)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("·")
                        .foregroundStyle(.tertiary)
                    Text(account.imapServer)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }

            Spacer()

            HStack(spacing: 4) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 8, height: 8)
                Text(statusLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    private var statusColor: Color {
        switch status {
        case .disconnected: return .gray
        case .connecting: return .orange
        case .monitoring: return .green
        case .error: return .red
        }
    }

    private var statusLabel: String {
        switch status {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting..."
        case .monitoring: return "Monitoring"
        case .error(let msg): return "Error: \(msg)"
        }
    }
}
