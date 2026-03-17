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
                        AccountRow(
                            account: account,
                            status: accountManager.status(for: account.id),
                            accountManager: accountManager
                        )
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
/// Tapping expands to show re-auth UI when disconnected or errored.
struct AccountRow: View {
    let account: MobileMonitoredAccount
    let status: AccountConnectionStatus
    @ObservedObject var accountManager: MobileAccountManager

    @State private var isExpanded = false
    @State private var password = ""
    @State private var errorMessage: String?

    private var isOAuthProvider: Bool {
        guard account.authMethod == .oauth2 else { return false }
        let oauthProv: OAuthConfig.Provider = account.provider == .gmail ? .google : .microsoft
        return OAuthConfig.isConfigured(for: oauthProv)
    }

    private var needsReauth: Bool {
        switch status {
        case .disconnected, .error: return true
        case .monitoring, .connecting: return false
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Main row — tap to expand when re-auth needed
            Button {
                if needsReauth {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        isExpanded.toggle()
                    }
                }
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(account.email)
                            .font(.body)
                            .fontWeight(.medium)
                            .foregroundStyle(.primary)
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

                    if needsReauth {
                        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .buttonStyle(.plain)

            // Expanded re-auth section
            if isExpanded && needsReauth {
                VStack(alignment: .leading, spacing: 8) {
                    if isOAuthProvider {
                        Button {
                            reconnectWithOAuth()
                        } label: {
                            HStack {
                                Spacer()
                                Image(systemName: "globe")
                                    .font(.caption)
                                Text(oauthButtonLabel)
                                    .font(.caption)
                                    .fontWeight(.medium)
                                Spacer()
                            }
                            .padding(.vertical, 8)
                            .background(oauthButtonColor)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                        }
                        .buttonStyle(.plain)

                        Text("Opens your browser to sign in securely")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    } else {
                        SecureField("App-specific password", text: $password)
                            .textContentType(.password)
                            .font(.callout)

                        Text(passwordHint)
                            .font(.caption2)
                            .foregroundStyle(.secondary)

                        HStack {
                            Spacer()
                            Button("Reconnect") {
                                reconnectWithPassword()
                            }
                            .font(.caption)
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                            .disabled(password.isEmpty)
                        }
                    }

                    if let error = errorMessage {
                        Text(error)
                            .font(.caption2)
                            .foregroundStyle(.red)
                            .lineLimit(3)
                    }

                    HStack {
                        Spacer()
                        Button("Remove Account") {
                            accountManager.removeAccount(id: account.id)
                        }
                        .font(.caption)
                        .foregroundStyle(.red)
                    }
                }
                .padding(.top, 4)
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: - Status Display

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

    // MARK: - OAuth

    private var oauthButtonLabel: String {
        switch account.provider {
        case .gmail: return "Sign in with Google"
        case .outlook: return "Sign in with Microsoft"
        default: return "Sign in"
        }
    }

    private var oauthButtonColor: Color {
        switch account.provider {
        case .gmail: return .blue
        case .yahoo: return Color(red: 0.44, green: 0.11, blue: 0.68)
        default: return .accentColor
        }
    }

    private var passwordHint: String {
        switch account.provider {
        case .icloud: return "Generate an app-specific password at appleid.apple.com"
        case .yahoo: return "Generate an app password at login.yahoo.com/account/security"
        case .gmail: return "Generate an app-specific password at myaccount.google.com/apppasswords"
        default: return "Enter your IMAP password"
        }
    }

    // MARK: - Actions

    private func reconnectWithOAuth() {
        errorMessage = nil
        Task {
            do {
                try await accountManager.reactivateWithOAuth(id: account.id)
                isExpanded = false
            } catch {
                if case OAuthError.userCancelled = error {
                    // User cancelled — don't show error
                } else {
                    errorMessage = error.localizedDescription
                }
            }
        }
    }

    private func reconnectWithPassword() {
        errorMessage = nil
        Task {
            await accountManager.reactivateWithPassword(id: account.id, password: password)
            let newStatus = accountManager.status(for: account.id)
            if case .error(let msg) = newStatus {
                errorMessage = msg
            } else {
                password = ""
                isExpanded = false
            }
        }
    }
}
