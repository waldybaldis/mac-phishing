import SwiftUI

/// Displays discovered mail accounts with activation controls.
struct AccountSetupView: View {
    @ObservedObject var accountManager: AccountManager

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                // Header with refresh
                HStack {
                    Text("Mail Accounts")
                        .font(.headline)
                    Spacer()
                    Button {
                        Task { await accountManager.discoverAccounts() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .disabled(accountManager.isDiscovering)
                }
                .padding(.horizontal)
                .padding(.top, 8)

                if accountManager.isDiscovering {
                    HStack {
                        ProgressView()
                            .scaleEffect(0.7)
                        Text("Discovering accounts from Mail...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.horizontal)
                }

                if let error = accountManager.discoveryError {
                    VStack(alignment: .leading, spacing: 6) {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.red)
                        Button("Retry") {
                            Task { await accountManager.discoverAccounts() }
                        }
                        .font(.caption)
                    }
                    .padding(.horizontal)
                }

                if accountManager.accounts.isEmpty && !accountManager.isDiscovering && accountManager.discoveryError == nil {
                    VStack(spacing: 8) {
                        Image(systemName: "envelope.badge.shield.half.filled")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No accounts found")
                            .font(.subheadline)
                        Text("Configure email accounts in Mail.app first")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 40)
                }

                // Account list
                ForEach(Array(accountManager.accounts.enumerated()), id: \.element.id) { index, account in
                    AccountRowView(
                        account: account,
                        onActivatePassword: { password in
                            Task { await accountManager.activateWithPassword(accountId: account.id, password: password) }
                        },
                        onActivateOAuth: {
                            Task { await accountManager.activateWithOAuth(accountId: account.id) }
                        },
                        onDeactivate: {
                            accountManager.deactivate(accountId: account.id)
                        }
                    )
                    if index < accountManager.accounts.count - 1 {
                        Divider()
                            .padding(.horizontal)
                    }
                }
            }
            .padding(.bottom, 8)
        }
        .task {
            if accountManager.accounts.isEmpty {
                await accountManager.discoverAccounts()
            }
        }
    }
}

/// A single account row with status and expand/collapse for activation.
struct AccountRowView: View {
    let account: MonitoredAccount
    let onActivatePassword: (String) -> Void
    let onActivateOAuth: () -> Void
    let onDeactivate: () -> Void

    @State private var isExpanded = false
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Main row — tap to expand
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(account.discovered.name)
                                .font(.system(.body, weight: .medium))
                                .foregroundStyle(.primary)
                        }
                        Text(account.discovered.email)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(account.discovered.server)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }

                    Spacer()

                    // Status badge
                    HStack(spacing: 4) {
                        Circle()
                            .fill(account.status.color)
                            .frame(width: 8, height: 8)
                        Text(account.status.label)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }

                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            .buttonStyle(.plain)
            .padding(.horizontal)

            // Expanded section
            if isExpanded {
                VStack(alignment: .leading, spacing: 8) {
                    if account.isActivated {
                        // Already activated — show deactivate
                        HStack {
                            Spacer()
                            Button("Deactivate") {
                                onDeactivate()
                                password = ""
                            }
                            .font(.caption)
                            .foregroundStyle(.red)
                        }
                    } else if account.usesOAuth {
                        // OAuth provider — show sign-in button
                        oauthActivationView
                    } else {
                        // Password provider — show password field
                        passwordActivationView
                    }

                    if case .error(let msg) = account.status {
                        Text(msg)
                            .font(.caption2)
                            .foregroundStyle(.red)
                            .lineLimit(3)
                    }
                }
                .padding(.horizontal)
                .padding(.bottom, 4)
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: - OAuth Activation

    @ViewBuilder
    private var oauthActivationView: some View {
        VStack(alignment: .leading, spacing: 8) {
            if account.provider == .gmail {
                Button {
                    onActivateOAuth()
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "globe")
                            .font(.caption)
                        Text("Sign in with Google")
                            .font(.caption)
                            .fontWeight(.medium)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(6)
                }
                .buttonStyle(.plain)
            } else {
                Button {
                    onActivateOAuth()
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "globe")
                            .font(.caption)
                        Text("Sign in with Microsoft")
                            .font(.caption)
                            .fontWeight(.medium)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(Color(nsColor: .controlAccentColor))
                    .foregroundColor(.white)
                    .cornerRadius(6)
                }
                .buttonStyle(.plain)
            }

            Text("Opens your browser to sign in securely")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Password Activation

    @ViewBuilder
    private var passwordActivationView: some View {
        SecureField("App-specific password", text: $password)
            .textFieldStyle(.roundedBorder)
            .font(.caption)

        switch account.provider {
        case .icloud:
            Text("Generate an app-specific password at appleid.apple.com")
                .font(.caption2)
                .foregroundStyle(.secondary)
        case .gmail:
            Text("Generate an app-specific password at myaccount.google.com/apppasswords")
                .font(.caption2)
                .foregroundStyle(.secondary)
        case .outlook:
            Text("Generate an app password at account.microsoft.com/security")
                .font(.caption2)
                .foregroundStyle(.secondary)
        case .custom:
            EmptyView()
        }

        HStack {
            Spacer()
            Button("Activate") {
                onActivatePassword(password)
            }
            .font(.caption)
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .disabled(password.isEmpty)
        }
    }
}
