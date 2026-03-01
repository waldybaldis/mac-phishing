import SwiftUI
import PhishGuardCore

/// Form for adding a new email account.
struct AddAccountView: View {
    @ObservedObject var accountManager: MobileAccountManager
    @Environment(\.dismiss) private var dismiss

    @State private var email = ""
    @State private var password = ""
    @State private var customServer = ""
    @State private var customPort = "993"
    @State private var isConnecting = false
    @State private var errorMessage: String?

    private var detectedProvider: MailProvider {
        MailProviderDetector.detect(email: email)
    }

    private var isOAuthProvider: Bool {
        let provider = detectedProvider
        guard provider.authMethod == .oauth2 else { return false }
        let oauthProv: OAuthConfig.Provider = provider == .gmail ? .google : .microsoft
        return OAuthConfig.isConfigured(for: oauthProv)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Email Address") {
                    TextField("you@example.com", text: $email)
                        .textContentType(.emailAddress)
                        .keyboardType(.emailAddress)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)

                    if !email.isEmpty {
                        HStack {
                            Image(systemName: providerIcon)
                            Text("Detected: \(detectedProvider.rawValue)")
                                .foregroundStyle(.secondary)
                        }
                        .font(.caption)
                    }
                }

                if !email.isEmpty {
                    if isOAuthProvider {
                        Section {
                            Button {
                                connectWithOAuth()
                            } label: {
                                HStack {
                                    Spacer()
                                    if isConnecting {
                                        ProgressView()
                                            .padding(.trailing, 8)
                                    }
                                    Text(oauthButtonLabel)
                                        .fontWeight(.medium)
                                    Spacer()
                                }
                            }
                            .disabled(isConnecting)
                        } footer: {
                            Text("Opens your browser to sign in securely")
                        }
                    } else {
                        Section {
                            SecureField("App-specific password", text: $password)
                                .textContentType(.password)
                        } header: {
                            Text("Password")
                        } footer: {
                            Text(passwordHint)
                        }

                        if detectedProvider == .custom {
                            Section("IMAP Server") {
                                TextField("imap.example.com", text: $customServer)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                TextField("Port", text: $customPort)
                                    .keyboardType(.numberPad)
                            }
                        }

                        Section {
                            Button {
                                connectWithPassword()
                            } label: {
                                HStack {
                                    Spacer()
                                    if isConnecting {
                                        ProgressView()
                                            .padding(.trailing, 8)
                                    }
                                    Text("Connect")
                                        .fontWeight(.medium)
                                    Spacer()
                                }
                            }
                            .disabled(password.isEmpty || isConnecting || (detectedProvider == .custom && customServer.isEmpty))
                        }
                    }
                }

                if let error = errorMessage {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                }
            }
            .navigationTitle("Add Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private var providerIcon: String {
        switch detectedProvider {
        case .gmail: return "envelope.fill"
        case .outlook: return "envelope.fill"
        case .icloud: return "icloud"
        case .yahoo: return "envelope.fill"
        case .custom: return "server.rack"
        }
    }

    private var oauthButtonLabel: String {
        switch detectedProvider {
        case .gmail: return "Sign in with Google"
        case .outlook: return "Sign in with Microsoft"
        default: return "Sign in"
        }
    }

    private var passwordHint: String {
        switch detectedProvider {
        case .icloud: return "Generate an app-specific password at appleid.apple.com"
        case .yahoo: return "Generate an app password at login.yahoo.com/account/security"
        case .gmail: return "Generate an app-specific password at myaccount.google.com/apppasswords"
        default: return "Enter your IMAP password"
        }
    }

    private func connectWithOAuth() {
        isConnecting = true
        errorMessage = nil
        Task {
            do {
                try await accountManager.addAccountWithOAuth(email: email, provider: detectedProvider)
                dismiss()
            } catch {
                if case OAuthError.userCancelled = error {
                    // User cancelled — don't show error
                } else {
                    errorMessage = error.localizedDescription
                }
            }
            isConnecting = false
        }
    }

    private func connectWithPassword() {
        isConnecting = true
        errorMessage = nil

        let server = detectedProvider == .custom ? customServer : nil
        let port = detectedProvider == .custom ? Int(customPort) : nil

        Task {
            await accountManager.addAccount(
                email: email,
                password: password,
                imapServer: server,
                imapPort: port
            )

            // Check if the last account connected successfully
            if let lastAccount = accountManager.accounts.last {
                let status = accountManager.status(for: lastAccount.id)
                if case .error(let msg) = status {
                    errorMessage = msg
                } else {
                    dismiss()
                }
            }
            isConnecting = false
        }
    }
}
