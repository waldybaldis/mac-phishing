import SwiftUI

/// View for configuring IMAP mail accounts.
struct AccountSetupView: View {
    @State private var provider = "iCloud"
    @State private var server = "imap.mail.me.com"
    @State private var port = "993"
    @State private var username = ""
    @State private var password = ""
    @State private var useTLS = true
    @State private var isConnecting = false
    @State private var connectionStatus: String?

    private let providers = ["iCloud", "Outlook", "Gmail", "Custom"]
    private let providerServers = [
        "iCloud": "imap.mail.me.com",
        "Outlook": "outlook.office365.com",
        "Gmail": "imap.gmail.com",
        "Custom": "",
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Mail Account")
                    .font(.headline)

                // Provider picker
                Picker("Provider", selection: $provider) {
                    ForEach(providers, id: \.self) { Text($0) }
                }
                .onChange(of: provider) { _, newValue in
                    if let defaultServer = providerServers[newValue] {
                        server = defaultServer
                    }
                    port = "993"
                }

                // Server settings
                Group {
                    LabeledContent("Server") {
                        TextField("imap.example.com", text: $server)
                            .textFieldStyle(.roundedBorder)
                            .disabled(provider != "Custom")
                    }
                    LabeledContent("Port") {
                        TextField("993", text: $port)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 80)
                    }
                    Toggle("Use TLS", isOn: $useTLS)
                }

                Divider()

                // Credentials
                Group {
                    LabeledContent("Username") {
                        TextField("user@example.com", text: $username)
                            .textFieldStyle(.roundedBorder)
                    }
                    LabeledContent("Password") {
                        SecureField("App-specific password", text: $password)
                            .textFieldStyle(.roundedBorder)
                    }
                }

                if provider == "iCloud" {
                    Text("Use an app-specific password from appleid.apple.com")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                // Connect button
                HStack {
                    Spacer()
                    Button(isConnecting ? "Connecting..." : "Connect") {
                        connect()
                    }
                    .disabled(username.isEmpty || password.isEmpty || isConnecting)
                    .buttonStyle(.borderedProminent)
                }

                if let status = connectionStatus {
                    Text(status)
                        .font(.caption)
                        .foregroundStyle(status.contains("Error") ? .red : .green)
                }
            }
            .padding()
        }
    }

    private func connect() {
        isConnecting = true
        connectionStatus = nil

        // In production, this would:
        // 1. Create an AccountConfig
        // 2. Store password in Keychain
        // 3. Initialize IMAPMonitor and attempt connection
        // 4. On success, start monitoring

        Task {
            try? await Task.sleep(for: .seconds(1))
            await MainActor.run {
                isConnecting = false
                connectionStatus = "Connected successfully"
            }
        }
    }
}
