import SwiftUI

/// Settings view for adjusting PhishGuard behavior.
struct SettingsView: View {
    @State private var sensitivityThreshold: Double = 3.0
    @State private var movePhishingToJunk = true
    @State private var showNotifications = true
    @State private var allowlistedDomains: [String] = ["apple.com", "icloud.com"]
    @State private var newDomain = ""
    @State private var blacklistCount = 48231
    @State private var lastUpdated = Date().addingTimeInterval(-3600)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Sensitivity
                Group {
                    Text("Detection Sensitivity")
                        .font(.headline)

                    VStack(alignment: .leading) {
                        Slider(value: $sensitivityThreshold, in: 1...10, step: 1)
                        HStack {
                            Text("Sensitive")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("Score threshold: \(Int(sensitivityThreshold))")
                                .font(.caption)
                                .fontWeight(.medium)
                            Spacer()
                            Text("Conservative")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Divider()

                // Actions
                Group {
                    Text("Actions")
                        .font(.headline)

                    Toggle("Move phishing emails to Junk", isOn: $movePhishingToJunk)
                    Toggle("Show notifications", isOn: $showNotifications)
                }

                Divider()

                // Allowlist
                Group {
                    Text("Trusted Domains (Allowlist)")
                        .font(.headline)

                    ForEach(allowlistedDomains, id: \.self) { domain in
                        HStack {
                            Text(domain)
                                .font(.system(.body, design: .monospaced))
                            Spacer()
                            Button(role: .destructive) {
                                allowlistedDomains.removeAll { $0 == domain }
                            } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    HStack {
                        TextField("domain.com", text: $newDomain)
                            .textFieldStyle(.roundedBorder)
                        Button("Add") {
                            let domain = newDomain.trimmingCharacters(in: .whitespaces).lowercased()
                            if !domain.isEmpty && !allowlistedDomains.contains(domain) {
                                allowlistedDomains.append(domain)
                                newDomain = ""
                            }
                        }
                        .disabled(newDomain.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }

                Divider()

                // Blacklist info
                Group {
                    Text("Phishing Blacklist")
                        .font(.headline)

                    HStack {
                        VStack(alignment: .leading) {
                            Text("\(blacklistCount) domains")
                                .font(.subheadline)
                            Text("Last updated: \(lastUpdated, style: .relative) ago")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Refresh Now") {
                            // Trigger blacklist update
                        }
                        .buttonStyle(.bordered)
                    }
                }
            }
            .padding()
        }
    }
}
