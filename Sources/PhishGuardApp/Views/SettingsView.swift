import SwiftUI

/// Settings view for adjusting PhishGuard behavior.
struct SettingsView: View {
    var accountManager: AccountManager?
    @State private var scanCount: Int = 100
    @State private var sensitivityThreshold: Double = 3.0
    @State private var movePhishingToJunk = true
    @State private var showNotifications = true
    @State private var senderDomainCount: Int = 0
    @State private var linkDomainCount: Int = 0
    @State private var showSenderSheet = false
    @State private var showLinkSheet = false
    @State private var blacklistCount = 48231
    @State private var lastUpdated = Date().addingTimeInterval(-3600)
    @State private var safeonwebBrandCount = 0
    @State private var safeonwebLastUpdated: Date?
    @State private var safeonwebRefreshing = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                // Detection Sensitivity
                sectionHeader("Detection Sensitivity")
                VStack(alignment: .leading, spacing: 4) {
                    Slider(value: $sensitivityThreshold, in: 1...10, step: 1)
                    HStack {
                        Text("Sensitive")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text("Threshold: \(Int(sensitivityThreshold))")
                            .font(.caption2)
                            .fontWeight(.medium)
                        Spacer()
                        Text("Conservative")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 14)

                sectionDivider

                // Actions
                sectionHeader("Actions")
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Move phishing to Junk", isOn: $movePhishingToJunk)
                        .font(.callout)
                    Toggle("Show notifications", isOn: $showNotifications)
                        .font(.callout)
                }
                .padding(.horizontal, 14)

                sectionDivider

                // Trusted Domains
                sectionHeader("Trusted Domains")
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Senders — \(senderDomainCount) domains")
                            .font(.caption)
                        Spacer()
                        Button("Manage") { showSenderSheet = true }
                            .controlSize(.small)
                            .buttonStyle(.bordered)
                    }
                    HStack {
                        Text("Links — \(linkDomainCount) domains")
                            .font(.caption)
                        Spacer()
                        Button("Manage") { showLinkSheet = true }
                            .controlSize(.small)
                            .buttonStyle(.bordered)
                    }
                }
                .padding(.horizontal, 14)
                .onAppear { refreshDomainCounts() }
                .sheet(isPresented: $showSenderSheet, onDismiss: { refreshDomainCounts() }) {
                    if let mgr = accountManager {
                        DomainListSheet(
                            title: "Trusted Senders",
                            onAdd: { try mgr.allowlistStore.add(domain: $0) },
                            onRemove: { try mgr.allowlistStore.remove(domain: $0) },
                            loadDomains: { try mgr.allowlistStore.allDomains() }
                        )
                    }
                }
                .sheet(isPresented: $showLinkSheet, onDismiss: { refreshDomainCounts() }) {
                    if let mgr = accountManager {
                        DomainListSheet(
                            title: "Trusted Links",
                            onAdd: { try mgr.trustedLinkDomainStore.add(domain: $0) },
                            onRemove: { try mgr.trustedLinkDomainStore.remove(domain: $0) },
                            loadDomains: { try Array(mgr.trustedLinkDomainStore.allDomains()) }
                        )
                    }
                }

                sectionDivider

                // Blacklist
                sectionHeader("Phishing Blacklist")
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(blacklistCount.formatted()) domains")
                            .font(.caption)
                        Text("Updated \(lastUpdated, style: .relative) ago")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                    Button("Refresh") {
                        // Trigger blacklist update
                    }
                    .controlSize(.small)
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal, 14)

                sectionDivider

                // Safeonweb Campaigns
                sectionHeader("Safeonweb Campaigns")
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(safeonwebBrandCount) active brands")
                            .font(.caption)
                        if let updated = safeonwebLastUpdated {
                            Text("Updated \(updated, style: .relative) ago")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        } else {
                            Text("Never updated")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    Spacer()
                    Button {
                        guard let mgr = accountManager else { return }
                        safeonwebRefreshing = true
                        Task {
                            _ = try? await mgr.safeonwebUpdater.update()
                            await MainActor.run {
                                safeonwebBrandCount = (try? mgr.campaignStore.count()) ?? 0
                                safeonwebLastUpdated = try? mgr.campaignStore.lastFetched()
                                safeonwebRefreshing = false
                            }
                        }
                    } label: {
                        if safeonwebRefreshing {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Text("Refresh")
                        }
                    }
                    .controlSize(.small)
                    .buttonStyle(.bordered)
                    .disabled(safeonwebRefreshing)
                }
                .padding(.horizontal, 14)
                .onAppear {
                    refreshSafeonwebStats()
                }
                .task {
                    // Check staleness on appear and refresh if needed
                    guard let mgr = accountManager else { return }
                    if (try? mgr.safeonwebUpdater.needsRefresh()) == true {
                        safeonwebRefreshing = true
                        _ = try? await mgr.safeonwebUpdater.update()
                        await MainActor.run {
                            refreshSafeonwebStats()
                            safeonwebRefreshing = false
                        }
                    }
                }

                if accountManager != nil {
                    sectionDivider

                    // Scan Mailbox
                    sectionHeader("Scan Mailbox")
                    HStack {
                        VStack(alignment: .leading, spacing: 6) {
                            Picker("Count", selection: $scanCount) {
                                Text("100").tag(100)
                                Text("250").tag(250)
                                Text("500").tag(500)
                                Text("1K").tag(1000)
                                Text("All").tag(0)
                            }
                            .pickerStyle(.segmented)
                            .labelsHidden()

                            if let result = accountManager?.scanResult {
                                Text("\(result.emailCount) emails scanned in \(String(format: "%.1f", result.totalTime))s")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        Button {
                            guard let mgr = accountManager else { return }
                            Task { await mgr.scanAllAccounts(count: scanCount) }
                        } label: {
                            if accountManager?.scanRunning == true {
                                ProgressView()
                                    .controlSize(.small)
                            } else {
                                Text("Scan")
                            }
                        }
                        .controlSize(.small)
                        .buttonStyle(.bordered)
                        .disabled(accountManager?.scanRunning == true
                                  || accountManager?.accounts.contains(where: \.isActivated) != true)
                    }
                    .padding(.horizontal, 14)
                }
            }
            .padding(.vertical, 10)
        }
    }

    // MARK: - Helpers

    private func refreshDomainCounts() {
        guard let mgr = accountManager else { return }
        senderDomainCount = (try? mgr.allowlistStore.allDomains().count) ?? 0
        linkDomainCount = (try? mgr.trustedLinkDomainStore.count()) ?? 0
    }

    private func refreshSafeonwebStats() {
        guard let mgr = accountManager else { return }
        safeonwebBrandCount = (try? mgr.campaignStore.count()) ?? 0
        safeonwebLastUpdated = try? mgr.campaignStore.lastFetched()
    }

    // MARK: - Section Helpers

    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.system(.subheadline, weight: .semibold))
            .foregroundStyle(.primary)
            .padding(.horizontal, 14)
            .padding(.top, 10)
            .padding(.bottom, 6)
    }

    private var sectionDivider: some View {
        Divider()
            .padding(.horizontal, 10)
            .padding(.top, 8)
    }
}
