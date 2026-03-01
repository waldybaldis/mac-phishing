import SwiftUI
import PhishGuardCore

/// Settings view for adjusting PhishGuard behavior on iOS.
struct MobileSettingsView: View {
    @ObservedObject var accountManager: MobileAccountManager
    @AppStorage("sensitivityThreshold") private var sensitivityThreshold: Double = 3.0
    @AppStorage("showScore") private var showScore: Bool = false
    @State private var senderDomainCount: Int = 0
    @State private var linkDomainCount: Int = 0
    @State private var showSenderSheet = false
    @State private var showLinkSheet = false
    @State private var blockedDomainCount: Int = 0
    @State private var showBlockedSheet = false
    @State private var userBrandCount = 0
    @State private var showUserBrandSheet = false
    @State private var safeonwebBrandCount = 0
    @State private var safeonwebLastUpdated: Date?
    @State private var safeonwebRefreshing = false
    @State private var scanCount: Int = 100

    var body: some View {
        NavigationStack {
            Form {
                // Detection Sensitivity
                Section("Detection Sensitivity") {
                    VStack(alignment: .leading, spacing: 4) {
                        Slider(value: $sensitivityThreshold, in: 1...10, step: 1)
                        HStack {
                            Text("Sensitive")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("Threshold: \(Int(sensitivityThreshold))")
                                .font(.caption)
                                .fontWeight(.medium)
                            Spacer()
                            Text("Conservative")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Toggle("Show Score on Alerts", isOn: $showScore)
                }

                // Trusted Domains
                Section("Trusted Domains") {
                    Button {
                        showSenderSheet = true
                    } label: {
                        HStack {
                            Text("Trusted Senders")
                            Spacer()
                            Text("\(senderDomainCount) domains")
                                .foregroundStyle(.secondary)
                        }
                    }

                    Button {
                        showLinkSheet = true
                    } label: {
                        HStack {
                            Text("Trusted Links")
                            Spacer()
                            Text("\(linkDomainCount) domains")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                // Blocked Domains
                Section("Blocked Domains") {
                    Button {
                        showBlockedSheet = true
                    } label: {
                        HStack {
                            Text("Blocked Senders")
                            Spacer()
                            Text("\(blockedDomainCount) domains")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                // Brand Watchlist
                Section("Brand Watchlist") {
                    Button {
                        showUserBrandSheet = true
                    } label: {
                        HStack {
                            Text("Your Brands")
                            Spacer()
                            Text("\(userBrandCount) brands")
                                .foregroundStyle(.secondary)
                        }
                    }

                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Safeonweb")
                            if let updated = safeonwebLastUpdated {
                                Text("Updated \(updated, style: .relative) ago")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        Spacer()
                        Text("\(safeonwebBrandCount) brands")
                            .foregroundStyle(.secondary)
                        Button {
                            refreshSafeonweb()
                        } label: {
                            if safeonwebRefreshing {
                                ProgressView()
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                        }
                        .disabled(safeonwebRefreshing)
                    }
                }

                // Scan Mailbox
                Section("Scan Mailbox") {
                    Picker("Emails to scan", selection: $scanCount) {
                        Text("100").tag(100)
                        Text("250").tag(250)
                        Text("500").tag(500)
                        Text("1K").tag(1000)
                        Text("All").tag(0)
                    }
                    .pickerStyle(.segmented)

                    Button {
                        Task { await accountManager.scanAllAccounts(count: scanCount) }
                    } label: {
                        HStack {
                            Spacer()
                            if accountManager.scanRunning {
                                ProgressView()
                                    .padding(.trailing, 8)
                            }
                            Text(accountManager.scanRunning ? "Scanning..." : "Scan Now")
                                .fontWeight(.medium)
                            Spacer()
                        }
                    }
                    .disabled(accountManager.scanRunning || accountManager.accounts.isEmpty)

                    if let result = accountManager.scanResult {
                        Text("\(result.emailCount) emails scanned in \(String(format: "%.1f", result.totalTime))s")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Settings")
            .onAppear {
                refreshDomainCounts()
                refreshBrandCounts()
            }
            .sheet(isPresented: $showSenderSheet, onDismiss: { refreshDomainCounts() }) {
                MobileDomainListView(
                    title: "Trusted Senders",
                    onAdd: { try accountManager.allowlistStore.add(domain: $0) },
                    onRemove: { try accountManager.allowlistStore.remove(domain: $0) },
                    loadDomains: { try accountManager.allowlistStore.allDomains() }
                )
            }
            .sheet(isPresented: $showLinkSheet, onDismiss: { refreshDomainCounts() }) {
                MobileDomainListView(
                    title: "Trusted Links",
                    onAdd: { try accountManager.trustedLinkDomainStore.add(domain: $0) },
                    onRemove: { try accountManager.trustedLinkDomainStore.remove(domain: $0) },
                    loadDomains: { try Array(accountManager.trustedLinkDomainStore.allDomains()) }
                )
            }
            .sheet(isPresented: $showBlockedSheet, onDismiss: { refreshDomainCounts() }) {
                MobileDomainListView(
                    title: "Blocked Senders",
                    onAdd: { try accountManager.userBlocklistStore.add(domain: $0) },
                    onRemove: { try accountManager.userBlocklistStore.remove(domain: $0) },
                    loadDomains: { try accountManager.userBlocklistStore.allDomains() }
                )
            }
            .sheet(isPresented: $showUserBrandSheet, onDismiss: { refreshBrandCounts() }) {
                MobileDomainListView(
                    title: "Brand Watchlist",
                    onAdd: { try accountManager.userBrandStore.add(brand: $0) },
                    onRemove: { try accountManager.userBrandStore.remove(brand: $0) },
                    loadDomains: { try accountManager.userBrandStore.allBrands() }
                )
            }
            .task {
                if (try? accountManager.safeonwebUpdater.needsRefresh()) == true {
                    refreshSafeonweb()
                }
            }
        }
    }

    private func refreshDomainCounts() {
        senderDomainCount = (try? accountManager.allowlistStore.allDomains().count) ?? 0
        linkDomainCount = (try? accountManager.trustedLinkDomainStore.count()) ?? 0
        blockedDomainCount = (try? accountManager.userBlocklistStore.count()) ?? 0
    }

    private func refreshBrandCounts() {
        userBrandCount = (try? accountManager.userBrandStore.count()) ?? 0
        safeonwebBrandCount = (try? accountManager.campaignStore.count()) ?? 0
        safeonwebLastUpdated = try? accountManager.campaignStore.lastFetched()
    }

    private func refreshSafeonweb() {
        safeonwebRefreshing = true
        Task {
            _ = try? await accountManager.safeonwebUpdater.update()
            await MainActor.run {
                refreshBrandCounts()
                safeonwebRefreshing = false
            }
        }
    }
}

/// Reusable domain/brand list view for iOS sheets.
struct MobileDomainListView: View {
    let title: String
    let onAdd: (String) throws -> Void
    let onRemove: (String) throws -> Void
    let loadDomains: () throws -> [String]

    @State private var domains: [String] = []
    @State private var searchText = ""
    @State private var newDomain = ""
    @Environment(\.dismiss) private var dismiss

    private var filteredDomains: [String] {
        if searchText.isEmpty { return domains }
        return domains.filter { $0.localizedCaseInsensitiveContains(searchText) }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        TextField("Add domain...", text: $newDomain)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .onSubmit { addDomain() }
                        Button("Add") { addDomain() }
                            .disabled(newDomain.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }

                Section {
                    if filteredDomains.isEmpty {
                        Text(domains.isEmpty ? "No entries" : "No matches")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(filteredDomains, id: \.self) { domain in
                            Text(domain)
                                .font(.system(.body, design: .monospaced))
                        }
                        .onDelete { indexSet in
                            for index in indexSet {
                                let domain = filteredDomains[index]
                                try? onRemove(domain)
                            }
                            reload()
                        }
                    }
                }
            }
            .searchable(text: $searchText, prompt: "Search")
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear { reload() }
        }
    }

    private func addDomain() {
        let domain = newDomain.trimmingCharacters(in: .whitespaces).lowercased()
        guard !domain.isEmpty else { return }
        try? onAdd(domain)
        newDomain = ""
        reload()
    }

    private func reload() {
        domains = (try? loadDomains())?.sorted() ?? []
    }
}
