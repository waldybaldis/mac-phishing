import SwiftUI
import PhishGuardCore

/// Displays recent phishing alerts from the verdict database.
struct AlertsView: View {
    @ObservedObject var accountManager: MobileAccountManager
    @AppStorage("sensitivityThreshold") private var sensitivityThreshold: Double = 3.0
    @AppStorage("showScore") private var showScore: Bool = false
    @State private var verdicts: [Verdict] = []

    var body: some View {
        NavigationStack {
            Group {
                if verdicts.isEmpty {
                    ContentUnavailableView(
                        "No Alerts",
                        systemImage: "checkmark.shield",
                        description: Text("Your inbox is clean")
                    )
                } else {
                    List {
                        ForEach(verdicts, id: \.messageId) { verdict in
                            MobileAlertRow(
                                verdict: verdict,
                                accountLabel: accountLabel(for: verdict),
                                showScore: showScore,
                                onDelete: { deleteVerdict(verdict) },
                                onMarkSafe: { markSafe(verdict) },
                                onBlock: { blockSender(verdict) }
                            )
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Alerts")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    statusIndicator
                }
            }
            .onAppear { refresh() }
            .refreshable { refresh() }
        }
    }

    @ViewBuilder
    private var statusIndicator: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(accountManager.isAnyMonitoring ? Color.green : Color.red)
                .frame(width: 8, height: 8)
            Text(accountManager.isAnyMonitoring ? "Monitoring" : "Stopped")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func refresh() {
        do {
            verdicts = try accountManager.verdictStore.recentVerdicts(limit: 50, minimumScore: Int(sensitivityThreshold))
        } catch {
            verdicts = []
        }
    }

    private func deleteVerdict(_ verdict: Verdict) {
        withAnimation {
            verdicts.removeAll { $0.messageId == verdict.messageId }
        }
        Task {
            await accountManager.deleteFromIMAP(verdict: verdict)
        }
    }

    private func markSafe(_ verdict: Verdict) {
        let senderDomain = ParsedEmail.extractDomain(from: verdict.from) ?? ""
        if !senderDomain.isEmpty {
            try? accountManager.allowlistStore.add(domain: senderDomain)
            try? accountManager.verdictStore.markDomainSafe(domain: senderDomain)
        }

        for reason in verdict.reasons where reason.checkName == "Link Text vs URL Mismatch Check" {
            if let hrefDomain = extractHrefDomain(from: reason.reason) {
                try? accountManager.trustedLinkDomainStore.add(domain: hrefDomain)
            }
        }

        withAnimation { refresh() }
    }

    private func blockSender(_ verdict: Verdict) {
        let senderDomain = ParsedEmail.extractDomain(from: verdict.from) ?? ""
        guard !senderDomain.isEmpty else { return }
        try? accountManager.userBlocklistStore.add(domain: senderDomain)
        // Also remove from allowlist if present
        try? accountManager.allowlistStore.remove(domain: senderDomain)
        deleteVerdict(verdict)
    }

    private func accountLabel(for verdict: Verdict) -> String? {
        guard let id = verdict.accountId,
              let uuid = UUID(uuidString: id),
              let account = accountManager.accounts.first(where: { $0.id == uuid }) else { return nil }
        return account.displayName
    }

    private func extractHrefDomain(from reason: String) -> String? {
        guard let range = reason.range(of: "points to \"") else { return nil }
        let after = reason[range.upperBound...]
        guard let endQuote = after.firstIndex(of: "\"") else { return nil }
        let domain = String(after[after.startIndex..<endQuote])
        let parts = domain.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return nil }
        return parts.suffix(2).joined(separator: ".")
    }
}

/// A single alert row for iOS.
struct MobileAlertRow: View {
    let verdict: Verdict
    let accountLabel: String?
    let showScore: Bool
    let onDelete: () -> Void
    let onMarkSafe: () -> Void
    let onBlock: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(threatColor)
                    .frame(width: 10, height: 10)
                Text(verdict.senderName)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .lineLimit(1)
                Spacer()
                Text(formattedDate)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            HStack {
                Text(verdict.senderEmail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if let label = accountLabel {
                    Spacer()
                    Text(label)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
            }

            Text(verdict.subject.isEmpty ? "(No Subject)" : verdict.subject)
                .font(.subheadline)
                .lineLimit(2)

            if let topReason = verdict.reasons.first {
                Label(topReason.reason, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(verdict.score >= 6 ? .red : .orange)
                    .lineLimit(2)
            }

            HStack {
                Button { onMarkSafe() } label: {
                    Label("Safe", systemImage: "checkmark.circle")
                        .font(.caption)
                }
                .buttonStyle(.bordered)
                .tint(.green)
                .controlSize(.small)

                Button { onBlock() } label: {
                    Label("Block", systemImage: "slash.circle")
                        .font(.caption)
                }
                .buttonStyle(.bordered)
                .tint(.orange)
                .controlSize(.small)

                Button(role: .destructive) { onDelete() } label: {
                    Label("Delete", systemImage: "trash")
                        .font(.caption)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)

                Spacer()

                if showScore {
                    Text("Score: \(verdict.score)")
                        .font(.caption2)
                        .fontWeight(.semibold)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(threatColor.opacity(0.15))
                        .foregroundStyle(threatColor)
                        .clipShape(Capsule())
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var threatColor: Color {
        switch verdict.score {
        case 0...2: return .green
        case 3...5: return .orange
        default: return .red
        }
    }

    private var formattedDate: String {
        let calendar = Calendar.current
        let date = verdict.receivedDate
        if calendar.isDateInToday(date) {
            return date.formatted(date: .omitted, time: .shortened)
        } else if calendar.isDateInYesterday(date) {
            return "Yesterday"
        } else {
            return date.formatted(.dateTime.month(.abbreviated).day())
        }
    }
}
