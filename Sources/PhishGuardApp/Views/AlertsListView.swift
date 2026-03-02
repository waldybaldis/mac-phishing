import SwiftUI
import PhishGuardCore

/// Displays recent phishing alerts from the verdict database.
struct AlertsListView: View {
    let accountManager: AccountManager
    @AppStorage("sensitivityThreshold") private var sensitivityThreshold: Double = 3.0
    @AppStorage("showScore") private var showScore: Bool = false
    @State private var verdicts: [Verdict] = []
    @State private var selectedId: String?

    var body: some View {
        Group {
            if verdicts.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.shield")
                        .font(.largeTitle)
                        .foregroundStyle(.green)
                    Text("No alerts")
                        .font(.headline)
                    Text("Your inbox is clean")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(verdicts, id: \.messageId) { verdict in
                            AlertRow(
                                verdict: verdict,
                                accountLabel: accountLabel(for: verdict),
                                showScore: showScore,
                                isSelected: selectedId == verdict.messageId,
                                onSelect: { selectedId = verdict.messageId },
                                onDelete: { deleteVerdict(verdict) },
                                onMarkSafe: { markSafe(verdict) },
                                onBlock: { blockSender(verdict) }
                            )
                            Divider()
                        }
                    }
                }
            }
        }
        .onAppear { refresh() }
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
        let service = VerdictActionService(
            verdictStore: accountManager.verdictStore,
            allowlistStore: accountManager.allowlistStore,
            trustedLinkDomainStore: accountManager.trustedLinkDomainStore,
            userBlocklistStore: accountManager.userBlocklistStore
        )
        service.markSafe(verdict)
        withAnimation { refresh() }
    }

    private func blockSender(_ verdict: Verdict) {
        let service = VerdictActionService(
            verdictStore: accountManager.verdictStore,
            allowlistStore: accountManager.allowlistStore,
            trustedLinkDomainStore: accountManager.trustedLinkDomainStore,
            userBlocklistStore: accountManager.userBlocklistStore
        )
        service.blockSender(verdict)
        deleteVerdict(verdict)
    }

    private func accountLabel(for verdict: Verdict) -> String? {
        guard let id = verdict.accountId,
              let account = accountManager.accounts.first(where: { $0.id == id }) else { return nil }
        return account.discovered.name
    }
}

/// A single alert row styled like an email client message preview.
struct AlertRow: View {
    let verdict: Verdict
    let accountLabel: String?
    let showScore: Bool
    let isSelected: Bool
    let onSelect: () -> Void
    let onDelete: () -> Void
    let onMarkSafe: () -> Void
    let onBlock: () -> Void

    @State private var isHovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Row 1: Threat indicator + Sender name + Date
            HStack(alignment: .center, spacing: 6) {
                Circle()
                    .fill(threatColor)
                    .frame(width: 8, height: 8)
                Text(verdict.senderName)
                    .font(.system(.callout, weight: .semibold))
                    .lineLimit(1)
                Spacer()
                Text(formattedDate)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            // Row 2: Email address + account
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
            .padding(.leading, 14)

            // Row 3: Subject
            Text(verdict.subject.isEmpty ? "(No Subject)" : verdict.subject)
                .font(.caption)
                .lineLimit(1)
                .padding(.leading, 14)

            // Row 4: Top reason
            if let topReason = verdict.reasons.first {
                Label(topReason.reason, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2)
                    .foregroundStyle(reasonColor)
                    .lineLimit(2)
                    .padding(.leading, 14)
            }

            // Row 5: Actions (shown on hover or when selected)
            if isHovering || isSelected {
                HStack(spacing: 10) {
                    Button { onMarkSafe() } label: {
                        Label("Safe", systemImage: "checkmark.circle")
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.green)

                    Button { onBlock() } label: {
                        Label("Block", systemImage: "slash.circle")
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.orange)

                    Button { onDelete() } label: {
                        Label("Delete", systemImage: "trash")
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.red)

                    Spacer()

                    if showScore {
                        Text("\(verdict.score)")
                            .font(.caption2.weight(.bold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(threatColor.opacity(0.15))
                            .foregroundStyle(threatColor)
                            .clipShape(Capsule())
                    }
                }
                .padding(.leading, 14)
                .transition(.opacity)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(isSelected ? Color.accentColor.opacity(0.08) : (isHovering ? Color.primary.opacity(0.03) : Color.clear))
        .contentShape(Rectangle())
        .onTapGesture { onSelect() }
        .onHover { isHovering = $0 }
    }

    private var threatColor: Color {
        switch verdict.threatLevel {
        case .clean: return .green
        case .suspicious: return .orange
        case .phishing: return .red
        }
    }

    private var reasonColor: Color {
        verdict.threatLevel == .phishing ? .red : .orange
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
