import SwiftUI
import PhishGuardCore

/// Displays recent phishing alerts from the verdict database.
struct AlertsListView: View {
    let accountManager: AccountManager
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
                                isSelected: selectedId == verdict.messageId,
                                onSelect: { selectedId = verdict.messageId },
                                onDelete: { deleteVerdict(verdict) },
                                onMarkSafe: { markSafe(verdict) }
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
            verdicts = try accountManager.verdictStore.recentVerdicts(limit: 50, minimumScore: 3)
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
        // Add sender domain to allowlist so future emails from this sender skip analysis
        let senderDomain = ParsedEmail.extractDomain(from: verdict.from) ?? ""
        if !senderDomain.isEmpty {
            try? accountManager.allowlistStore.add(domain: senderDomain)
            // Mark all existing verdicts from this domain as safe too
            try? accountManager.verdictStore.markDomainSafe(domain: senderDomain)
        }

        // Extract href domains from link mismatch reasons and add to trusted link domains
        for reason in verdict.reasons where reason.checkName == "Link Text vs URL Mismatch Check" {
            if let hrefDomain = extractHrefDomain(from: reason.reason) {
                try? accountManager.trustedLinkDomainStore.add(domain: hrefDomain)
            }
        }

        // Refresh the full list so other alerts from the same sender disappear
        withAnimation {
            refresh()
        }
    }

    /// Extracts the href domain from a link mismatch reason string.
    /// Expected format: `Link displays "X" but actually points to "Y"`
    private func extractHrefDomain(from reason: String) -> String? {
        guard let range = reason.range(of: "points to \"") else { return nil }
        let after = reason[range.upperBound...]
        guard let endQuote = after.firstIndex(of: "\"") else { return nil }
        let domain = String(after[after.startIndex..<endQuote])
        // Extract base domain (take last 2 parts)
        let parts = domain.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return nil }
        return parts.suffix(2).joined(separator: ".")
    }
}

/// A single alert row styled like an email client message preview.
struct AlertRow: View {
    let verdict: Verdict
    let isSelected: Bool
    let onSelect: () -> Void
    let onDelete: () -> Void
    let onMarkSafe: () -> Void

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

            // Row 2: Email address
            Text(verdict.senderEmail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
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

                    Button { onDelete() } label: {
                        Label("Delete", systemImage: "trash")
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.red)

                    Spacer()

                    Text("\(verdict.score)")
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(threatColor.opacity(0.15))
                        .foregroundStyle(threatColor)
                        .clipShape(Capsule())
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
        switch verdict.score {
        case 0...2: return .green
        case 3...5: return .orange
        default: return .red
        }
    }

    private var reasonColor: Color {
        verdict.score >= 6 ? .red : .orange
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
