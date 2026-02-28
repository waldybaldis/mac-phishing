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
        }

        // Extract href domains from link mismatch reasons and add to trusted link domains
        for reason in verdict.reasons where reason.checkName == "Link Text vs URL Mismatch Check" {
            if let hrefDomain = extractHrefDomain(from: reason.reason) {
                try? accountManager.trustedLinkDomainStore.add(domain: hrefDomain)
            }
        }

        try? accountManager.verdictStore.updateAction(messageId: verdict.messageId, action: .markedSafe)
        withAnimation {
            verdicts.removeAll { $0.messageId == verdict.messageId }
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
        VStack(alignment: .leading, spacing: 0) {
            // Main content area
            VStack(alignment: .leading, spacing: 6) {
                // Row 1: Threat indicator + Sender name + Date
                HStack(alignment: .center, spacing: 8) {
                    threatBadge
                    Text(verdict.senderName)
                        .font(.system(.body, weight: .semibold))
                        .lineLimit(1)
                    Spacer()
                    Text(formattedDate)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                // Row 2: Sender email
                Text(verdict.senderEmail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)

                // Row 3: Subject
                Text(verdict.subject.isEmpty ? "(No Subject)" : verdict.subject)
                    .font(.subheadline)
                    .lineLimit(2)

                // Row 4: Top reason
                if let topReason = verdict.reasons.first {
                    Label(topReason.reason, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(reasonColor)
                        .lineLimit(2)
                }

                // Row 5: Actions (shown on hover or when selected)
                if isHovering || isSelected {
                    HStack(spacing: 12) {
                        Button {
                            onMarkSafe()
                        } label: {
                            Label("Mark Safe", systemImage: "checkmark.circle")
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.green)

                        Button {
                            onDelete()
                        } label: {
                            Label("Delete", systemImage: "trash")
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.red)

                        Spacer()

                        scoreBadge
                    }
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
        }
        .background(isSelected ? Color.accentColor.opacity(0.08) : (isHovering ? Color.primary.opacity(0.03) : Color.clear))
        .contentShape(Rectangle())
        .onTapGesture { onSelect() }
        .onHover { isHovering = $0 }
    }

    private var threatBadge: some View {
        Circle()
            .fill(threatColor)
            .frame(width: 10, height: 10)
    }

    private var scoreBadge: some View {
        Text("Score: \(verdict.score)")
            .font(.caption2)
            .fontWeight(.medium)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(threatColor.opacity(0.15))
            .foregroundStyle(threatColor)
            .clipShape(Capsule())
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
