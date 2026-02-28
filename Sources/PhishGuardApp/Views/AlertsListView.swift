import SwiftUI
import PhishGuardCore

/// Displays recent phishing alerts from the verdict database.
struct AlertsListView: View {
    let verdictStore: VerdictStore
    @State private var alerts: [AlertItem] = []

    var body: some View {
        Group {
            if alerts.isEmpty {
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
                List(alerts) { alert in
                    AlertRow(alert: alert)
                }
                .listStyle(.plain)
            }
        }
        .onAppear { refresh() }
    }

    private func refresh() {
        do {
            let verdicts = try verdictStore.recentVerdicts(limit: 50, minimumScore: 3)
            alerts = verdicts.map { AlertItem(verdict: $0) }
        } catch {
            alerts = []
        }
    }
}

/// A single alert row in the list.
struct AlertRow: View {
    let alert: AlertItem

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(alert.threatColor)
                    .frame(width: 10, height: 10)
                Text(alert.senderDomain)
                    .font(.system(.body, design: .monospaced))
                    .fontWeight(.medium)
                Spacer()
                Text("Score: \(alert.score)")
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(alert.threatColor.opacity(0.15))
                    .clipShape(Capsule())
            }

            Text(alert.subject)
                .font(.subheadline)
                .lineLimit(1)
                .foregroundStyle(.secondary)

            Text(alert.topReason)
                .font(.caption)
                .foregroundStyle(.orange)
                .lineLimit(2)

            HStack {
                Text(alert.timestamp, style: .relative)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                Spacer()
                Button("Mark Safe") {
                    // Add to allowlist
                }
                .font(.caption2)
                .buttonStyle(.plain)
                .foregroundStyle(.blue)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Model for an alert item displayed in the list.
struct AlertItem: Identifiable {
    let id: String
    let messageId: String
    let senderDomain: String
    let subject: String
    let score: Int
    let topReason: String
    let timestamp: Date

    var threatColor: Color {
        switch score {
        case 0...2: return .green
        case 3...5: return .orange
        default: return .red
        }
    }

    init(verdict: Verdict) {
        self.id = verdict.messageId
        self.messageId = verdict.messageId
        self.senderDomain = Self.extractDomain(from: verdict.messageId)
        self.subject = verdict.messageId // messageId is what we have; subject isn't stored in Verdict
        self.score = verdict.score
        self.topReason = verdict.reasons.first?.reason ?? "Suspicious content detected"
        self.timestamp = verdict.timestamp
    }

    private static func extractDomain(from messageId: String) -> String {
        if let atIndex = messageId.firstIndex(of: "@") {
            let afterAt = messageId[messageId.index(after: atIndex)...]
            let domain = afterAt.trimmingCharacters(in: CharacterSet(charactersIn: ">"))
            return domain
        }
        return messageId
    }
}
