import SwiftUI

/// Displays recent phishing alerts.
struct AlertsListView: View {
    @State private var alerts: [AlertItem] = AlertItem.sampleAlerts

    var body: some View {
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
    let id = UUID()
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

    /// Sample data for development preview.
    static let sampleAlerts: [AlertItem] = [
        AlertItem(
            messageId: "msg-001",
            senderDomain: "fedrex.com",
            subject: "Your package is waiting for delivery",
            score: 9,
            topReason: "Domain fedrex.com found in phishing blacklist",
            timestamp: Date().addingTimeInterval(-300)
        ),
        AlertItem(
            messageId: "msg-002",
            senderDomain: "secure-banking.xyz",
            subject: "Urgent: Verify your account now",
            score: 6,
            topReason: "Suspicious TLD .xyz found in sender domain",
            timestamp: Date().addingTimeInterval(-3600)
        ),
        AlertItem(
            messageId: "msg-003",
            senderDomain: "notifications.amaz0n.com",
            subject: "Order confirmation #38291",
            score: 4,
            topReason: "SPF softfail — sender authentication failed",
            timestamp: Date().addingTimeInterval(-7200)
        ),
    ]
}
