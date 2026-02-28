import SwiftUI

/// Reusable sheet for managing a list of domains (add, remove, search).
struct DomainListSheet: View {
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
        VStack(spacing: 0) {
            // Header
            HStack {
                Text(title)
                    .font(.headline)
                Spacer()
                Button { dismiss() } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 14)
            .padding(.top, 12)
            .padding(.bottom, 8)

            // Search
            TextField("Search…", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .font(.caption)
                .controlSize(.small)
                .padding(.horizontal, 14)
                .padding(.bottom, 6)

            Divider().padding(.horizontal, 10)

            // Domain list
            if filteredDomains.isEmpty {
                Spacer()
                Text(domains.isEmpty ? "No domains" : "No matches")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(filteredDomains, id: \.self) { domain in
                            HStack {
                                Text(domain)
                                    .font(.system(.caption, design: .monospaced))
                                Spacer()
                                Button(role: .destructive) {
                                    removeDomain(domain)
                                } label: {
                                    Image(systemName: "minus.circle")
                                        .font(.caption2)
                                }
                                .buttonStyle(.plain)
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 4)
                        }
                    }
                }
            }

            Divider().padding(.horizontal, 10)

            // Add row
            HStack(spacing: 6) {
                TextField("domain.com", text: $newDomain)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .controlSize(.small)
                    .onSubmit { addDomain() }
                Button("Add") { addDomain() }
                    .controlSize(.small)
                    .disabled(newDomain.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
        }
        .frame(width: 300, height: 400)
        .onAppear { reload() }
    }

    private func addDomain() {
        let domain = newDomain.trimmingCharacters(in: .whitespaces).lowercased()
        guard !domain.isEmpty else { return }
        try? onAdd(domain)
        newDomain = ""
        reload()
    }

    private func removeDomain(_ domain: String) {
        try? onRemove(domain)
        reload()
    }

    private func reload() {
        domains = (try? loadDomains())?.sorted() ?? []
    }
}
