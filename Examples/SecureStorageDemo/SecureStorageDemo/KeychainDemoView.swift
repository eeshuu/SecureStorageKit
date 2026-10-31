import SecureStorageKit
import SwiftUI

struct KeychainDemoView: View {
    @State private var key = "access_token"
    @State private var value = ""
    @State private var keys: [String] = []
    @State private var status = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Item") {
                    TextField("Key", text: $key)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Value", text: $value)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section {
                    Button("Save") { run { try await Demo.storage.save(value, forKey: key); return "Saved “\(key)”." } }
                    Button("Read") {
                        run {
                            let stored = try await Demo.storage.retrieve(key, as: String.self)
                            value = stored ?? ""
                            return stored == nil ? "No item for “\(key)”." : "Read “\(key)”."
                        }
                    }
                    Button("Delete") { run { try await Demo.storage.delete(key) ? "Deleted “\(key)”." : "Nothing to delete." } }
                    Button("Clear namespace", role: .destructive) { run { try await Demo.storage.clearAll(); return "Cleared the demo namespace." } }
                }
                if !status.isEmpty {
                    Section { Text(status).font(.callout).foregroundStyle(.secondary) }
                }
                Section("Keys in namespace “demo”") {
                    if keys.isEmpty { Text("None").foregroundStyle(.secondary) }
                    ForEach(keys, id: \.self) { Text($0).font(.body.monospaced()) }
                }
                Section("Recent events (no secrets)") {
                    ForEach(Array(Demo.audit.events().suffix(6).reversed().enumerated()), id: \.offset) { _, event in
                        HStack {
                            Text(event.operation.rawValue).font(.caption.monospaced())
                            Spacer()
                            Text(event.keyFingerprint ?? "–").font(.caption2.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Keychain")
            .task { await refresh() }
        }
    }

    private func run(_ action: @escaping () async throws -> String) {
        Task {
            do { status = try await action() } catch { status = error.demoMessage }
            await refresh()
        }
    }

    private func refresh() async {
        keys = (try? await Demo.storage.allKeys()) ?? []
    }
}
