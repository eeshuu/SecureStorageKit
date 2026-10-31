import SecureStorageKit
import SwiftUI

struct CryptoDemoView: View {
    @State private var plaintext = "Patient record #1042"
    @State private var sealed: Data?
    @State private var decrypted = ""
    @State private var versions: [KeyVersion] = []
    @State private var status = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("AES-256-GCM") {
                    TextField("Plaintext", text: $plaintext)
                    Button("Encrypt") {
                        run {
                            sealed = try await Demo.keys.encrypt(Data(plaintext.utf8), associatedData: Data("record-1042".utf8))
                            decrypted = ""
                            return "Encrypted with \(try CipherEnvelope.keyID(of: sealed!))."
                        }
                    }
                    if let sealed {
                        Text(sealed.base64EncodedString())
                            .font(.caption2.monospaced())
                            .lineLimit(4)
                            .foregroundStyle(.secondary)
                        Button("Decrypt") {
                            run {
                                decrypted = String(decoding: try await Demo.keys.decrypt(sealed, associatedData: Data("record-1042".utf8)), as: UTF8.self)
                                return "Decrypted and verified."
                            }
                        }
                        Button("Flip one byte, then decrypt") {
                            run {
                                var tampered = sealed
                                tampered[tampered.count - 1] ^= 1
                                _ = try await Demo.keys.decrypt(tampered, associatedData: Data("record-1042".utf8))
                                return "Unexpectedly succeeded."
                            }
                        }
                    }
                    if !decrypted.isEmpty { LabeledContent("Decrypted", value: decrypted) }
                }
                Section {
                    ForEach(versions, id: \.version) { version in
                        LabeledContent("default#\(version.version)", value: version.state.rawValue)
                    }
                    Button("Rotate key") { run { "Now on version \(try await Demo.keys.rotate().version). Old data still decrypts." } }
                    Button("Migrate sample record and retire old keys") {
                        run {
                            guard let sealed else { return "Encrypt something first." }
                            let store = InMemoryRecordStore(["record-1042": sealed])
                            let engine = KeyRotationEngine(keyManager: Demo.keys) { Data($0.utf8) }
                            let report = try await engine.migrate(store)
                            self.sealed = await store.load("record-1042")
                            return "Migrated \(report.migrated.count), retired \(report.retiredVersions.map(String.init).joined(separator: ", "))."
                        }
                    }
                } header: {
                    Text("Key versions")
                }
                if !status.isEmpty {
                    Section { Text(status).font(.callout).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Encryption")
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
        versions = (try? await Demo.keys.versions()) ?? []
    }
}
