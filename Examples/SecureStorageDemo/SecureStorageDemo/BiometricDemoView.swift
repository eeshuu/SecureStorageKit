import SecureStorageKit
import SwiftUI

struct BiometricDemoView: View {
    @State private var secret = "My recovery phrase"
    @State private var revealed: String?
    @State private var status = ""
    @State private var protection = ItemProtection.biometryCurrentSetOrPasscode

    private let biometrics = BiometricManager()
    private let options: [ItemProtection] = [.biometryCurrentSet, .biometryCurrentSetOrPasscode, .biometryAny, .userPresence]

    var body: some View {
        NavigationStack {
            Form {
                Section("This device") {
                    LabeledContent("Biometry", value: biometrics.biometryType.rawValue)
                    LabeledContent("Availability", value: describe(biometrics.availability()))
                }
                Section {
                    TextField("Secret", text: $secret)
                    Picker("Protection", selection: $protection) {
                        ForEach(options, id: \.self) { Text($0.description).tag($0) }
                    }
                    Button("Save to vault") {
                        run {
                            try await Demo.vault.save(secret, forKey: "secret", protection: protection)
                            revealed = nil
                            return "Saved. The Keychain will ask for authentication on every read."
                        }
                    }
                } footer: {
                    Text("Protection is enforced by the Keychain item itself, not by a separate prompt. With biometryCurrentSet, adding a face or finger makes the item unreadable.")
                }
                Section {
                    Button("Read with Face ID / Touch ID") {
                        run {
                            revealed = try await Demo.vault.retrieve("secret", as: String.self,
                                                                     prompt: AuthenticationPrompt(reason: "Unlock your secret", cancelTitle: "Not now"))
                            return revealed == nil ? "The vault is empty (or was invalidated)." : "Unlocked."
                        }
                    }
                    Button("Read without UI") {
                        run {
                            revealed = try await Demo.vault.retrieve("secret", as: String.self, prompt: .noInteraction)
                            return "Read without prompting."
                        }
                    }
                    Button("Delete", role: .destructive) { run { try await Demo.vault.clearAll(); revealed = nil; return "Vault cleared." } }
                }
                if let revealed {
                    Section("Revealed") { Text(revealed).font(.body.monospaced()) }
                }
                if !status.isEmpty {
                    Section { Text(status).font(.callout).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Biometrics")
        }
    }

    private func run(_ action: @escaping () async throws -> String) {
        Task {
            do { status = try await action() } catch { status = error.demoMessage }
        }
    }

    private func describe(_ availability: BiometricAvailability) -> String {
        switch availability {
        case .available: "Ready"
        case .notEnrolled: "Not enrolled"
        case .lockedOut: "Locked out"
        case .passcodeNotSet: "No passcode"
        case .notSupported: "Not supported"
        }
    }
}
