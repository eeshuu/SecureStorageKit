import SecureStorageKit
import SwiftUI

struct TokenDemoView: View {
    @State private var account = "alice"
    @State private var tokens: TokenSet?
    @State private var accounts: [String] = []
    @State private var status = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Account") {
                    TextField("Account", text: $account)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                    Button("Sign in (token expires in 15 s)") {
                        run {
                            try await Demo.tokens.save(TokenSet(accessToken: "at_initial", refreshToken: "rt_initial", expiresIn: 15), for: account)
                            try await Demo.tokens.sessionStorage(for: account).save("1234", forKey: "card-pin")
                            return "Signed in. A session secret was stored too."
                        }
                    }
                    Button("Get valid access token") {
                        run {
                            let token = try await Demo.tokens.validAccessToken(for: account)
                            return "Access token: \(token)"
                        }
                    }
                    Button("Log out", role: .destructive) {
                        run { try await Demo.tokens.logout(account: account); return "Tokens and session secrets removed." }
                    }
                }
                if let tokens {
                    Section("Stored (printed safely)") {
                        Text(String(describing: tokens)).font(.caption.monospaced())
                        if let expiresAt = tokens.expiresAt {
                            LabeledContent("Expires", value: expiresAt.formatted(date: .omitted, time: .standard))
                        }
                    }
                }
                Section("Signed-in accounts") {
                    if accounts.isEmpty { Text("None").foregroundStyle(.secondary) }
                    ForEach(accounts, id: \.self) { Text($0) }
                }
                if !status.isEmpty {
                    Section { Text(status).font(.callout).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Tokens")
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
        tokens = try? await Demo.tokens.tokens(for: account)
        accounts = (try? await Demo.tokens.accounts()) ?? []
    }
}
