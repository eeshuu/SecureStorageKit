import Foundation

/// Partitions secrets by account or tenant, each in its own namespace, and
/// removes everything belonging to an account in one call.
///
/// ```swift
/// let vault = MultiAccountVault(configuration: .init(service: "my-app"))
/// let alice = try await vault.storage(for: "alice")
/// try await alice.save("pin", forKey: "card-pin")
/// try await vault.remove(account: "alice")   // wipes only Alice's items
/// ```
public actor MultiAccountVault {
    private let index: SecureStorage
    private let template: StorageConfiguration
    private let backend: any KeychainBackend

    private static let indexKey = "accounts"

    /// - Parameter configuration: Shared settings; its namespace prefixes every account namespace.
    public init(configuration: StorageConfiguration, backend: any KeychainBackend = SystemKeychain()) {
        self.template = configuration
        self.backend = backend
        self.index = SecureStorage(configuration: configuration.namespaced("\(configuration.namespace).index"), backend: backend)
    }

    /// Storage for one account, registering the account if it's new.
    public func storage(for account: String) async throws -> SecureStorage {
        guard !account.isEmpty else { throw StorageError.invalidConfiguration("account must not be empty") }
        var accounts = try await self.accounts()
        if !accounts.contains(account) {
            accounts.append(account)
            try await index.save(accounts, forKey: Self.indexKey)
        }
        return storageWithoutRegistering(account)
    }

    /// Registered accounts, in the order they were added.
    public func accounts() async throws -> [String] {
        try await index.retrieve(Self.indexKey, as: [String].self) ?? []
    }

    /// Deletes every item of one account and unregisters it.
    public func remove(account: String) async throws {
        try await storageWithoutRegistering(account).clearAll()
        var accounts = try await self.accounts()
        accounts.removeAll { $0 == account }
        try await index.save(accounts, forKey: Self.indexKey)
    }

    /// Deletes every account's items and the account index.
    public func removeAll() async throws {
        for account in try await accounts() {
            try await storageWithoutRegistering(account).clearAll()
        }
        try await index.clearAll()
    }

    private func storageWithoutRegistering(_ account: String) -> SecureStorage {
        let encoded = account.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? account
        return SecureStorage(configuration: template.namespaced("\(template.namespace).acct.\(encoded)"), backend: backend)
    }
}
