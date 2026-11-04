import Foundation

/// How `save` treats an existing item.
public enum SaveMode: Sendable {
    /// Insert, or replace an existing item.
    case upsert
    /// Insert only; throws `.duplicateItem` if the key exists.
    case insertOnly
    /// Replace only; throws `.itemNotFound` if the key doesn't exist.
    case updateOnly
}

/// The storage operations, as a protocol for dependency injection.
/// In tests, inject a `SecureStorage` backed by `InMemoryKeychain`.
public protocol SecureStoring: Sendable {
    func save<T: Encodable>(_ value: T, forKey key: String, protection: ItemProtection?,
                            accessibility: KeychainAccessibility?, mode: SaveMode) async throws
    func retrieve<T: Decodable>(_ key: String, as type: T.Type, prompt: AuthenticationPrompt?) async throws -> T?
    @discardableResult func delete(_ key: String) async throws -> Bool
    func contains(_ key: String) async throws -> Bool
    func allKeys() async throws -> [String]
    func clearAll() async throws
}

/// Keychain-backed storage for strings, data and Codable values.
///
/// ```swift
/// let storage = SecureStorage(service: "my-app")
/// try await storage.save("secret", forKey: "access_token")
/// let token = try await storage.retrieve("access_token", as: String.self)
/// try await storage.save("private", forKey: "vault", protection: .biometryCurrentSet)
/// let value = try await storage.retrieve("vault", as: String.self, authenticationReason: "Unlock secure data")
/// ```
///
/// Operations run one at a time on a private serial queue, so concurrent calls
/// never race and a Face ID prompt never blocks the main thread or Swift's
/// cooperative thread pool. Strings are stored as UTF-8, `Data` as raw bytes and
/// other Codable values through the configured serializer.
public final class SecureStorage: SecureStoring {
    public let configuration: StorageConfiguration
    let backend: any KeychainBackend
    private let queue: DispatchQueue

    /// Storage for `service` in `namespace`, using the real Keychain.
    public convenience init(service: String, namespace: String = "default") {
        self.init(configuration: StorageConfiguration(service: service, namespace: namespace))
    }

    /// Storage with full configuration. Pass `InMemoryKeychain()` as the backend in tests.
    /// Invalid configurations are reported by the first operation.
    public init(configuration: StorageConfiguration, backend: any KeychainBackend = SystemKeychain()) {
        self.configuration = configuration
        self.backend = backend
        self.queue = DispatchQueue(label: "SecureStorageKit.\(configuration.resolvedService).\(configuration.namespace)", qos: .userInitiated)
    }

    /// A storage instance for another namespace, sharing this one's settings and backend.
    public func namespaced(_ namespace: String) -> SecureStorage {
        SecureStorage(configuration: configuration.namespaced(namespace), backend: backend)
    }

    // MARK: - Save

    /// Saves a value. Strings and `Data` are stored as raw bytes; other values
    /// are encoded with the configured serializer.
    ///
    /// - Parameters:
    ///   - protection: Authentication required to read the item. Defaults to the configuration's.
    ///   - accessibility: When the item can be read. Defaults to the configuration's.
    ///   - mode: Insert, update or both.
    public func save<T: Encodable>(_ value: T, forKey key: String, protection: ItemProtection? = nil,
                                   accessibility: KeychainAccessibility? = nil, mode: SaveMode = .upsert) async throws {
        let data = try encode(value)
        try await saveData(data, forKey: key, protection: protection, accessibility: accessibility, mode: mode)
    }

    /// Saves raw bytes.
    public func saveData(_ data: Data, forKey key: String, protection: ItemProtection? = nil,
                         accessibility: KeychainAccessibility? = nil, mode: SaveMode = .upsert) async throws {
        let request = KeychainWriteRequest(
            key: try itemKey(key),
            data: data,
            accessibility: accessibility ?? configuration.accessibility,
            protection: protection ?? configuration.protection,
            synchronizable: configuration.synchronizable,
            label: configuration.service)
        let staging = try stagingKey(key)
        let backend = self.backend
        try await run(.save, key: key) {
            switch mode {
            case .insertOnly:
                // A staged copy left by an interrupted replace counts as an existing item.
                if try backend.exists(staging) { throw StorageError.duplicateItem }
                try backend.add(request)
            case .updateOnly:
                guard try backend.exists(request.key) || backend.exists(staging) else { throw StorageError.itemNotFound }
                try Self.replace(request, staging: staging, backend: backend)
            case .upsert:
                do {
                    try backend.add(request)
                    _ = try? backend.delete(staging)
                } catch StorageError.duplicateItem {
                    try Self.replace(request, staging: staging, backend: backend)
                }
            }
        }
    }

    /// Replaces an item without ever losing the old value to a failed write.
    ///
    /// Delete + add (not SecItemUpdate) so new protection and accessibility apply and
    /// replacing a protected item never prompts. The new value is first written to a
    /// staging slot: that proves the write can succeed (device locked, access control,
    /// entitlements) before the old item is deleted. If the final add still fails, the
    /// staged copy remains and reads fall back to it.
    static func replace(_ request: KeychainWriteRequest, staging: KeychainItemKey, backend: any KeychainBackend) throws {
        var staged = request
        staged.key = staging
        _ = try? backend.delete(staging)
        try backend.add(staged)
        if try backend.exists(request.key) { try backend.delete(request.key) }
        try backend.add(request)
        _ = try? backend.delete(staging)
    }

    /// Replaces an existing value. Throws `.itemNotFound` if the key doesn't exist.
    public func update<T: Encodable>(_ value: T, forKey key: String, protection: ItemProtection? = nil) async throws {
        try await save(value, forKey: key, protection: protection, mode: .updateOnly)
    }

    // MARK: - Retrieve

    /// Reads a value, or returns nil if the key doesn't exist.
    ///
    /// - Parameter authenticationReason: Shown in the Face ID / Touch ID prompt
    ///   when the item is protected.
    public func retrieve<T: Decodable>(_ key: String, as type: T.Type = T.self, authenticationReason: String? = nil) async throws -> T? {
        try await retrieve(key, as: type, prompt: authenticationReason.map { AuthenticationPrompt(reason: $0) })
    }

    /// Reads a value with full control over the authentication prompt.
    public func retrieve<T: Decodable>(_ key: String, as type: T.Type = T.self, prompt: AuthenticationPrompt?) async throws -> T? {
        guard let data = try await retrieveData(key, prompt: prompt) else { return nil }
        return try decode(type, from: data)
    }

    /// Reads raw bytes, or nil if the key doesn't exist.
    public func retrieveData(_ key: String, prompt: AuthenticationPrompt? = nil) async throws -> Data? {
        let itemKey = try itemKey(key)
        let staging = try stagingKey(key)
        let backend = self.backend
        return try await run(.read, key: key, outcome: { $0 == nil ? .notFound : .success }) { () -> Data? in
            do {
                return try backend.read(itemKey, prompt: prompt)
            } catch StorageError.itemNotFound {
                // The value of an interrupted replace lives in the staging slot.
                do { return try backend.read(staging, prompt: prompt) } catch StorageError.itemNotFound { return nil }
            }
        }
    }

    // MARK: - Versioned Codable

    /// Saves a model together with its schema version.
    public func saveVersioned<T: VersionedCodable>(_ value: T, forKey key: String, protection: ItemProtection? = nil) async throws {
        let payload = try encode(value)
        let envelope = try encode(RecordEnvelope(schema: T.schemaVersion, payload: payload))
        try await saveData(envelope, forKey: key, protection: protection)
    }

    /// Reads a model saved with `saveVersioned`, migrating older records and
    /// re-saving them in the current schema.
    public func retrieveVersioned<T: VersionedCodable>(_ key: String, as type: T.Type = T.self, prompt: AuthenticationPrompt? = nil,
                                                       onObsolete policy: ObsoleteRecordPolicy = .throw) async throws -> T? {
        guard let data = try await retrieveData(key, prompt: prompt) else { return nil }
        let envelope = try decode(RecordEnvelope.self, from: data)
        if envelope.schema == T.schemaVersion {
            return try decode(T.self, from: envelope.payload)
        }
        if envelope.schema > T.schemaVersion {
            throw StorageError.unsupportedSchemaVersion(envelope.schema)
        }
        do {
            guard envelope.schema >= T.minimumSupportedVersion else {
                throw StorageError.obsoleteRecord(foundVersion: envelope.schema, minimumSupported: T.minimumSupportedVersion)
            }
            let migrated = try T.migrate(from: envelope.schema, data: envelope.payload, serializer: configuration.serializer)
            try? await rewriteInPlace(key, data: try encode(RecordEnvelope(schema: T.schemaVersion, payload: try encode(migrated))),
                                      prompt: prompt)
            return migrated
        } catch StorageError.obsoleteRecord(let found, let minimum) {
            guard policy == .delete else { throw StorageError.obsoleteRecord(foundVersion: found, minimumSupported: minimum) }
            try await delete(key)
            return nil
        }
    }

    /// Stores the migrated record in the same item, keeping its protection and accessibility
    /// (saving it again would apply the configuration's defaults, which may be weaker).
    /// Best effort: if the backend can't update in place or the update fails, the old record
    /// stays and is migrated again on the next read.
    private func rewriteInPlace(_ key: String, data: Data, prompt: AuthenticationPrompt?) async throws {
        let itemKey = try itemKey(key)
        let staging = try stagingKey(key)
        let backend = self.backend
        try await run(.migrate, key: key) {
            let target = try backend.exists(itemKey) ? itemKey : staging
            _ = try backend.updateData(target, data: data, prompt: prompt)
        }
    }

    // MARK: - Delete, list, clear

    /// Deletes an item. Returns false if it didn't exist. Never prompts for authentication.
    @discardableResult
    public func delete(_ key: String) async throws -> Bool {
        let itemKey = try itemKey(key)
        let staging = try stagingKey(key)
        let backend = self.backend
        return try await run(.delete, key: key, outcome: { $0 ? .success : .notFound }) {
            let deleted = try backend.delete(itemKey)
            return try backend.delete(staging) || deleted
        }
    }

    /// True if the key exists. Never prompts for authentication.
    public func contains(_ key: String) async throws -> Bool {
        let itemKey = try itemKey(key)
        let staging = try stagingKey(key)
        let backend = self.backend
        return try await perform { try backend.exists(itemKey) || backend.exists(staging) }
    }

    /// The keys stored in this namespace, sorted.
    public func allKeys() async throws -> [String] {
        try configuration.validate()
        let (backend, service, group) = (backend, configuration.resolvedService, configuration.accessGroup)
        let prefixes = [configuration.accountPrefix, configuration.stagingPrefix]
        return try await run(.list, key: nil) {
            var keys = Set<String>()
            for account in try backend.accounts(service: service, accessGroup: group) {
                if let prefix = prefixes.first(where: account.hasPrefix) { keys.insert(String(account.dropFirst(prefix.count))) }
            }
            return keys.sorted()
        }
    }

    /// Deletes every item in this namespace, and nothing else: other namespaces,
    /// environments and Keychain items written by other code are untouched.
    public func clearAll() async throws {
        try configuration.validate()
        let (backend, service, group) = (backend, configuration.resolvedService, configuration.accessGroup)
        let prefixes = [configuration.accountPrefix, configuration.stagingPrefix]
        try await run(.clear, key: nil) {
            for account in try backend.accounts(service: service, accessGroup: group) where prefixes.contains(where: account.hasPrefix) {
                try backend.delete(KeychainItemKey(service: service, account: account, accessGroup: group))
            }
        }
    }

    // MARK: - Internals

    func itemKey(_ key: String) throws -> KeychainItemKey {
        try configuration.validate()
        guard !key.isEmpty else { throw StorageError.invalidConfiguration("key must not be empty") }
        return KeychainItemKey(service: configuration.resolvedService,
                               account: configuration.accountPrefix + key,
                               accessGroup: configuration.accessGroup)
    }

    /// Where a replace stages the new value before deleting the old one.
    func stagingKey(_ key: String) throws -> KeychainItemKey {
        var k = try itemKey(key)
        k.account = configuration.stagingPrefix + key
        return k
    }

    func encode<T: Encodable>(_ value: T) throws -> Data {
        if let string = value as? String { return Data(string.utf8) }
        if let data = value as? Data { return data }
        do {
            return try configuration.serializer.encode(value)
        } catch {
            throw StorageError.encodingFailed(type: String(describing: T.self))
        }
    }

    func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        if T.self == Data.self, let data = data as? T { return data }
        if T.self == String.self {
            guard let string = String(data: data, encoding: .utf8) as? T else {
                throw StorageError.decodingFailed(type: "String")
            }
            return string
        }
        do {
            return try configuration.serializer.decode(type, from: data)
        } catch {
            throw StorageError.decodingFailed(type: String(describing: T.self))
        }
    }

    private func run<R: Sendable>(_ operation: StorageEvent.Operation, key: String?,
                                  outcome: (R) -> StorageEvent.Outcome = { _ in .success },
                                  _ work: @escaping @Sendable () throws -> R) async throws -> R {
        do {
            let result = try await perform(work)
            emit(operation, key: key, outcome: outcome(result))
            return result
        } catch let error as StorageError {
            emit(operation, key: key, outcome: .failure(error))
            throw error
        }
    }

    private func perform<R: Sendable>(_ work: @escaping @Sendable () throws -> R) async throws -> R {
        try Task.checkCancellation()
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result {
                    do {
                        return try work()
                    } catch let error as StorageError {
                        throw error
                    } catch {
                        throw StorageError.unexpectedStatus(-1)
                    }
                })
            }
        }
    }

    private func emit(_ operation: StorageEvent.Operation, key: String?, outcome: StorageEvent.Outcome) {
        configuration.eventHandler?(StorageEvent(operation: operation, namespace: configuration.namespace, key: key, outcome: outcome))
    }
}
