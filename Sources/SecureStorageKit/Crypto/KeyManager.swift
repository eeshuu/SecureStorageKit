import CryptoKit
import Foundation

/// One version of a named key.
public struct KeyVersion: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        /// Used for new encryption.
        case active
        /// Replaced by a newer version; still decrypts existing data until migrated.
        case decryptOnly
        /// Key material destroyed; data still encrypted with it can't be read.
        case retired
    }

    public let version: Int
    public let createdAt: Date
    public internal(set) var state: State
}

struct KeyRing: Codable, Sendable {
    var name: String
    var versions: [KeyVersion]

    var current: KeyVersion? { versions.last { $0.state == .active } }
}

/// Creates, stores, rotates and retires named AES-256 keys in the Keychain.
///
/// Key ids have the form `"<name>#<version>"` and are written into every
/// envelope, so data encrypted with an older version stays readable after
/// rotation until it is migrated and the old version is retired.
///
/// ```swift
/// let keys = KeyManager(storage: SecureStorage(service: "my-app", namespace: "keys"))
/// let sealed = try await keys.encrypt(Data("hello".utf8))
/// let plain = try await keys.decrypt(sealed)
/// try await keys.rotate()
/// ```
public actor KeyManager {
    public static let defaultKeyName = "default"

    private let storage: SecureStorage
    private let protection: ItemProtection
    private let encryption = EncryptionManager()
    private var rings: [String: KeyRing] = [:]
    private var loading: [String: Task<KeyRing, Error>] = [:]

    /// - Parameters:
    ///   - storage: Where key material is kept. Use a dedicated namespace.
    ///   - protection: Authentication required to load key material.
    public init(storage: SecureStorage, protection: ItemProtection = .none) {
        self.storage = storage
        self.protection = protection
    }

    // MARK: Lifecycle

    /// The active key for `name`, creating version 1 if none exists.
    public func currentKey(named name: String = defaultKeyName) async throws -> (id: String, key: SymmetricKey) {
        var ring = try await loadRing(name)
        if ring.current == nil {
            ring = try await addVersion(to: ring)
        }
        let version = ring.current!.version
        return (Self.keyID(name, version), try await material(name, version))
    }

    /// The key for an id such as `"default#2"`. Throws `.keyRetired` for retired versions.
    public func key(withID id: String) async throws -> SymmetricKey {
        guard let (name, version) = Self.parse(id) else { throw StorageError.keyNotFound(id: id) }
        let ring = try await loadRing(name)
        guard let info = ring.versions.first(where: { $0.version == version }) else { throw StorageError.keyNotFound(id: id) }
        guard info.state != .retired else { throw StorageError.keyRetired(id: id) }
        return try await material(name, version)
    }

    /// Creates a new active version; the previous one becomes decrypt-only.
    @discardableResult
    public func rotate(named name: String = defaultKeyName) async throws -> KeyVersion {
        let ring = try await addVersion(to: try await loadRing(name))
        emit(.keyRotate, name)
        return ring.current!
    }

    /// Destroys a decrypt-only version's key material. Call it once no data
    /// uses the version (see `KeyRotationEngine`).
    public func retire(named name: String = defaultKeyName, version: Int) async throws {
        var ring = try await loadRing(name)
        guard let index = ring.versions.firstIndex(where: { $0.version == version }) else {
            throw StorageError.keyNotFound(id: Self.keyID(name, version))
        }
        guard ring.versions[index].state != .active else {
            throw StorageError.invalidConfiguration("rotate before retiring the active key")
        }
        ring.versions[index].state = .retired
        try await saveRing(ring)
        try await storage.delete(Self.materialKey(name, version))
        emit(.keyRetire, name)
    }

    /// Retires every decrypt-only version of `name`.
    public func retireInactiveVersions(named name: String = defaultKeyName) async throws {
        for info in try await loadRing(name).versions where info.state == .decryptOnly {
            try await retire(named: name, version: info.version)
        }
    }

    /// All versions of `name`, oldest first.
    public func versions(named name: String = defaultKeyName) async throws -> [KeyVersion] {
        try await loadRing(name).versions
    }

    /// Deletes every version of `name`. Data encrypted with it becomes unreadable.
    public func destroy(named name: String = defaultKeyName) async throws {
        let ring = try await loadRing(name)
        for info in ring.versions { try await storage.delete(Self.materialKey(name, info.version)) }
        try await storage.delete(Self.ringKey(name))
        rings[name] = nil
    }

    // MARK: Encrypt / decrypt

    /// Encrypts with the active version of `keyName`.
    public func encrypt(_ plaintext: Data, keyName: String = defaultKeyName, associatedData: Data = Data()) async throws -> Data {
        let (id, key) = try await currentKey(named: keyName)
        let sealed = try encryption.seal(plaintext, using: key, keyID: id, associatedData: associatedData)
        emit(.encrypt, keyName)
        return sealed
    }

    /// Decrypts with whichever key version the envelope names.
    public func decrypt(_ sealed: Data, associatedData: Data = Data()) async throws -> Data {
        let envelope = try CipherEnvelope(serialized: sealed)
        let key = try await key(withID: envelope.keyID)
        let plaintext = try encryption.decrypt(envelope, using: key, associatedData: associatedData)
        emit(.decrypt, Self.parse(envelope.keyID)?.name)
        return plaintext
    }

    /// True if `sealed` was encrypted with the active version of its key.
    public func isCurrent(_ sealed: Data) async throws -> Bool {
        let id = try CipherEnvelope.keyID(of: sealed)
        guard let (name, _) = Self.parse(id) else { return false }
        return try await currentKey(named: name).id == id
    }

    /// An HKDF-derived sub-key of the active version, for example one per account.
    public func derivedKey(named name: String = defaultKeyName, salt: Data = Data(), info: Data) async throws -> SymmetricKey {
        EncryptionManager.deriveKey(from: try await currentKey(named: name).key, salt: salt, info: info)
    }

    // MARK: Internals

    static func keyID(_ name: String, _ version: Int) -> String { "\(name)#\(version)" }

    static func parse(_ id: String) -> (name: String, version: Int)? {
        guard let hash = id.lastIndex(of: "#"), let version = Int(id[id.index(after: hash)...]) else { return nil }
        return (String(id[..<hash]), version)
    }

    private static func ringKey(_ name: String) -> String { "ring.\(name)" }
    private static func materialKey(_ name: String, _ version: Int) -> String { "key.\(name).\(version)" }

    private func loadRing(_ name: String) async throws -> KeyRing {
        guard !name.isEmpty, !name.contains("#") else { throw StorageError.invalidConfiguration("key name must be non-empty and must not contain '#'") }
        if let ring = rings[name] { return ring }
        if let task = loading[name] { return try await task.value }
        let storage = self.storage
        let task = Task { try await storage.retrieve(Self.ringKey(name), as: KeyRing.self) ?? KeyRing(name: name, versions: []) }
        loading[name] = task
        defer { loading[name] = nil }
        let ring = try await task.value
        if rings[name] == nil { rings[name] = ring }
        return rings[name]!
    }

    private func saveRing(_ ring: KeyRing) async throws {
        try await storage.save(ring, forKey: Self.ringKey(ring.name))
        rings[ring.name] = ring
    }

    private func addVersion(to ring: KeyRing) async throws -> KeyRing {
        var ring = ring
        let version = (ring.versions.map(\.version).max() ?? 0) + 1
        let key = EncryptionManager.generateKey()
        let bytes = key.withUnsafeBytes { Data($0) }
        try await storage.saveData(bytes, forKey: Self.materialKey(ring.name, version), protection: protection)
        for index in ring.versions.indices where ring.versions[index].state == .active {
            ring.versions[index].state = .decryptOnly
        }
        ring.versions.append(KeyVersion(version: version, createdAt: Date(), state: .active))
        try await saveRing(ring)
        if version == 1 { emit(.keyCreate, ring.name) }
        return ring
    }

    private func material(_ name: String, _ version: Int) async throws -> SymmetricKey {
        guard let bytes = try await storage.retrieveData(Self.materialKey(name, version)) else {
            throw StorageError.keyNotFound(id: Self.keyID(name, version))
        }
        let key = SymmetricKey(data: bytes)
        try EncryptionManager.validate(key)
        return key
    }

    private func emit(_ operation: StorageEvent.Operation, _ name: String?) {
        storage.configuration.eventHandler?(StorageEvent(operation: operation, namespace: storage.configuration.namespace, key: name, outcome: .success))
    }
}
