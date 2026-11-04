import Foundation

/// Where encrypted records live (a database table, files, Keychain items…).
/// The rotation engine reads each record and writes back a re-encrypted copy.
public protocol EncryptedRecordStore: Sendable {
    func recordIDs() async throws -> [String]
    func load(_ id: String) async throws -> Data?
    func store(_ data: Data, for id: String) async throws
}

/// The result of a rotation or migration pass.
public struct RotationReport: Sendable, Equatable {
    public var activeKeyID: String
    public var migrated: [String] = []
    public var alreadyCurrent: [String] = []
    public var failed: [String: StorageError] = [:]
    public var retiredVersions: [Int] = []

    public var isComplete: Bool { failed.isEmpty }
}

/// Rotates a key and re-encrypts every record with the new version.
///
/// Rotation is recoverable: old versions stay decrypt-only until every record
/// has been migrated, and only then are they retired. If a pass is interrupted
/// (crash, cancellation, a record that fails), run `migrate(_:)` again; records
/// already on the new key are skipped.
public struct KeyRotationEngine: Sendable {
    public let keyManager: KeyManager
    public let keyName: String
    /// Associated data each record was encrypted with, by record id.
    public let associatedData: @Sendable (String) -> Data

    public init(keyManager: KeyManager, keyName: String = KeyManager.defaultKeyName,
                associatedData: @escaping @Sendable (String) -> Data = { _ in Data() }) {
        self.keyManager = keyManager
        self.keyName = keyName
        self.associatedData = associatedData
    }

    /// Creates a new key version, then migrates all records to it.
    public func rotateAndMigrate(_ store: some EncryptedRecordStore, retireWhenComplete: Bool = true) async throws -> RotationReport {
        try await keyManager.rotate(named: keyName)
        return try await migrate(store, retireWhenComplete: retireWhenComplete)
    }

    /// Re-encrypts every record not on the active version. Safe to run repeatedly.
    ///
    /// With `retireWhenComplete`, old versions are destroyed once every record in `store` is
    /// migrated. Only do that when `store` holds **all** data encrypted with `keyName`; if the
    /// same key also protects other data (files, another table), migrate those first or pass
    /// `false` and call `KeyManager.retire` yourself.
    public func migrate(_ store: some EncryptedRecordStore, retireWhenComplete: Bool = true) async throws -> RotationReport {
        let active = try await keyManager.currentKey(named: keyName).id
        var report = RotationReport(activeKeyID: active)
        for id in try await store.recordIDs() {
            try Task.checkCancellation()
            do {
                guard let sealed = try await store.load(id) else { continue }
                if try CipherEnvelope.keyID(of: sealed) == active {
                    report.alreadyCurrent.append(id)
                    continue
                }
                let aad = associatedData(id)
                let plaintext = try await keyManager.decrypt(sealed, associatedData: aad)
                let resealed = try await keyManager.encrypt(plaintext, keyName: keyName, associatedData: aad)
                try await store.store(resealed, for: id)
                report.migrated.append(id)
            } catch let error as StorageError {
                report.failed[id] = error
            }
        }
        if report.isComplete && retireWhenComplete {
            for version in try await keyManager.versions(named: keyName) where version.state == .decryptOnly {
                try await keyManager.retire(named: keyName, version: version.version)
                report.retiredVersions.append(version.version)
            }
        }
        return report
    }
}

/// A simple in-memory `EncryptedRecordStore`, for tests and small data sets.
public actor InMemoryRecordStore: EncryptedRecordStore {
    private var records: [String: Data]

    public init(_ records: [String: Data] = [:]) {
        self.records = records
    }

    public func recordIDs() -> [String] { records.keys.sorted() }
    public func load(_ id: String) -> Data? { records[id] }
    public func store(_ data: Data, for id: String) { records[id] = data }
    public func all() -> [String: Data] { records }
}

/// Stores encrypted records as Keychain items in a `SecureStorage` namespace.
public struct SecureStorageRecordStore: EncryptedRecordStore {
    public let storage: SecureStorage

    public init(storage: SecureStorage) {
        self.storage = storage
    }

    public func recordIDs() async throws -> [String] { try await storage.allKeys() }
    public func load(_ id: String) async throws -> Data? { try await storage.retrieveData(id) }
    public func store(_ data: Data, for id: String) async throws { try await storage.saveData(data, forKey: id) }
}
