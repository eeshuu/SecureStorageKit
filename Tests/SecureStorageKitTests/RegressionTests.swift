import Foundation
import Testing
@testable import SecureStorageKit

// Regression tests for the issues fixed in 1.0.1.

private struct NoteV1: VersionedCodable {
    static let schemaVersion = 1
    var text: String
}

private struct NoteV2: VersionedCodable, Equatable {
    static let schemaVersion = 2
    var text: String
    var pinned: Bool

    static func migrate(from version: Int, data: Data, serializer: any StorageSerializer) throws -> NoteV2 {
        NoteV2(text: try serializer.decode(NoteV1.self, from: data).text, pinned: false)
    }
}

/// Wraps `InMemoryKeychain` and fails chosen `add` calls, like the real Keychain does for
/// `whenUnlocked` items while the device is locked (deleting still works then).
private final class FailingAddBackend: KeychainBackend, @unchecked Sendable {
    let inner = InMemoryKeychain()
    private let lock = NSLock()
    private var adds = 0
    /// 1-based numbers of the adds that fail, counted from when it was set.
    var failingAdds: Set<Int> = [] {
        didSet { lock.sync { adds = 0 } }
    }

    func add(_ request: KeychainWriteRequest) throws {
        let n = lock.sync { adds += 1; return adds }
        if failingAdds.contains(n) { throw StorageError.interactionNotAllowed }
        try inner.add(request)
    }
    func read(_ key: KeychainItemKey, prompt: AuthenticationPrompt?) throws -> Data { try inner.read(key, prompt: prompt) }
    func exists(_ key: KeychainItemKey) throws -> Bool { try inner.exists(key) }
    func delete(_ key: KeychainItemKey) throws -> Bool { try inner.delete(key) }
    func accounts(service: String, accessGroup: String?) throws -> [String] { try inner.accounts(service: service, accessGroup: accessGroup) }
}

private struct SlowRefresher: TokenRefresher {
    func refreshTokens(using refreshToken: String, account: String) async throws -> TokenSet {
        // Ignores cancellation, like most networking code.
        try? await Task.sleep(nanoseconds: 200_000_000)
        return TokenSet(accessToken: "new", refreshToken: "r2", expiresIn: 3600)
    }
}

@Suite("1.0.1 regressions")
struct RegressionTests {
    // MARK: Versioned migration keeps protection

    @Test func versionedMigrationKeepsItemProtection() async throws {
        let mock = InMemoryKeychain()
        let storage = makeStorage(backend: mock)
        try await storage.saveVersioned(NoteV1(text: "secret"), forKey: "note", protection: .biometryCurrentSet)

        let migrated = try await storage.retrieveVersioned("note", as: NoteV2.self)
        #expect(migrated == .some(NoteV2(text: "secret", pinned: false)))
        #expect(mock.protection(of: try storage.itemKey("note")) == .biometryCurrentSet)

        // The record was rewritten in the new schema, and reading it still needs authentication.
        let prompts = mock.promptCount
        #expect(try await storage.retrieveVersioned("note", as: NoteV2.self)?.text == "secret")
        #expect(mock.promptCount == prompts + 1)
    }

    @Test func migrationWithoutInPlaceUpdateLeavesRecordUntouched() async throws {
        let backend = FailingAddBackend()   // uses the protocol's default updateData (returns false)
        let storage = SecureStorage(configuration: .init(service: "s"), backend: backend)
        try await storage.saveVersioned(NoteV1(text: "a"), forKey: "note", protection: .userPresence)
        #expect(try await storage.retrieveVersioned("note", as: NoteV2.self)?.text == "a")
        #expect(backend.inner.protection(of: try storage.itemKey("note")) == .userPresence)
        #expect(try await storage.retrieveVersioned("note", as: NoteV2.self)?.text == "a")
    }

    // MARK: Replacing never loses the old value

    @Test(arguments: [SaveMode.updateOnly, .upsert])
    func failedReplaceKeepsTheOldValue(mode: SaveMode) async throws {
        let backend = FailingAddBackend()
        let storage = SecureStorage(configuration: .init(service: "s"), backend: backend)
        try await storage.save("old-token", forKey: "t")
        backend.failingAdds = [1, 2, 3]   // device locked: every add fails
        await #expect(throws: StorageError.interactionNotAllowed) {
            try await storage.save("new-token", forKey: "t", mode: mode)
        }
        backend.failingAdds = []
        #expect(try await storage.retrieve("t", as: String.self) == "old-token")
    }

    @Test func interruptedReplaceIsReadFromStaging() async throws {
        let backend = FailingAddBackend()
        let storage = SecureStorage(configuration: .init(service: "s"), backend: backend)
        try await storage.save("v1", forKey: "t")
        // Staged add succeeds, old item deleted, final add fails.
        backend.failingAdds = [2]
        await #expect(throws: StorageError.self) { try await storage.update("v2", forKey: "t") }
        backend.failingAdds = []

        #expect(try await storage.retrieve("t", as: String.self) == "v2")
        #expect(try await storage.contains("t"))
        #expect(try await storage.allKeys() == ["t"])
        await #expect(throws: StorageError.duplicateItem) { try await storage.save("x", forKey: "t", mode: .insertOnly) }

        // The next save normalizes, and the staged copy is cleaned up.
        try await storage.save("v3", forKey: "t")
        #expect(try await storage.retrieve("t", as: String.self) == "v3")
        #expect(backend.inner.count == 1)
    }

    @Test func deleteAndClearRemoveStagedCopies() async throws {
        let backend = FailingAddBackend()
        let storage = SecureStorage(configuration: .init(service: "s"), backend: backend)
        try await storage.save("v1", forKey: "a")
        try await storage.save("v1", forKey: "b")
        backend.failingAdds = [2]
        _ = try? await storage.update("v2", forKey: "a")
        backend.failingAdds = []
        #expect(try await storage.delete("a"))
        #expect(try await storage.retrieve("a", as: String.self) == nil)

        backend.failingAdds = [2]
        _ = try? await storage.update("v2", forKey: "b")
        backend.failingAdds = []
        try await storage.clearAll()
        #expect(backend.inner.count == 0)
    }

    @Test func successfulReplaceLeavesNoStagingItem() async throws {
        let mock = InMemoryKeychain()
        let storage = makeStorage(backend: mock)
        try await storage.save("a", forKey: "k")
        try await storage.save("b", forKey: "k", protection: .biometryAny)
        try await storage.update("c", forKey: "k")
        #expect(mock.count == 1)
        #expect(try await storage.retrieve("k", as: String.self) == "c")
    }

    // MARK: Token store

    @Test func refreshRunningDuringLogoutDoesNotRestoreTokens() async throws {
        let store = SecureTokenStore(configuration: .init(service: "s", namespace: "tokens"), backend: InMemoryKeychain(),
                                     refresher: SlowRefresher())
        try await store.save(TokenSet(accessToken: "old", refreshToken: "r1", expiresIn: -10))
        let pending = Task { try await store.validAccessToken() }
        try await Task.sleep(nanoseconds: 50_000_000)
        try await store.logout()

        await #expect(throws: StorageError.itemNotFound) { try await pending.value }
        #expect(try await store.tokens() == nil)
        #expect(try await store.accounts().isEmpty)
    }

    @Test func accountNamesCannotReachAnotherAccountsSession() async throws {
        let store = SecureTokenStore(configuration: .init(service: "s", namespace: "tokens"), backend: InMemoryKeychain())
        try await store.save(TokenSet(accessToken: "mallory"), for: "session.alice")
        let aliceSession = try await store.sessionStorage(for: "alice")
        #expect(try await aliceSession.retrieve("tokens", as: TokenSet.self) == nil)
        #expect(try await aliceSession.allKeys().isEmpty)

        // Logging Alice out doesn't touch the other account.
        try await store.save(TokenSet(accessToken: "alice"), for: "alice")
        try await store.logout(account: "alice")
        #expect(try await store.tokens(for: "session.alice")?.accessToken == "mallory")
    }

    @Test func tokensSavedBy100AreMigratedOnFirstRead() async throws {
        let backend = InMemoryKeychain()
        let config = StorageConfiguration(service: "s", namespace: "tokens")
        // Where 1.0.0 stored the tokens of account "maya@example.com".
        let legacy = SecureStorage(configuration: config.namespaced("tokens.\(NamespaceEncoding.encode("maya@example.com"))"),
                                   backend: backend)
        try await legacy.save(TokenSet(accessToken: "kept", refreshToken: "r"), forKey: "tokens")

        let store = SecureTokenStore(configuration: config, backend: backend)
        #expect(try await store.tokens(for: "maya@example.com")?.accessToken == "kept")
        #expect(try await legacy.retrieve("tokens", as: TokenSet.self) == nil)
        #expect(try await store.tokens(for: "maya@example.com")?.accessToken == "kept")

        // Logout also clears anything still in the old location.
        try await legacy.save(TokenSet(accessToken: "stale"), forKey: "tokens")
        try await store.logout(account: "maya@example.com")
        #expect(try await legacy.retrieve("tokens", as: TokenSet.self) == nil)
    }

    // MARK: Hardening

    @Test func keyMaterialIsNeverOverwritten() async throws {
        let storage = makeStorage(namespace: "keys")
        let first = KeyManager(storage: storage)
        let sealed = try await first.encrypt(Data("hello".utf8))
        // A second manager with a stale view tries to create version 1 again.
        let second = KeyManager(storage: storage)
        let original = try await storage.retrieveData("key.default.1")
        await #expect(throws: StorageError.duplicateItem) {
            try await storage.saveData(Data(repeating: 7, count: 32), forKey: "key.default.1", mode: .insertOnly)
        }
        #expect(try await storage.retrieveData("key.default.1") == original)
        #expect(try await second.decrypt(sealed) == Data("hello".utf8))
    }

    @Test func fileVaultPrefixesAreRandom() throws {
        let a = try EncryptedFileVault.randomPrefix()
        let b = try EncryptedFileVault.randomPrefix()
        #expect(a.count == EncryptedFileVault.prefixSize)
        #expect(a != b)
    }
}
