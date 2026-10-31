import CryptoKit
import Foundation
import Testing
@testable import SecureStorageKit

func makeStorage(_ namespace: String, _ backend: InMemoryKeychain, events: (@Sendable (StorageEvent) -> Void)? = nil) -> SecureStorage {
    makeStorage(namespace: namespace, backend: backend, events: events)
}

@Suite("Encrypted file vault")
struct FileVaultTests {
    let backend = InMemoryKeychain()
    var vault: EncryptedFileVault { EncryptedFileVault(keyManager: KeyManager(storage: makeStorage("keys", backend)), chunkSize: 1024) }
    let dir: URL = {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ssk-tests-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    func randomData(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    @Test(arguments: [0, 1, 1023, 1024, 1025, 3 * 1024 + 5])
    func roundTripsFiles(size: Int) async throws {
        let vault = self.vault
        let plain = randomData(size)
        let src = dir.appendingPathComponent("in-\(size)")
        let enc = dir.appendingPathComponent("enc-\(size)")
        let out = dir.appendingPathComponent("out-\(size)")
        try plain.write(to: src)
        try await vault.encryptFile(at: src, to: enc)
        #expect(try Data(contentsOf: enc) != plain)
        try await vault.decryptFile(at: enc, to: out)
        #expect(try Data(contentsOf: out) == plain)
        #expect(try EncryptedFileVault.keyID(ofFileAt: enc) == "file-vault#1")
    }

    @Test func roundTripsInMemory() async throws {
        let vault = self.vault
        let plain = randomData(5000)
        #expect(try await vault.decrypt(try await vault.encrypt(plain)) == plain)
        #expect(try await vault.decrypt(try await vault.encrypt(Data())) == Data())
    }

    @Test func detectsTamperingTruncationAndReordering() async throws {
        let vault = self.vault
        let sealed = try await vault.encrypt(randomData(4000))   // 4 chunks of 1024 + tag
        let headerSize = 10 + "file-vault#1".utf8.count + 7
        let chunk = 1024 + 16

        var flipped = sealed
        flipped[headerSize + 100] ^= 1
        var header = sealed
        header[6] ^= 1                                           // chunk size field
        let truncated = sealed.prefix(headerSize + 2 * chunk)    // drop final chunks at a boundary
        let partial = sealed.dropLast(5)
        var swapped = sealed.prefix(headerSize)
        swapped.append(sealed[(headerSize + chunk)..<(headerSize + 2 * chunk)])
        swapped.append(sealed[headerSize..<(headerSize + chunk)])
        swapped.append(sealed[(headerSize + 2 * chunk)...])

        for bad in [flipped, truncated, Data(partial), swapped] {
            #expect(await expectError(.tamperedData) { try await vault.decrypt(bad) })
        }
        await #expect(throws: StorageError.self) { try await vault.decrypt(header) }
    }

    @Test func failedDecryptionLeavesNoPlaintext() async throws {
        let vault = self.vault
        let src = dir.appendingPathComponent("in")
        let enc = dir.appendingPathComponent("enc")
        let out = dir.appendingPathComponent("out")
        try randomData(5000).write(to: src)
        try await vault.encryptFile(at: src, to: enc)
        var bytes = try Data(contentsOf: enc)
        bytes[bytes.count - 1] ^= 1   // corrupt the final chunk
        try bytes.write(to: enc)

        #expect(await expectError(.tamperedData) { try await vault.decryptFile(at: enc, to: out) })
        #expect(FileManager.default.fileExists(atPath: out.path) == false)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".partial") }
        #expect(leftovers.isEmpty)
    }

    @Test func filesStayReadableAfterRotation() async throws {
        let keys = KeyManager(storage: makeStorage("keys", backend))
        let vault = EncryptedFileVault(keyManager: keys, chunkSize: 1024)
        let old = try await vault.encrypt(Data("before".utf8))
        try await keys.rotate(named: "file-vault")
        let new = try await vault.encrypt(Data("after".utf8))
        #expect(try await vault.decrypt(old) == Data("before".utf8))
        #expect(try await vault.decrypt(new) == Data("after".utf8))
    }
}

@Suite("Key rotation engine")
struct RotationTests {
    @Test func rotatesMigratesAndRetires() async throws {
        let keys = KeyManager(storage: makeStorage("keys", InMemoryKeychain()))
        let aad: @Sendable (String) -> Data = { Data($0.utf8) }
        var records: [String: Data] = [:]
        for i in 0..<5 { records["r\(i)"] = try await keys.encrypt(Data("value \(i)".utf8), associatedData: aad("r\(i)")) }
        let store = InMemoryRecordStore(records)
        let engine = KeyRotationEngine(keyManager: keys, associatedData: aad)

        let report = try await engine.rotateAndMigrate(store)
        #expect(report.activeKeyID == "default#2")
        #expect(report.migrated.count == 5)
        #expect(report.retiredVersions == [1])
        for (id, sealed) in await store.all() {
            #expect(try CipherEnvelope.keyID(of: sealed) == "default#2")
            #expect(try await keys.decrypt(sealed, associatedData: aad(id)) == Data("value \(id.dropFirst())".utf8))
        }

        let again = try await engine.migrate(store)
        #expect(again.migrated.isEmpty)
        #expect(again.alreadyCurrent.count == 5)
    }

    @Test func failedRecordsBlockRetirementUntilFixed() async throws {
        let keys = KeyManager(storage: makeStorage("keys", InMemoryKeychain()))
        let good = try await keys.encrypt(Data("good".utf8))
        var bad = try await keys.encrypt(Data("bad".utf8))
        bad[bad.count - 1] ^= 1
        let store = InMemoryRecordStore(["good": good, "bad": bad])
        let engine = KeyRotationEngine(keyManager: keys)

        let report = try await engine.rotateAndMigrate(store)
        #expect(report.failed == ["bad": .tamperedData])
        #expect(report.retiredVersions.isEmpty)
        #expect(try await keys.versions().map(\.state) == [.decryptOnly, .active])

        // Recover: replace the bad record, then resume.
        await store.store(try await keys.encrypt(Data("fixed".utf8)), for: "bad")
        let resumed = try await engine.migrate(store)
        #expect(resumed.isComplete)
        #expect(resumed.retiredVersions == [1])
    }

    @Test func worksWithKeychainRecordStore() async throws {
        let backend = InMemoryKeychain()
        let keys = KeyManager(storage: makeStorage("keys", backend))
        let records = SecureStorageRecordStore(storage: makeStorage("records", backend))
        try await records.store(try await keys.encrypt(Data("x".utf8)), for: "a")
        let report = try await KeyRotationEngine(keyManager: keys).rotateAndMigrate(records)
        #expect(report.migrated == ["a"])
    }
}

@Suite("Multi-account vault")
struct MultiAccountTests {
    @Test func isolatesAndRemovesAccounts() async throws {
        let backend = InMemoryKeychain()
        let vault = MultiAccountVault(configuration: .init(service: "test-service", namespace: "vault"), backend: backend)
        let alice = try await vault.storage(for: "alice")
        let bob = try await vault.storage(for: "bob")
        try await alice.save("a-pin", forKey: "pin")
        try await bob.save("b-pin", forKey: "pin")
        #expect(try await vault.accounts() == ["alice", "bob"])
        #expect(try await alice.retrieve("pin", as: String.self) == "a-pin")

        try await vault.remove(account: "alice")
        #expect(try await alice.allKeys().isEmpty)
        #expect(try await bob.retrieve("pin", as: String.self) == "b-pin")
        #expect(try await vault.accounts() == ["bob"])

        try await vault.removeAll()
        #expect(backend.count == 0)
    }
}

@Suite("Legacy migration")
struct MigrationTests {
    @Test func importsMapsAndSkips() async throws {
        let backend = InMemoryKeychain()
        func legacy(_ account: String, _ value: String, protection: ItemProtection = .none) throws {
            try backend.add(KeychainWriteRequest(key: KeychainItemKey(service: "legacy-service", account: account),
                                                 data: Data(value.utf8), accessibility: .whenUnlocked, protection: protection))
        }
        try legacy("token", "t")
        try legacy("user_id", "42")
        try legacy("debug_flag", "1")
        try legacy("vault", "v", protection: .biometryAny)
        try legacy("existing", "old")

        let destination = makeStorage("app", backend)
        try await destination.save("new", forKey: "existing")
        let source = LegacyKeychainSource(service: "legacy-service") { $0.hasPrefix("debug") ? nil : $0 }
        let report = try await MigrationManager(destination: destination).migrate(from: source, deleteSource: true)

        #expect(report.imported == ["token": "token", "user_id": "user_id"])
        #expect(report.skippedByMapping == ["debug_flag"])
        #expect(report.skippedProtected == ["vault"])
        #expect(report.skippedExisting == ["existing"])
        #expect(backend.promptCount == 0)
        #expect(try await destination.retrieve("user_id", as: String.self) == "42")
        #expect(try await destination.retrieve("existing", as: String.self) == "new")
        // Imported items were removed from the legacy service; skipped ones stay.
        #expect(try backend.accounts(service: "legacy-service", accessGroup: nil) == ["debug_flag", "existing", "vault"])
    }
}

@Suite("Secure backup")
struct BackupTests {
    let password = "correct horse battery"

    @Test func exportsAndImportsWithPassword() async throws {
        let backend = InMemoryKeychain()
        let source = makeStorage("source", backend)
        try await source.save("t", forKey: "token")
        try await source.save(Data([0, 1, 2]), forKey: "blob")
        try await source.save("secret", forKey: "vault", protection: .biometryCurrentSet)

        let (backup, report) = try await SecureBackup.export(from: source, password: password, iterations: 100_000)
        #expect(report.exported == ["blob", "token"])
        #expect(report.skippedProtected == ["vault"])
        #expect(backend.promptCount == 0)
        #expect(backup.range(of: Data("secret".utf8)) == nil)

        let target = makeStorage("target", backend)
        let imported = try await SecureBackup.import(backup, password: password, into: target)
        #expect(imported.imported == ["blob", "token"])
        #expect(try await target.retrieve("token", as: String.self) == "t")
        #expect(try await target.retrieve("blob", as: Data.self) == Data([0, 1, 2]))

        let again = try await SecureBackup.import(backup, password: password, into: target)
        #expect(again.skippedExisting == ["blob", "token"])
    }

    @Test func rejectsWrongPasswordTamperingAndWeakSettings() async throws {
        let source = makeStorage("source", InMemoryKeychain())
        try await source.save("t", forKey: "token")
        let (backup, _) = try await SecureBackup.export(from: source, password: password, iterations: 100_000)
        let target = makeStorage("target", InMemoryKeychain())

        #expect(await expectError(.tamperedData) { try await SecureBackup.import(backup, password: "wrong password!!", into: target) })
        var tampered = backup
        tampered[tampered.count - 3] ^= 1
        #expect(await expectError(.tamperedData) { try await SecureBackup.import(tampered, password: password, into: target) })
        #expect(await expectError(.unsupportedFormat) { try await SecureBackup.import(Data("junk".utf8), password: password, into: target) })

        await #expect(throws: StorageError.self) { try await SecureBackup.export(from: source, password: "short") }
        await #expect(throws: StorageError.self) { try await SecureBackup.export(from: source, password: password, iterations: 1000) }
    }
}

@Suite("Audit log")
struct AuditTests {
    @Test func recordsBoundedNonSensitiveEvents() async throws {
        let audit = AuditLog(capacity: 3)
        let store = makeStorage("a", InMemoryKeychain(), events: audit.handler)
        try await store.save("top-secret", forKey: "password")
        _ = try await store.retrieve("password", as: String.self)
        _ = try await store.retrieve("missing", as: String.self)
        try await store.delete("password")
        _ = try? await store.save("x", forKey: "")   // invalid key: no event, fails before the Keychain

        let events = audit.events()
        #expect(events.count == 3)
        #expect(events.map(\.operation) == [.read, .read, .delete])
        #expect(!events.contains { String(describing: $0).contains("top-secret") || String(describing: $0).contains("password") })
        #expect(audit.events(operation: .delete).count == 1)
        audit.clear()
        #expect(audit.events().isEmpty)
    }
}

@Suite("Secure Enclave", .enabled(if: SecureEnclaveManager.isAvailable))
struct SecureEnclaveTests {
    @Test func signsAndSeals() async throws {
        let manager = SecureEnclaveManager(storage: makeStorage("se", InMemoryKeychain()))
        let message = Data("sign me".utf8)
        do {
            let publicKey = try await manager.createSigningKey(tag: "device")
            let signature = try await manager.sign(message, tag: "device")
            #expect(SecureEnclaveManager.verify(signature, for: message, publicKey: publicKey))
            #expect(!SecureEnclaveManager.verify(signature, for: Data("other".utf8), publicKey: publicKey))

            try await manager.createAgreementKey(tag: "device")
            let sealed = try await manager.seal(Data("wrapped key".utf8), toKeyTag: "device", associatedData: Data("ctx".utf8))
            #expect(try await manager.open(sealed, keyTag: "device", associatedData: Data("ctx".utf8)) == Data("wrapped key".utf8))
            await #expect(throws: StorageError.self) { try await manager.open(sealed, keyTag: "device", associatedData: Data("x".utf8)) }

            try await manager.deleteKey(tag: "device")
            #expect(try await manager.hasKey(tag: "device") == false)
        } catch StorageError.secureEnclaveUnavailable {
            // Some Macs report availability but refuse unsigned test processes.
        }
    }
}
