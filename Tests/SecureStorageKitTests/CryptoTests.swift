import CryptoKit
import Foundation
import Testing
@testable import SecureStorageKit

@Suite("AES-GCM envelope")
struct EncryptionTests {
    let crypto = EncryptionManager()
    let key = EncryptionManager.generateKey()
    let message = Data("The quick brown fox".utf8)

    @Test func roundTripsWithAssociatedData() throws {
        let sealed = try crypto.seal(message, using: key, keyID: "k#1", associatedData: Data("record-42".utf8))
        #expect(try crypto.open(sealed, using: key, associatedData: Data("record-42".utf8)) == message)
    }

    @Test func envelopeRecordsVersionAlgorithmAndKey() throws {
        let envelope = try crypto.encrypt(message, using: key, keyID: "default#7")
        let parsed = try CipherEnvelope(serialized: envelope.serialized())
        #expect(parsed == envelope)
        #expect(parsed.formatVersion == 1)
        #expect(parsed.algorithm == .aes256GCM)
        #expect(parsed.keyID == "default#7")
        #expect(parsed.nonce.count == 12)
        #expect(parsed.tag.count == 16)
    }

    @Test func noncesAreUnique() throws {
        let a = try crypto.encrypt(message, using: key, keyID: "k")
        let b = try crypto.encrypt(message, using: key, keyID: "k")
        #expect(a.nonce != b.nonce)
        #expect(a.ciphertext != b.ciphertext)
    }

    @Test func detectsTampering() throws {
        let sealed = try crypto.seal(message, using: key, keyID: "k#1", associatedData: Data("aad".utf8))
        let headerSize = CipherEnvelope.header(keyID: "k#1").count

        for index in [headerSize + 2, headerSize + 14, sealed.count - 1] {   // nonce, ciphertext, tag
            var tampered = sealed
            tampered[index] ^= 0x01
            #expect(throws: StorageError.tamperedData) { try crypto.open(tampered, using: key, associatedData: Data("aad".utf8)) }
        }

        // Changing the key id in the header is detected too.
        var relabeled = sealed
        relabeled[headerSize - 1] = UInt8(ascii: "2")
        #expect(throws: StorageError.tamperedData) { try crypto.open(relabeled, using: key, associatedData: Data("aad".utf8)) }

        #expect(throws: StorageError.tamperedData) { try crypto.open(sealed, using: key, associatedData: Data("other".utf8)) }
        #expect(throws: StorageError.tamperedData) { try crypto.open(sealed, using: EncryptionManager.generateKey(), associatedData: Data("aad".utf8)) }
    }

    @Test func rejectsMalformedInput() throws {
        #expect(throws: StorageError.unsupportedFormat) { try CipherEnvelope(serialized: Data("nope".utf8)) }
        let sealed = try crypto.seal(message, using: key, keyID: "k")
        #expect(throws: StorageError.unsupportedFormat) { try CipherEnvelope(serialized: sealed.prefix(20)) }
        var futureVersion = sealed
        futureVersion[4] = 9
        #expect(throws: StorageError.unsupportedFormat) { try CipherEnvelope(serialized: futureVersion) }
    }

    @Test func rejectsWrongKeySize() {
        #expect(throws: StorageError.invalidKey) { try crypto.seal(message, using: SymmetricKey(size: .bits128), keyID: "k") }
    }

    @Test func hkdfIsDeterministicAndContextBound() {
        let a1 = EncryptionManager.deriveKey(from: key, salt: Data("s".utf8), info: Data("account-a".utf8))
        let a2 = EncryptionManager.deriveKey(from: key, salt: Data("s".utf8), info: Data("account-a".utf8))
        let b = EncryptionManager.deriveKey(from: key, salt: Data("s".utf8), info: Data("account-b".utf8))
        #expect(a1 == a2)
        #expect(a1 != b)
        #expect(a1.bitCount == 256)
    }

    @Test func emptyPlaintextWorks() throws {
        let sealed = try crypto.seal(Data(), using: key, keyID: "k")
        #expect(try crypto.open(sealed, using: key) == Data())
    }
}

@Suite("Key manager")
struct KeyManagerTests {
    func makeKeys(_ backend: InMemoryKeychain = InMemoryKeychain()) -> KeyManager {
        KeyManager(storage: makeStorage(namespace: "keys", backend: backend))
    }

    @Test func createsKeyLazilyAndRoundTrips() async throws {
        let keys = makeKeys()
        let sealed = try await keys.encrypt(Data("hi".utf8), associatedData: Data("id-1".utf8))
        #expect(try CipherEnvelope.keyID(of: sealed) == "default#1")
        #expect(try await keys.decrypt(sealed, associatedData: Data("id-1".utf8)) == Data("hi".utf8))
    }

    @Test func rotationKeepsOldDataReadable() async throws {
        let keys = makeKeys()
        let old = try await keys.encrypt(Data("old".utf8))
        let version = try await keys.rotate()
        #expect(version.version == 2)
        let new = try await keys.encrypt(Data("new".utf8))
        #expect(try CipherEnvelope.keyID(of: new) == "default#2")
        #expect(try await keys.decrypt(old) == Data("old".utf8))
        #expect(try await keys.isCurrent(old) == false)
        #expect(try await keys.isCurrent(new))
        #expect(try await keys.versions().map(\.state) == [.decryptOnly, .active])
    }

    @Test func retiredKeysCannotDecrypt() async throws {
        let keys = makeKeys()
        let old = try await keys.encrypt(Data("old".utf8))
        try await keys.rotate()
        try await keys.retire(version: 1)
        #expect(await expectError(.keyRetired(id: "default#1")) { try await keys.decrypt(old) })
        await #expect(throws: StorageError.self) { try await keys.retire(version: 2) }   // active key
    }

    @Test func keysPersistAcrossInstances() async throws {
        let backend = InMemoryKeychain()
        let sealed = try await makeKeys(backend).encrypt(Data("persist".utf8))
        #expect(try await makeKeys(backend).decrypt(sealed) == Data("persist".utf8))
    }

    @Test func concurrentFirstUseCreatesOneVersion() async throws {
        let keys = makeKeys()
        try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<20 { group.addTask { try await keys.currentKey().id } }
            var ids = Set<String>()
            for try await id in group { ids.insert(id) }
            #expect(ids == ["default#1"])
        }
        #expect(try await keys.versions().count == 1)
    }

    @Test func namedKeysAreIndependent() async throws {
        let keys = makeKeys()
        let a = try await keys.encrypt(Data("a".utf8), keyName: "photos")
        let b = try await keys.encrypt(Data("b".utf8), keyName: "notes")
        try await keys.rotate(named: "photos")
        #expect(try CipherEnvelope.keyID(of: a) == "photos#1")
        #expect(try CipherEnvelope.keyID(of: b) == "notes#1")
        #expect(try await keys.currentKey(named: "notes").id == "notes#1")
        #expect(try await keys.currentKey(named: "photos").id == "photos#2")
    }

    @Test func destroyRemovesAllMaterial() async throws {
        let backend = InMemoryKeychain()
        let keys = makeKeys(backend)
        let sealed = try await keys.encrypt(Data("x".utf8))
        try await keys.destroy()
        #expect(backend.count == 0)
        // A fresh version 1 is created, which can't open the old data.
        await #expect(throws: StorageError.self) { try await keys.decrypt(sealed) }
    }
}
