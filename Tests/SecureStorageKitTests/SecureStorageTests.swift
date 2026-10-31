import Foundation
import Testing
@testable import SecureStorageKit

@Suite("Keychain storage")
struct SecureStorageTests {
    @Test func savesAndRetrievesStringDataAndCodable() async throws {
        let storage = makeStorage()
        try await storage.save("secret", forKey: "access_token")
        try await storage.save(Data([1, 2, 3]), forKey: "blob")
        try await storage.save(Profile(name: "Asha", age: 31), forKey: "profile")

        #expect(try await storage.retrieve("access_token", as: String.self) == "secret")
        #expect(try await storage.retrieve("blob", as: Data.self) == Data([1, 2, 3]))
        #expect(try await storage.retrieve("profile", as: Profile.self) == Profile(name: "Asha", age: 31))
    }

    @Test func stringsAreStoredAsRawUTF8() async throws {
        let backend = InMemoryKeychain()
        let storage = makeStorage(backend: backend)
        try await storage.save("héllo", forKey: "k")
        let raw = try backend.read(storage.itemKey("k"), prompt: nil)
        #expect(raw == Data("héllo".utf8))
    }

    @Test func missingKeyReturnsNil() async throws {
        #expect(try await makeStorage().retrieve("nope", as: String.self) == nil)
    }

    @Test func upsertReplacesValue() async throws {
        let storage = makeStorage()
        try await storage.save("one", forKey: "k")
        try await storage.save("two", forKey: "k")
        #expect(try await storage.retrieve("k", as: String.self) == "two")
    }

    @Test func insertOnlyRejectsDuplicates() async throws {
        let storage = makeStorage()
        try await storage.save("one", forKey: "k", mode: .insertOnly)
        #expect(await expectError(.duplicateItem) { try await storage.save("two", forKey: "k", mode: .insertOnly) })
        #expect(try await storage.retrieve("k", as: String.self) == "one")
    }

    @Test func updateRequiresExistingItem() async throws {
        let storage = makeStorage()
        #expect(await expectError(.itemNotFound) { try await storage.update("x", forKey: "missing") })
        try await storage.save("one", forKey: "k")
        try await storage.update("two", forKey: "k")
        #expect(try await storage.retrieve("k", as: String.self) == "two")
    }

    @Test func deleteReportsWhetherItemExisted() async throws {
        let storage = makeStorage()
        try await storage.save("v", forKey: "k")
        #expect(try await storage.delete("k"))
        #expect(try await storage.delete("k") == false)
        #expect(try await storage.contains("k") == false)
    }

    @Test func decodingFailureIsTyped() async throws {
        let storage = makeStorage()
        try await storage.save("not json", forKey: "k")
        #expect(await expectError(.decodingFailed(type: "Profile")) { try await storage.retrieve("k", as: Profile.self) })
    }

    @Test func listsKeysInNamespace() async throws {
        let backend = InMemoryKeychain()
        let a = makeStorage(namespace: "a", backend: backend)
        let b = makeStorage(namespace: "b", backend: backend)
        try await a.save("1", forKey: "x")
        try await a.save("2", forKey: "y")
        try await b.save("3", forKey: "z")
        #expect(try await a.allKeys() == ["x", "y"])
        #expect(try await b.allKeys() == ["z"])
    }

    @Test func clearAllOnlyRemovesOwnNamespace() async throws {
        let backend = InMemoryKeychain()
        let a = makeStorage(namespace: "a", backend: backend)
        let b = makeStorage(namespace: "b", backend: backend)
        let dev = makeStorage(namespace: "a", environment: .development, backend: backend)
        try await a.save("1", forKey: "x")
        try await b.save("2", forKey: "x")
        try await dev.save("3", forKey: "x")
        // An item written by other code in the same service.
        try backend.add(KeychainWriteRequest(key: KeychainItemKey(service: "test-service", account: "foreign"),
                                             data: Data("keep".utf8), accessibility: .whenUnlocked))

        try await a.clearAll()

        #expect(try await a.allKeys().isEmpty)
        #expect(try await b.retrieve("x", as: String.self) == "2")
        #expect(try await dev.retrieve("x", as: String.self) == "3")
        #expect(try backend.read(KeychainItemKey(service: "test-service", account: "foreign"), prompt: nil) == Data("keep".utf8))
    }

    @Test func environmentsAreIsolated() async throws {
        let backend = InMemoryKeychain()
        let prod = makeStorage(backend: backend)
        let dev = makeStorage(environment: .development, backend: backend)
        try await prod.save("prod", forKey: "k")
        #expect(try await dev.retrieve("k", as: String.self) == nil)
        #expect(dev.configuration.resolvedService == "test-service.dev")
    }

    @Test func rejectsInvalidConfiguration() async throws {
        let badNamespace = SecureStorage(configuration: .init(service: "s", namespace: "a/b"), backend: InMemoryKeychain())
        await #expect(throws: StorageError.self) { try await badNamespace.save("v", forKey: "k") }

        let syncDeviceOnly = SecureStorage(configuration: .init(service: "s", accessibility: .whenUnlockedThisDeviceOnly, synchronizable: true),
                                           backend: InMemoryKeychain())
        await #expect(throws: StorageError.self) { try await syncDeviceOnly.save("v", forKey: "k") }

        let syncOK = SecureStorage(configuration: .init(service: "s", accessibility: .afterFirstUnlock, synchronizable: true),
                                   backend: InMemoryKeychain())
        try await syncOK.save("v", forKey: "k")

        await #expect(throws: StorageError.self) { try await makeStorage().save("v", forKey: "") }
    }

    @Test func lockedDeviceBlocksWhenUnlockedItems() async throws {
        let backend = InMemoryKeychain()
        let storage = makeStorage(backend: backend)
        try await storage.save("a", forKey: "foreground", accessibility: .whenUnlockedThisDeviceOnly)
        try await storage.save("b", forKey: "background", accessibility: .afterFirstUnlockThisDeviceOnly)
        backend.isDeviceLocked = true
        #expect(await expectError(.interactionNotAllowed) { try await storage.retrieve("foreground", as: String.self) })
        #expect(try await storage.retrieve("background", as: String.self) == "b")
    }

    @Test func concurrentOperationsAreSafe() async throws {
        let storage = makeStorage()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<200 {
                group.addTask {
                    try await storage.save("value-\(i)", forKey: "k\(i % 20)")
                    _ = try await storage.retrieve("k\(i % 20)", as: String.self)
                }
            }
            try await group.waitForAll()
        }
        #expect(try await storage.allKeys().count == 20)
    }

    @Test func eventsNeverContainKeysOrValues() async throws {
        let collector = EventCollector()
        let storage = makeStorage(events: collector.handler)
        try await storage.save("super-secret-value", forKey: "access_token")
        _ = try await storage.retrieve("access_token", as: String.self)
        _ = try await storage.retrieve("missing", as: String.self)
        try await storage.delete("access_token")

        let events = collector.events
        #expect(events.map(\.operation) == [.save, .read, .read, .delete])
        #expect(events[2].outcome == .notFound)
        for event in events {
            let text = String(describing: event)
            #expect(!text.contains("super-secret-value"))
            #expect(!text.contains("access_token"))
        }
        #expect(events[0].keyFingerprint == StorageEvent.fingerprint("access_token"))
    }
}

@Suite("Biometric item protection")
struct ProtectionTests {
    @Test func protectedItemRequiresAuthentication() async throws {
        let backend = InMemoryKeychain()
        let storage = makeStorage(backend: backend)
        try await storage.save("private", forKey: "vault", protection: .biometryCurrentSet)

        #expect(try await storage.retrieve("vault", as: String.self, authenticationReason: "Unlock secure data") == "private")
        #expect(backend.promptCount == 1)

        backend.authenticationResult = .failure(.userCancelled)
        #expect(await expectError(.userCancelled) { try await storage.retrieve("vault", as: String.self, authenticationReason: "x") })

        backend.authenticationResult = .failure(.authenticationFailed)
        #expect(await expectError(.authenticationFailed) { try await storage.retrieve("vault", as: String.self, authenticationReason: "x") })
    }

    @Test func noInteractionPromptNeverShowsUI() async throws {
        let backend = InMemoryKeychain()
        let storage = makeStorage(backend: backend)
        try await storage.save("private", forKey: "vault", protection: .userPresence)
        #expect(await expectError(.interactionNotAllowed) { try await storage.retrieve("vault", as: String.self, prompt: .noInteraction) })
        #expect(backend.promptCount == 0)
    }

    @Test func deletingAndListingNeverPrompt() async throws {
        let backend = InMemoryKeychain()
        let storage = makeStorage(backend: backend)
        try await storage.save("private", forKey: "vault", protection: .biometryAny)
        #expect(try await storage.contains("vault"))
        #expect(try await storage.allKeys() == ["vault"])
        try await storage.save("replaced", forKey: "vault", protection: .biometryAny)
        try await storage.clearAll()
        #expect(backend.promptCount == 0)
    }

    @Test func enrollmentChangeInvalidatesCurrentSetOnly() async throws {
        let backend = InMemoryKeychain()
        let storage = makeStorage(backend: backend)
        try await storage.save("a", forKey: "current", protection: .biometryCurrentSet)
        try await storage.save("b", forKey: "any", protection: .biometryAny)
        try await storage.save("c", forKey: "fallback", protection: .biometryCurrentSetOrPasscode)
        backend.simulateBiometryEnrollmentChange()
        #expect(try await storage.retrieve("current", as: String.self) == nil)
        #expect(try await storage.retrieve("fallback", as: String.self) == nil)
        #expect(try await storage.retrieve("any", as: String.self) == "b")
    }

    @Test func protectedItemsCannotSync() async throws {
        let storage = SecureStorage(configuration: .init(service: "s", accessibility: .afterFirstUnlock, synchronizable: true),
                                    backend: InMemoryKeychain())
        await #expect(throws: StorageError.self) { try await storage.save("v", forKey: "k", protection: .biometryAny) }
    }

    @Test func protectionFlags() {
        #expect(ItemProtection.none.requiresAuthentication == false)
        #expect(ItemProtection.biometryCurrentSet.invalidatedByEnrollmentChange)
        #expect(ItemProtection.biometryAny.invalidatedByEnrollmentChange == false)
        #expect(ItemProtection.biometryCurrentSet.description == "biometryCurrentSet")
    }
}

@Suite("Errors")
struct ErrorTests {
    @Test func mapsOSStatus() {
        #expect(StorageError(status: errSecItemNotFound) == .itemNotFound)
        #expect(StorageError(status: errSecDuplicateItem) == .duplicateItem)
        #expect(StorageError(status: errSecUserCanceled) == .userCancelled)
        #expect(StorageError(status: errSecAuthFailed) == .authenticationFailed)
        #expect(StorageError(status: errSecInteractionNotAllowed) == .interactionNotAllowed)
        #expect(StorageError(status: errSecMissingEntitlement) == .missingEntitlement)
        #expect(StorageError(status: -99999) == .unexpectedStatus(-99999))
    }

    @Test func mapsLocalAuthenticationErrors() {
        #expect(StorageError(authenticationError: LAErrorShim.make(.userCancel)) == .userCancelled)
        #expect(StorageError(authenticationError: LAErrorShim.make(.biometryLockout)) == .biometryLockout)
        #expect(StorageError(authenticationError: LAErrorShim.make(.biometryNotEnrolled)) == .biometryNotEnrolled)
        #expect(StorageError(authenticationError: LAErrorShim.make(.userFallback)) == .userFallback)
        #expect(StorageError.userFallback.isCancellation)
    }

    @Test func everyErrorHasADescription() {
        let errors: [StorageError] = [.itemNotFound, .tamperedData, .keyRetired(id: "default#1"), .obsoleteRecord(foundVersion: 1, minimumSupported: 2)]
        for error in errors { #expect(error.errorDescription?.isEmpty == false) }
    }
}

import LocalAuthentication
enum LAErrorShim {
    static func make(_ code: LAError.Code) -> Error { LAError(code) }
}
