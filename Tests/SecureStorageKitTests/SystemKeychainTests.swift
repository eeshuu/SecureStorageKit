import Foundation
import Testing
@testable import SecureStorageKit

/// Runs against the real Keychain. Opt in with `SSK_KEYCHAIN_TESTS=1 swift test` on macOS.
/// It uses the file-based macOS keychain, because unsigned test binaries have no
/// data protection keychain entitlement. Package tests on the iOS Simulator have
/// no host app and fail with `.missingEntitlement`; exercise the iOS Keychain
/// through the example app instead.
@Suite("System Keychain (integration)", .enabled(if: ProcessInfo.processInfo.environment["SSK_KEYCHAIN_TESTS"] == "1"))
struct SystemKeychainTests {
    let storage: SecureStorage = {
        #if os(macOS)
        let backend = SystemKeychain(useDataProtectionKeychain: false)
        #else
        let backend = SystemKeychain()
        #endif
        return SecureStorage(configuration: .init(service: "com.securestoragekit.tests.\(UUID().uuidString)"), backend: backend)
    }()

    @Test func crudAgainstRealKeychain() async throws {
        defer { Task { [storage] in try? await storage.clearAll() } }
        try await storage.save("secret", forKey: "access_token")
        #expect(try await storage.retrieve("access_token", as: String.self) == "secret")
        try await storage.save("rotated", forKey: "access_token")
        #expect(try await storage.retrieve("access_token", as: String.self) == "rotated")
        #expect(await expectError(.duplicateItem) { try await storage.save("x", forKey: "access_token", mode: .insertOnly) })
        try await storage.save(Profile(name: "A", age: 2), forKey: "profile")
        #expect(try await storage.allKeys() == ["access_token", "profile"])
        #expect(try await storage.delete("access_token"))
        #expect(try await storage.retrieve("access_token", as: String.self) == nil)
        try await storage.clearAll()
        #expect(try await storage.allKeys().isEmpty)
    }
}
