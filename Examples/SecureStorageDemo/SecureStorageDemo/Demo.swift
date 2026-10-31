import Foundation
import SecureStorageKit

/// Shared instances used by every screen.
enum Demo {
    static let service = "com.securestoragekit.demo"
    static let audit = AuditLog(capacity: 200, forward: SecureLogger.unifiedLog)

    static let storage = SecureStorage(configuration: StorageConfiguration(
        service: service, namespace: "demo", eventHandler: audit.handler))

    static let vault = SecureStorage(configuration: StorageConfiguration(
        service: service, namespace: "biometric-vault", accessibility: .whenPasscodeSetThisDeviceOnly,
        eventHandler: audit.handler))

    static let keys = KeyManager(storage: SecureStorage(configuration: StorageConfiguration(
        service: service, namespace: "keys", eventHandler: audit.handler)))

    static let tokens = SecureTokenStore(
        configuration: StorageConfiguration(service: service, namespace: "tokens",
                                            accessibility: .afterFirstUnlockThisDeviceOnly, eventHandler: audit.handler),
        refresher: FakeAuthServer())
}

/// Stands in for your backend's token endpoint.
struct FakeAuthServer: TokenRefresher {
    func refreshTokens(using refreshToken: String, account: String) async throws -> TokenSet {
        try await Task.sleep(nanoseconds: 600_000_000)
        return TokenSet(accessToken: "at_" + UUID().uuidString.prefix(8), refreshToken: "rt_" + UUID().uuidString.prefix(8), expiresIn: 15)
    }
}

extension Error {
    var demoMessage: String {
        (self as? StorageError)?.errorDescription ?? localizedDescription
    }
}
