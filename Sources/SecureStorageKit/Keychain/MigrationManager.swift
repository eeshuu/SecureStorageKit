import Foundation

/// Generic password items written by another Keychain wrapper.
///
/// Most wrappers store a value under service = a fixed name or the bundle id
/// and account = the key:
/// - KeychainAccess: `Keychain(service:)` → `.init(service: <that service>)`
/// - SwiftKeychainWrapper: `.init(service: Bundle.main.bundleIdentifier ?? "SwiftKeychainWrapper")`
/// - Raw `SecItemAdd` code: the service and access group it used
public struct LegacyKeychainSource: Sendable {
    public var service: String
    public var accessGroup: String?
    /// Maps a legacy account name to the new key, or nil to skip it.
    public var keyMapping: @Sendable (String) -> String?

    public init(service: String, accessGroup: String? = nil, keyMapping: @escaping @Sendable (String) -> String? = { $0 }) {
        self.service = service
        self.accessGroup = accessGroup
        self.keyMapping = keyMapping
    }
}

public struct MigrationReport: Sendable, Equatable {
    /// legacy account → new key
    public var imported: [String: String] = [:]
    /// Already present in the destination and `overwrite` was false.
    public var skippedExisting: [String] = []
    /// Needs authentication to read (biometric or passcode protected); never prompted for.
    public var skippedProtected: [String] = []
    public var skippedByMapping: [String] = []
    public var failed: [String: StorageError] = [:]
}

/// Imports items from legacy Keychain wrappers into `SecureStorage`.
public struct MigrationManager: Sendable {
    public let destination: SecureStorage
    private let backend: any KeychainBackend

    /// - Parameter backend: The Keychain to read legacy items from. Defaults to
    ///   the destination's own backend.
    public init(destination: SecureStorage, backend: (any KeychainBackend)? = nil) {
        self.destination = destination
        self.backend = backend ?? destination.backend
    }

    /// Copies every readable item. Protected items are skipped rather than
    /// prompting once per item. Source items are deleted only after a
    /// successful import, and only when `deleteSource` is true.
    public func migrate(from source: LegacyKeychainSource, overwrite: Bool = false, deleteSource: Bool = false) async throws -> MigrationReport {
        let backend = self.backend
        let accounts = try await Self.offMain { try backend.accounts(service: source.service, accessGroup: source.accessGroup) }
        var report = MigrationReport()

        for account in accounts.sorted() {
            // Never re-import our own items if the services coincide.
            if account.hasPrefix("ssk/") || account.hasPrefix("ssk-staging/") { continue }
            guard let key = source.keyMapping(account) else {
                report.skippedByMapping.append(account)
                continue
            }
            let legacyKey = KeychainItemKey(service: source.service, account: account, accessGroup: source.accessGroup)
            do {
                if !overwrite, try await destination.contains(key) {
                    report.skippedExisting.append(account)
                    continue
                }
                let data = try await Self.offMain { try backend.read(legacyKey, prompt: .noInteraction) }
                try await destination.saveData(data, forKey: key)
                report.imported[account] = key
                if deleteSource {
                    _ = try await Self.offMain { try backend.delete(legacyKey) }
                }
            } catch StorageError.interactionNotAllowed {
                report.skippedProtected.append(account)
            } catch let error as StorageError {
                report.failed[account] = error
            }
        }
        destination.configuration.eventHandler?(StorageEvent(operation: .migrate, namespace: destination.configuration.namespace,
                                                             key: nil, outcome: report.failed.isEmpty ? .success : .failure(report.failed.values.first!)))
        return report
    }

    private static func offMain<R: Sendable>(_ work: @escaping @Sendable () throws -> R) async throws -> R {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { continuation.resume(with: Result { try work() }) }
        }
    }
}
