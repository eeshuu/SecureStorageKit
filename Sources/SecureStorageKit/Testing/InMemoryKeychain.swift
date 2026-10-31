import Foundation

/// A thread-safe, in-memory `KeychainBackend` for unit tests, SwiftUI previews
/// and the simulator. It mirrors the real Keychain's behavior: duplicate and
/// not-found errors, item-level authentication and biometric invalidation.
///
/// ```swift
/// let mock = InMemoryKeychain()
/// let storage = SecureStorage(configuration: .init(service: "test"), backend: mock)
/// mock.authenticationResult = .failure(.userCancelled)   // simulate Face ID cancel
/// ```
public final class InMemoryKeychain: KeychainBackend, @unchecked Sendable {
    private struct Item {
        var data: Data
        var protection: ItemProtection
        var accessibility: KeychainAccessibility
        var synchronizable: Bool
    }

    private let lock = NSLock()
    private var items: [KeychainItemKey: Item] = [:]
    private var _authenticationResult: Result<Void, StorageError> = .success(())
    private var _isLocked = false
    private var _promptCount = 0

    public init() {}

    /// What happens when a protected item is read. Defaults to success.
    public var authenticationResult: Result<Void, StorageError> {
        get { lock.sync { _authenticationResult } }
        set { lock.sync { _authenticationResult = newValue } }
    }

    /// Simulates a locked device: `whenUnlocked` items fail with `.interactionNotAllowed`.
    public var isDeviceLocked: Bool {
        get { lock.sync { _isLocked } }
        set { lock.sync { _isLocked = newValue } }
    }

    /// How many authentication prompts would have been shown.
    public var promptCount: Int { lock.sync { _promptCount } }

    public var count: Int { lock.sync { items.count } }

    /// Simulates adding or removing a finger or face: `.biometryCurrentSet` items are lost.
    public func simulateBiometryEnrollmentChange() {
        lock.sync { items = items.filter { !$0.value.protection.invalidatedByEnrollmentChange } }
    }

    public func removeAll() {
        lock.sync { items.removeAll() }
    }

    // MARK: KeychainBackend

    public func add(_ request: KeychainWriteRequest) throws {
        if request.synchronizable && (request.protection.requiresAuthentication || request.accessibility.isThisDeviceOnly) {
            throw StorageError.invalidConfiguration("synchronizable items can't use ThisDeviceOnly accessibility or authentication")
        }
        try lock.sync {
            guard items[request.key] == nil else { throw StorageError.duplicateItem }
            items[request.key] = Item(data: request.data, protection: request.protection,
                                      accessibility: request.accessibility, synchronizable: request.synchronizable)
        }
    }

    public func read(_ key: KeychainItemKey, prompt: AuthenticationPrompt?) throws -> Data {
        try lock.sync {
            guard let item = items[key] else { throw StorageError.itemNotFound }
            if _isLocked, item.accessibility == .whenUnlocked || item.accessibility == .whenUnlockedThisDeviceOnly
                || item.accessibility == .whenPasscodeSetThisDeviceOnly {
                throw StorageError.interactionNotAllowed
            }
            if item.protection.requiresAuthentication {
                if prompt?.allowsInteraction == false { throw StorageError.interactionNotAllowed }
                _promptCount += 1
                try _authenticationResult.get()
            }
            return item.data
        }
    }

    public func exists(_ key: KeychainItemKey) throws -> Bool {
        lock.sync { items[key] != nil }
    }

    @discardableResult
    public func delete(_ key: KeychainItemKey) throws -> Bool {
        lock.sync { items.removeValue(forKey: key) != nil }
    }

    public func accounts(service: String, accessGroup: String?) throws -> [String] {
        lock.sync {
            items.keys.filter { $0.service == service && $0.accessGroup == accessGroup }.map(\.account).sorted()
        }
    }
}
