import Foundation

/// The Keychain location of one item: service, optional access group and account.
public struct KeychainItemKey: Hashable, Sendable {
    public var service: String
    public var account: String
    public var accessGroup: String?

    public init(service: String, account: String, accessGroup: String? = nil) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }
}

/// Everything needed to write one item.
public struct KeychainWriteRequest: Sendable {
    public var key: KeychainItemKey
    public var data: Data
    public var accessibility: KeychainAccessibility
    public var protection: ItemProtection
    public var synchronizable: Bool
    public var label: String?

    public init(key: KeychainItemKey, data: Data, accessibility: KeychainAccessibility,
                protection: ItemProtection = .none, synchronizable: Bool = false, label: String? = nil) {
        self.key = key
        self.data = data
        self.accessibility = accessibility
        self.protection = protection
        self.synchronizable = synchronizable
        self.label = label
    }
}

/// Text and behavior of the system prompt shown when reading a protected item.
public struct AuthenticationPrompt: Sendable, Hashable {
    /// Why the app needs access, shown in the Face ID / Touch ID prompt. Localize it.
    public var reason: String
    /// Title of the fallback button. `nil` uses the system default; `""` hides it.
    public var fallbackTitle: String?
    /// Title of the cancel button. `nil` uses the system default.
    public var cancelTitle: String?
    /// When false, reads fail with `.interactionNotAllowed` instead of showing UI.
    public var allowsInteraction: Bool
    /// Seconds a recent device unlock with Touch ID counts as authentication (max 300).
    public var reuseDuration: TimeInterval

    public init(reason: String, fallbackTitle: String? = nil, cancelTitle: String? = nil,
                allowsInteraction: Bool = true, reuseDuration: TimeInterval = 0) {
        self.reason = reason
        self.fallbackTitle = fallbackTitle
        self.cancelTitle = cancelTitle
        self.allowsInteraction = allowsInteraction
        self.reuseDuration = reuseDuration
    }

    /// A prompt that never shows UI: protected items fail with `.interactionNotAllowed`.
    public static let noInteraction = AuthenticationPrompt(reason: "", allowsInteraction: false)
}

/// Low-level Keychain operations. `SystemKeychain` talks to the real Keychain;
/// `InMemoryKeychain` is a drop-in for unit tests and previews.
///
/// Implementations are called from a serial queue and may block (for example
/// while the system shows a Face ID prompt).
public protocol KeychainBackend: Sendable {
    /// Adds a new item. Throws `.duplicateItem` if one exists.
    func add(_ request: KeychainWriteRequest) throws
    /// Returns the item's data. Throws `.itemNotFound` if it does not exist.
    func read(_ key: KeychainItemKey, prompt: AuthenticationPrompt?) throws -> Data
    /// True if the item exists. Never shows authentication UI.
    func exists(_ key: KeychainItemKey) throws -> Bool
    /// Deletes the item. Returns false if it did not exist. Never shows authentication UI.
    @discardableResult
    func delete(_ key: KeychainItemKey) throws -> Bool
    /// All account names stored under a service and access group. Never shows authentication UI.
    func accounts(service: String, accessGroup: String?) throws -> [String]
}
