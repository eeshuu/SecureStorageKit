import Foundation

/// Separates development and production data so a debug build never reads or
/// clears a release build's secrets on a shared device.
public enum StorageEnvironment: Sendable, Hashable {
    case production
    case development
    case custom(String)

    var serviceSuffix: String? {
        switch self {
        case .production: nil
        case .development: "dev"
        case .custom(let name): name
        }
    }
}

/// How a `SecureStorage` instance names, protects and serializes its items.
public struct StorageConfiguration: Sendable {
    /// The Keychain service, usually your bundle identifier.
    public var service: String
    /// Items are grouped by namespace; `clearAll()` only removes the current namespace.
    public var namespace: String
    public var environment: StorageEnvironment
    /// Default accessibility for new items.
    public var accessibility: KeychainAccessibility
    /// Default authentication required to read new items.
    public var protection: ItemProtection
    /// A Keychain access group shared with app extensions (needs the entitlement).
    public var accessGroup: String?
    /// Sync items through iCloud Keychain. Requires non-`ThisDeviceOnly`
    /// accessibility and no item protection.
    public var synchronizable: Bool
    /// Encodes Codable values. Strings and `Data` are always stored as raw bytes.
    public var serializer: any StorageSerializer
    /// Receives non-sensitive operation events (see `SecureLogger` and `AuditLog`).
    public var eventHandler: (@Sendable (StorageEvent) -> Void)?

    public init(
        service: String,
        namespace: String = "default",
        environment: StorageEnvironment = .production,
        accessibility: KeychainAccessibility = .whenUnlockedThisDeviceOnly,
        protection: ItemProtection = .none,
        accessGroup: String? = nil,
        synchronizable: Bool = false,
        serializer: any StorageSerializer = JSONStorageSerializer(),
        eventHandler: (@Sendable (StorageEvent) -> Void)? = nil
    ) {
        self.service = service
        self.namespace = namespace
        self.environment = environment
        self.accessibility = accessibility
        self.protection = protection
        self.accessGroup = accessGroup
        self.synchronizable = synchronizable
        self.serializer = serializer
        self.eventHandler = eventHandler
    }

    /// The Keychain service actually used, including the environment suffix.
    public var resolvedService: String {
        environment.serviceSuffix.map { "\(service).\($0)" } ?? service
    }

    /// Every SDK-owned account starts with this prefix, which is what lets
    /// `clearAll()` leave other code's Keychain items alone.
    var accountPrefix: String { "ssk/\(namespace)/" }

    /// Accounts of values staged by an in-progress replace (see `SecureStorage.replace`).
    var stagingPrefix: String { "ssk-staging/\(namespace)/" }

    func validate() throws {
        if service.isEmpty { throw StorageError.invalidConfiguration("service must not be empty") }
        if namespace.isEmpty || namespace.contains("/") {
            throw StorageError.invalidConfiguration("namespace must be non-empty and must not contain '/'")
        }
        if synchronizable && (accessibility.isThisDeviceOnly || protection.requiresAuthentication) {
            throw StorageError.invalidConfiguration("synchronizable items can't use ThisDeviceOnly accessibility or authentication")
        }
    }

    /// Returns a copy with a different namespace.
    public func namespaced(_ namespace: String) -> StorageConfiguration {
        var copy = self
        copy.namespace = namespace
        return copy
    }
}

enum NamespaceEncoding {
    /// Makes an arbitrary account or tenant id safe to use in a namespace.
    static func encode(_ id: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.")
        return id.addingPercentEncoding(withAllowedCharacters: allowed) ?? id
    }

    /// Like `encode`, but also escapes `.`, so encoded ids can't be mistaken for namespace separators.
    static func encodeStrict(_ id: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_")
        return id.addingPercentEncoding(withAllowedCharacters: allowed) ?? id
    }

    static func decode(_ id: String) -> String {
        id.removingPercentEncoding ?? id
    }
}
