import Foundation
import LocalAuthentication
import Security

/// The real Keychain, using generic password items.
public struct SystemKeychain: KeychainBackend {
    /// macOS only: use the iOS-style data protection keychain (recommended by Apple).
    /// It requires the app to be signed with a Keychain access group entitlement;
    /// unsigned command-line tools get `.missingEntitlement` and should pass `false`.
    public var useDataProtectionKeychain: Bool

    public init(useDataProtectionKeychain: Bool = true) {
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }

    public func add(_ request: KeychainWriteRequest) throws {
        if request.synchronizable && (request.protection.requiresAuthentication || request.accessibility.isThisDeviceOnly) {
            throw StorageError.invalidConfiguration("synchronizable items can't use ThisDeviceOnly accessibility or authentication")
        }
        var query = baseQuery(request.key, synchronizable: request.synchronizable as CFBoolean)
        query[kSecValueData] = request.data
        if let label = request.label { query[kSecAttrLabel] = label }
        if let control = try request.protection.accessControl(accessibility: request.accessibility) {
            query[kSecAttrAccessControl] = control
        } else {
            query[kSecAttrAccessible] = request.accessibility.secValue
        }
        try check(SecItemAdd(query as CFDictionary, nil))
    }

    public func read(_ key: KeychainItemKey, prompt: AuthenticationPrompt?) throws -> Data {
        var query = baseQuery(key)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        if let prompt { query[kSecUseAuthenticationContext] = Self.context(for: prompt) }
        var result: CFTypeRef?
        try check(SecItemCopyMatching(query as CFDictionary, &result))
        guard let data = result as? Data else { throw StorageError.unsupportedFormat }
        return data
    }

    public func exists(_ key: KeychainItemKey) throws -> Bool {
        var query = baseQuery(key)
        query[kSecReturnAttributes] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext] = Self.context(for: .noInteraction)
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess, errSecInteractionNotAllowed: return true
        case errSecItemNotFound: return false
        default: throw StorageError(status: status)
        }
    }

    @discardableResult
    public func delete(_ key: KeychainItemKey) throws -> Bool {
        let status = SecItemDelete(baseQuery(key) as CFDictionary)
        if status == errSecItemNotFound { return false }
        try check(status)
        return true
    }

    public func accounts(service: String, accessGroup: String?) throws -> [String] {
        var query = commonQuery(service: service, accessGroup: accessGroup, synchronizable: kSecAttrSynchronizableAny)
        query[kSecReturnAttributes] = true
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecUseAuthenticationContext] = Self.context(for: .noInteraction)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try check(status)
        let items = result as? [[CFString: Any]] ?? []
        return items.compactMap { $0[kSecAttrAccount] as? String }
    }

    // MARK: - Queries

    private func baseQuery(_ key: KeychainItemKey, synchronizable: CFTypeRef = kSecAttrSynchronizableAny) -> [CFString: Any] {
        var query = commonQuery(service: key.service, accessGroup: key.accessGroup, synchronizable: synchronizable)
        query[kSecAttrAccount] = key.account
        return query
    }

    private func commonQuery(service: String, accessGroup: String?, synchronizable: CFTypeRef) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrSynchronizable: synchronizable,
        ]
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        #if os(macOS)
        if useDataProtectionKeychain { query[kSecUseDataProtectionKeychain] = true }
        #endif
        return query
    }

    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw StorageError(status: status) }
    }

    static func context(for prompt: AuthenticationPrompt) -> LAContext {
        let context = LAContext()
        context.interactionNotAllowed = !prompt.allowsInteraction
        if !prompt.reason.isEmpty { context.localizedReason = prompt.reason }
        if let fallback = prompt.fallbackTitle { context.localizedFallbackTitle = fallback }
        if let cancel = prompt.cancelTitle { context.localizedCancelTitle = cancel }
        context.touchIDAuthenticationAllowableReuseDuration = min(max(prompt.reuseDuration, 0), LATouchIDAuthenticationMaximumAllowableReuseDuration)
        return context
    }
}
