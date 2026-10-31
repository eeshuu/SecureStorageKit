import Foundation
import LocalAuthentication
import Security

/// Every error thrown by SecureStorageKit.
///
/// Errors never carry stored values, keys, tokens or key material, so they are
/// safe to log, show in crash reports or send to analytics.
public enum StorageError: Error, Sendable, Equatable {
    // Keychain
    case itemNotFound
    case duplicateItem
    case interactionNotAllowed
    case missingEntitlement
    case protectedDataUnavailable
    case unexpectedStatus(OSStatus)

    // Authentication
    case userCancelled
    case userFallback
    case authenticationFailed
    case biometryNotAvailable
    case biometryNotEnrolled
    case biometryLockout
    case passcodeNotSet

    // Serialization
    case encodingFailed(type: String)
    case decodingFailed(type: String)
    case obsoleteRecord(foundVersion: Int, minimumSupported: Int)
    case unsupportedSchemaVersion(Int)

    // Crypto & keys
    case invalidKey
    case keyNotFound(id: String)
    case keyRetired(id: String)
    case cryptoFailure
    case tamperedData
    case unsupportedFormat
    case secureEnclaveUnavailable

    // Tokens
    case tokenExpired
    case noRefreshToken

    // Configuration
    case invalidConfiguration(String)

    /// Maps a Keychain `OSStatus` to a typed error.
    public init(status: OSStatus) {
        switch status {
        case errSecItemNotFound: self = .itemNotFound
        case errSecDuplicateItem: self = .duplicateItem
        case errSecUserCanceled: self = .userCancelled
        case errSecAuthFailed: self = .authenticationFailed
        case errSecInteractionNotAllowed: self = .interactionNotAllowed
        case errSecMissingEntitlement: self = .missingEntitlement
        case errSecNotAvailable: self = .protectedDataUnavailable
        default: self = .unexpectedStatus(status)
        }
    }

    /// Maps a LocalAuthentication error (or any error) to a typed error.
    public init(authenticationError error: Error) {
        if let storageError = error as? StorageError {
            self = storageError
            return
        }
        guard let laError = error as? LAError else {
            self = .authenticationFailed
            return
        }
        switch laError.code {
        case .userCancel, .appCancel, .systemCancel: self = .userCancelled
        case .userFallback: self = .userFallback
        case .biometryNotAvailable: self = .biometryNotAvailable
        case .biometryNotEnrolled: self = .biometryNotEnrolled
        case .biometryLockout: self = .biometryLockout
        case .passcodeNotSet: self = .passcodeNotSet
        case .notInteractive: self = .interactionNotAllowed
        default: self = .authenticationFailed
        }
    }

    /// True when the user dismissed an authentication prompt rather than failing it.
    public var isCancellation: Bool {
        self == .userCancelled || self == .userFallback
    }
}

extension StorageError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .itemNotFound: "The item was not found."
        case .duplicateItem: "An item with this key already exists."
        case .interactionNotAllowed: "The item can't be read right now (device locked or authentication UI not allowed)."
        case .missingEntitlement: "The app is missing the Keychain entitlement for this access group."
        case .protectedDataUnavailable: "Protected data is not available while the device is locked."
        case .unexpectedStatus(let status): "Keychain error \(status)."
        case .userCancelled: "Authentication was cancelled."
        case .userFallback: "The user chose the fallback option."
        case .authenticationFailed: "Authentication failed."
        case .biometryNotAvailable: "Biometric authentication is not available on this device."
        case .biometryNotEnrolled: "No Face ID or Touch ID is enrolled."
        case .biometryLockout: "Biometry is locked after too many failed attempts. Enter the device passcode to unlock it."
        case .passcodeNotSet: "A device passcode is required."
        case .encodingFailed(let type): "Could not encode a value of type \(type)."
        case .decodingFailed(let type): "Could not decode a value of type \(type)."
        case .obsoleteRecord(let found, let minimum): "Stored record version \(found) is older than the minimum supported version \(minimum)."
        case .unsupportedSchemaVersion(let version): "Stored record version \(version) is newer than this app supports."
        case .invalidKey: "The encryption key is invalid."
        case .keyNotFound(let id): "Encryption key \(id) was not found."
        case .keyRetired(let id): "Encryption key \(id) has been retired."
        case .cryptoFailure: "A cryptographic operation failed."
        case .tamperedData: "The data failed its integrity check. It is corrupted, was modified, or the wrong key or password was used."
        case .unsupportedFormat: "The data is not in a supported format."
        case .secureEnclaveUnavailable: "The Secure Enclave is not available on this device."
        case .tokenExpired: "The access token has expired and no refresher is configured."
        case .noRefreshToken: "The access token has expired and there is no refresh token."
        case .invalidConfiguration(let reason): "Invalid configuration: \(reason)"
        }
    }
}
