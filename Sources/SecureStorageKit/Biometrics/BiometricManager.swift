import Foundation
import LocalAuthentication

public enum BiometryType: String, Sendable {
    case none, touchID, faceID, opticID
}

/// Whether biometric authentication can be used right now, and if not, why.
public enum BiometricAvailability: Sendable, Equatable {
    case available(BiometryType)
    case notEnrolled(BiometryType)
    case lockedOut(BiometryType)
    case passcodeNotSet
    case notSupported

    public var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }
}

/// Which credentials satisfy an authentication request.
public enum AuthenticationPolicy: Sendable {
    /// Face ID / Touch ID / Optic ID only.
    case biometrics
    /// Biometry, with the device passcode as fallback (and after lockout).
    case biometricsOrPasscode

    var laPolicy: LAPolicy {
        switch self {
        case .biometrics: .deviceOwnerAuthenticationWithBiometrics
        case .biometricsOrPasscode: .deviceOwnerAuthentication
        }
    }
}

/// Face ID / Touch ID availability, enrollment tracking and standalone authentication.
///
/// To protect a secret, prefer `ItemProtection` on the Keychain item: the system
/// then refuses to release the data without authentication. A standalone
/// `authenticate` call only gates UI and can be bypassed on a compromised device.
public struct BiometricManager: Sendable {
    public init() {}

    /// The biometry hardware on this device, whether or not it's enrolled.
    public var biometryType: BiometryType {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return Self.map(context.biometryType)
    }

    /// Current availability, distinguishing not enrolled, locked out and no passcode.
    public func availability(for policy: AuthenticationPolicy = .biometrics) -> BiometricAvailability {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(policy.laPolicy, error: &error)
        let type = Self.map(context.biometryType)
        if canEvaluate { return .available(type) }
        switch (error as? LAError)?.code {
        case .biometryNotEnrolled: return .notEnrolled(type)
        case .biometryLockout: return .lockedOut(type)
        case .passcodeNotSet: return .passcodeNotSet
        default: return .notSupported
        }
    }

    /// Shows the system authentication prompt.
    ///
    /// Throws `.userCancelled`, `.userFallback`, `.authenticationFailed`,
    /// `.biometryLockout`, `.biometryNotEnrolled` or `.biometryNotAvailable`.
    public func authenticate(reason: String, policy: AuthenticationPolicy = .biometricsOrPasscode,
                             fallbackTitle: String? = nil, cancelTitle: String? = nil) async throws {
        let context = LAContext()
        if let fallbackTitle { context.localizedFallbackTitle = fallbackTitle }
        if let cancelTitle { context.localizedCancelTitle = cancelTitle }
        do {
            let success = try await context.evaluatePolicy(policy.laPolicy, localizedReason: reason)
            if !success { throw StorageError.authenticationFailed }
        } catch {
            throw StorageError(authenticationError: error)
        }
    }

    /// An opaque value that changes when fingers or faces are added or removed.
    /// Store it and compare later with `hasEnrollmentChanged(since:)`.
    public func enrollmentState() -> Data? {
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return nil }
        if #available(iOS 18.0, macOS 15.0, *) {
            return context.domainState.biometry.stateHash
        }
        return context.evaluatedPolicyDomainState
    }

    /// True if enrollment differs from a previously saved `enrollmentState()`.
    /// Items saved with `.biometryCurrentSet` are unreadable after such a change.
    public func hasEnrollmentChanged(since previous: Data?) -> Bool {
        enrollmentState() != previous
    }

    static func map(_ type: LABiometryType) -> BiometryType {
        switch type {
        case .faceID: return .faceID
        case .touchID: return .touchID
        case .none: return .none
        default:
            if #available(iOS 17.0, macOS 14.0, *), type == .opticID { return .opticID }
            return .none
        }
    }
}
