import Foundation
import Security

/// Authentication the Keychain itself enforces before releasing an item.
///
/// This is an access control on the item, not a separate prompt shown by the
/// app: the system refuses to return the data until the user authenticates.
public struct ItemProtection: Sendable, Hashable, CustomStringConvertible {
    let rawFlags: UInt?
    public let description: String

    private init(_ name: String, _ flags: SecAccessControlCreateFlags?) {
        description = name
        rawFlags = flags?.rawValue
    }

    /// No authentication beyond the item's accessibility.
    public static let none = ItemProtection("none", nil)

    /// Face ID, Touch ID or the device passcode.
    public static let userPresence = ItemProtection("userPresence", .userPresence)

    /// Any enrolled biometry. Items stay readable after fingers or faces are added.
    public static let biometryAny = ItemProtection("biometryAny", .biometryAny)

    /// The biometry enrolled right now. Adding or removing a finger or face
    /// makes the item permanently unreadable.
    public static let biometryCurrentSet = ItemProtection("biometryCurrentSet", .biometryCurrentSet)

    /// The device passcode only.
    public static let devicePasscode = ItemProtection("devicePasscode", .devicePasscode)

    /// Current biometry, falling back to the device passcode.
    public static let biometryCurrentSetOrPasscode = ItemProtection(
        "biometryCurrentSetOrPasscode", [.biometryCurrentSet, .or, .devicePasscode])

    /// Any biometry, falling back to the device passcode.
    public static let biometryAnyOrPasscode = ItemProtection(
        "biometryAnyOrPasscode", [.biometryAny, .or, .devicePasscode])

    public var requiresAuthentication: Bool { rawFlags != nil }

    /// True when a change to biometric enrollment invalidates the item.
    public var invalidatedByEnrollmentChange: Bool {
        guard let rawFlags else { return false }
        return SecAccessControlCreateFlags(rawValue: rawFlags).contains(.biometryCurrentSet)
    }

    /// Builds the access control object for `SecItemAdd`.
    func accessControl(accessibility: KeychainAccessibility, extraFlags: SecAccessControlCreateFlags = []) throws -> SecAccessControl? {
        guard rawFlags != nil || !extraFlags.isEmpty else { return nil }
        let flags = SecAccessControlCreateFlags(rawValue: rawFlags ?? 0).union(extraFlags)
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, accessibility.secValue, flags, &error) else {
            let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? -1
            throw StorageError.invalidConfiguration("could not create access control (\(code))")
        }
        return control
    }
}
