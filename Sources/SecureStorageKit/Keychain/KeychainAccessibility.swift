import Foundation
import Security

/// When a Keychain item can be read, and whether it may leave the device.
///
/// `ThisDeviceOnly` variants are never included in backups restored to another
/// device and are never synchronized through iCloud Keychain.
public enum KeychainAccessibility: String, Sendable, Codable, CaseIterable {
    /// Readable while the device is unlocked.
    case whenUnlocked
    /// Readable while the device is unlocked; never leaves this device.
    case whenUnlockedThisDeviceOnly
    /// Readable after the first unlock following a restart, including in the background.
    case afterFirstUnlock
    /// Readable after the first unlock; never leaves this device.
    case afterFirstUnlockThisDeviceOnly
    /// Readable only while a passcode is set; removed if the passcode is turned off.
    case whenPasscodeSetThisDeviceOnly

    public var isThisDeviceOnly: Bool {
        switch self {
        case .whenUnlocked, .afterFirstUnlock: false
        default: true
        }
    }

    var secValue: CFString {
        switch self {
        case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }
}
