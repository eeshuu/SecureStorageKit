import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Whether data protection currently allows reading `whenUnlocked` items and
/// files with complete protection.
public enum ProtectedData {
    /// On iOS this is false while the device is locked. On macOS it is always true.
    @MainActor
    public static var isAvailable: Bool {
        #if canImport(UIKit) && !os(watchOS)
        UIApplication.shared.isProtectedDataAvailable
        #else
        true
        #endif
    }

    /// Throws `.protectedDataUnavailable` while the device is locked.
    @MainActor
    public static func requireAvailable() throws {
        guard isAvailable else { throw StorageError.protectedDataUnavailable }
    }
}
