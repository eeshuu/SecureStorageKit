import CryptoKit
import Foundation
import os

/// A non-sensitive record of one storage operation. Events never contain
/// values, tokens or key material; keys appear only as a short one-way fingerprint.
public struct StorageEvent: Sendable, Equatable {
    public enum Operation: String, Sendable {
        case save, read, delete, clear, list
        case encrypt, decrypt, keyCreate, keyRotate, keyRetire
        case tokenRefresh, logout
        case export, `import`, migrate
    }

    public enum Outcome: Sendable, Equatable {
        case success
        case notFound
        case failure(StorageError)
    }

    public let operation: Operation
    public let namespace: String
    public let keyFingerprint: String?
    public let outcome: Outcome
    public let timestamp: Date

    public init(operation: Operation, namespace: String, key: String?, outcome: Outcome, timestamp: Date = Date()) {
        self.operation = operation
        self.namespace = namespace
        self.keyFingerprint = key.map(Self.fingerprint)
        self.outcome = outcome
        self.timestamp = timestamp
    }

    /// First 8 bytes of SHA-256, hex. Lets you correlate events for one key without revealing it.
    public static func fingerprint(_ key: String) -> String {
        SHA256.hash(data: Data(key.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}

/// Logs storage events to the unified log with privacy-preserving formatting.
///
/// ```swift
/// var config = StorageConfiguration(service: "my-app")
/// config.eventHandler = SecureLogger.unifiedLog
/// ```
public enum SecureLogger {
    static let logger = Logger(subsystem: "SecureStorageKit", category: "storage")

    /// Sends each event to `os.Logger`. The key fingerprint is marked private.
    public static let unifiedLog: @Sendable (StorageEvent) -> Void = { event in
        switch event.outcome {
        case .success, .notFound:
            logger.debug("\(event.operation.rawValue, privacy: .public) ns=\(event.namespace, privacy: .public) key=\(event.keyFingerprint ?? "-", privacy: .private) outcome=\(String(describing: event.outcome), privacy: .public)")
        case .failure(let error):
            logger.error("\(event.operation.rawValue, privacy: .public) ns=\(event.namespace, privacy: .public) key=\(event.keyFingerprint ?? "-", privacy: .private) failed: \(String(describing: error), privacy: .public)")
        }
    }
}

/// Wraps a sensitive value so it prints as `<redacted>` in logs, `print`,
/// `dump`, string interpolation and the debugger's summary.
///
/// This prevents accidental exposure; it does not encrypt or wipe memory.
public struct Redacted<Value>: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var value: Value

    public init(_ value: Value) { self.value = value }

    public var description: String { "<redacted>" }
    public var debugDescription: String { "<redacted>" }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

extension Redacted: Sendable where Value: Sendable {}
extension Redacted: Equatable where Value: Equatable {}
extension Redacted: Hashable where Value: Hashable {}

extension NSLock {
    /// `withLock` is only available from iOS 16 / macOS 13.
    func sync<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
