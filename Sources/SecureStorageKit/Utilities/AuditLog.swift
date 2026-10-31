import Foundation

/// Keeps the most recent storage events in memory for diagnostics screens,
/// support bundles or your own analytics. Events never contain secret payloads.
///
/// ```swift
/// let audit = AuditLog()
/// var config = StorageConfiguration(service: "my-app")
/// config.eventHandler = audit.handler
/// ```
public final class AuditLog: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: [StorageEvent] = []
    private let forward: (@Sendable (StorageEvent) -> Void)?
    public let capacity: Int

    /// - Parameters:
    ///   - capacity: Oldest events are dropped beyond this count.
    ///   - forward: Also passes each event on, for example to `SecureLogger.unifiedLog`.
    public init(capacity: Int = 500, forward: (@Sendable (StorageEvent) -> Void)? = nil) {
        self.capacity = max(1, capacity)
        self.forward = forward
    }

    /// Assign this to `StorageConfiguration.eventHandler`.
    public var handler: @Sendable (StorageEvent) -> Void {
        { [weak self] event in self?.record(event) }
    }

    public func record(_ event: StorageEvent) {
        lock.lock()
        buffer.append(event)
        if buffer.count > capacity { buffer.removeFirst(buffer.count - capacity) }
        lock.unlock()
        forward?(event)
    }

    /// Recorded events, oldest first, optionally filtered.
    public func events(operation: StorageEvent.Operation? = nil, failuresOnly: Bool = false) -> [StorageEvent] {
        lock.lock()
        defer { lock.unlock() }
        return buffer.filter { event in
            (operation == nil || event.operation == operation)
                && (!failuresOnly || { if case .failure = event.outcome { return true }; return false }())
        }
    }

    public func clear() {
        lock.lock()
        buffer.removeAll()
        lock.unlock()
    }
}
