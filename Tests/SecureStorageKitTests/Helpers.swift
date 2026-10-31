import Foundation
@testable import SecureStorageKit

struct Profile: Codable, Equatable {
    var name: String
    var age: Int
}

func makeStorage(namespace: String = "default", environment: StorageEnvironment = .production,
                 backend: InMemoryKeychain = InMemoryKeychain(),
                 events: (@Sendable (StorageEvent) -> Void)? = nil) -> SecureStorage {
    SecureStorage(configuration: StorageConfiguration(service: "test-service", namespace: namespace,
                                                      environment: environment, eventHandler: events),
                  backend: backend)
}

final class EventCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [StorageEvent] = []
    var events: [StorageEvent] { lock.lock(); defer { lock.unlock() }; return _events }
    lazy var handler: @Sendable (StorageEvent) -> Void = { [unowned self] event in
        self.lock.lock(); self._events.append(event); self.lock.unlock()
    }
}

/// True if `body` throws exactly `expected`.
func expectError<T>(_ expected: StorageError, _ body: () async throws -> T) async -> Bool {
    do {
        _ = try await body()
        return false
    } catch let error as StorageError {
        return error == expected
    } catch {
        return false
    }
}
