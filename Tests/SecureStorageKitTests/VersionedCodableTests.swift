import Foundation
import Testing
@testable import SecureStorageKit

struct SettingsV1: VersionedCodable, Equatable {
    static let schemaVersion = 1
    var fullName: String
}

struct SettingsV2: VersionedCodable, Equatable {
    static let schemaVersion = 2
    var firstName: String
    var lastName: String

    static func migrate(from version: Int, data: Data, serializer: any StorageSerializer) throws -> SettingsV2 {
        let old = try serializer.decode(SettingsV1.self, from: data)
        let parts = old.fullName.split(separator: " ", maxSplits: 1).map(String.init)
        return SettingsV2(firstName: parts.first ?? "", lastName: parts.count > 1 ? parts[1] : "")
    }
}

struct SettingsV3: VersionedCodable, Equatable {
    static let schemaVersion = 3
    static let minimumSupportedVersion = 2
    var displayName: String

    static func migrate(from version: Int, data: Data, serializer: any StorageSerializer) throws -> SettingsV3 {
        let old = try serializer.decode(SettingsV2.self, from: data)
        return SettingsV3(displayName: "\(old.firstName) \(old.lastName)")
    }
}

@Suite("Versioned Codable")
struct VersionedCodableTests {
    @Test func roundTripsCurrentVersion() async throws {
        let storage = makeStorage()
        try await storage.saveVersioned(SettingsV2(firstName: "Ravi", lastName: "Kumar"), forKey: "s")
        #expect(try await storage.retrieveVersioned("s", as: SettingsV2.self) == SettingsV2(firstName: "Ravi", lastName: "Kumar"))
    }

    @Test func migratesAndResavesOlderRecords() async throws {
        let storage = makeStorage()
        try await storage.saveVersioned(SettingsV1(fullName: "Ravi Kumar"), forKey: "s")
        let migrated = try await storage.retrieveVersioned("s", as: SettingsV2.self)
        #expect(migrated == SettingsV2(firstName: "Ravi", lastName: "Kumar"))

        // The record was rewritten as v2, so v1 can no longer read it.
        #expect(await expectError(.unsupportedSchemaVersion(2)) { try await storage.retrieveVersioned("s", as: SettingsV1.self) })
    }

    @Test func obsoleteRecordsThrowOrDelete() async throws {
        let storage = makeStorage()
        try await storage.saveVersioned(SettingsV1(fullName: "Old"), forKey: "s")
        #expect(await expectError(.obsoleteRecord(foundVersion: 1, minimumSupported: 2)) {
            try await storage.retrieveVersioned("s", as: SettingsV3.self)
        })
        #expect(try await storage.contains("s"))

        #expect(try await storage.retrieveVersioned("s", as: SettingsV3.self, onObsolete: .delete) == nil)
        #expect(try await storage.contains("s") == false)
    }

    @Test func customSerializerIsUsed() async throws {
        struct PlistSerializer: StorageSerializer {
            func encode<T: Encodable>(_ value: T) throws -> Data { try PropertyListEncoder().encode(value) }
            func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T { try PropertyListDecoder().decode(type, from: data) }
        }
        let backend = InMemoryKeychain()
        let storage = SecureStorage(configuration: .init(service: "s", serializer: PlistSerializer()), backend: backend)
        try await storage.save(Profile(name: "A", age: 1), forKey: "p")
        let raw = try backend.read(storage.itemKey("p"), prompt: nil)
        #expect(raw.starts(with: Data("bplist".utf8)))
        #expect(try await storage.retrieve("p", as: Profile.self) == Profile(name: "A", age: 1))
    }
}
