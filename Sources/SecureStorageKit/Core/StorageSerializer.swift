import Foundation

/// Turns Codable values into bytes and back. Supply your own to use a format
/// other than JSON (for example Property Lists or Protocol Buffers).
public protocol StorageSerializer: Sendable {
    func encode<T: Encodable>(_ value: T) throws -> Data
    func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T
}

/// JSON serialization. Encoders are created per call, so they never cross threads.
public struct JSONStorageSerializer: StorageSerializer {
    private let makeEncoder: @Sendable () -> JSONEncoder
    private let makeDecoder: @Sendable () -> JSONDecoder

    public init(
        encoder: @escaping @Sendable () -> JSONEncoder = {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = .sortedKeys
            return encoder
        },
        decoder: @escaping @Sendable () -> JSONDecoder = {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return decoder
        }
    ) {
        makeEncoder = encoder
        makeDecoder = decoder
    }

    public func encode<T: Encodable>(_ value: T) throws -> Data {
        try makeEncoder().encode(value)
    }

    public func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try makeDecoder().decode(type, from: data)
    }
}

/// A Codable model whose stored layout can change between app versions.
///
/// Records are saved with their schema version. On read, older records are
/// passed to `migrate(from:data:serializer:)`; records older than
/// `minimumSupportedVersion` are reported as obsolete.
public protocol VersionedCodable: Codable {
    static var schemaVersion: Int { get }
    static var minimumSupportedVersion: Int { get }
    /// Converts a record stored with an older schema version.
    static func migrate(from version: Int, data: Data, serializer: any StorageSerializer) throws -> Self
}

extension VersionedCodable {
    public static var minimumSupportedVersion: Int { 1 }

    public static func migrate(from version: Int, data: Data, serializer: any StorageSerializer) throws -> Self {
        throw StorageError.obsoleteRecord(foundVersion: version, minimumSupported: schemaVersion)
    }
}

/// What `retrieveVersioned` does with a record that can't be migrated.
public enum ObsoleteRecordPolicy: Sendable {
    /// Throw `.obsoleteRecord` and leave the item in place.
    case `throw`
    /// Delete the item and return nil.
    case delete
}

struct RecordEnvelope: Codable {
    var schema: Int
    var payload: Data
}
