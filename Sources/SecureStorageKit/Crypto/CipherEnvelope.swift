import Foundation

/// The self-describing, versioned format of encrypted data.
///
/// ```
/// "SSKE" | formatVersion (1) | algorithm (1) | keyID length (1) | keyID (UTF-8)
///        | nonce (12) | ciphertext (n) | tag (16)
/// ```
///
/// The header (everything before the nonce) is authenticated together with the
/// caller's associated data, so changing the key id, algorithm or version is
/// detected as tampering.
public struct CipherEnvelope: Sendable, Equatable {
    public enum Algorithm: UInt8, Sendable {
        case aes256GCM = 1
    }

    public static let magic = Data("SSKE".utf8)
    public static let currentFormatVersion: UInt8 = 1
    static let nonceSize = 12
    static let tagSize = 16

    public let formatVersion: UInt8
    public let algorithm: Algorithm
    /// Identifies the key that encrypted the data (for example `"default#3"`).
    public let keyID: String
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    init(keyID: String, nonce: Data, ciphertext: Data, tag: Data) {
        self.formatVersion = Self.currentFormatVersion
        self.algorithm = .aes256GCM
        self.keyID = keyID
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    /// Parses serialized bytes. Throws `.unsupportedFormat` for anything that
    /// isn't a well-formed envelope of a known version.
    public init(serialized data: Data) throws {
        let bytes = [UInt8](data)
        let magic = [UInt8](Self.magic)
        let fixedHeader = magic.count + 3
        guard bytes.count >= fixedHeader, Array(bytes[0..<magic.count]) == magic else { throw StorageError.unsupportedFormat }
        let version = bytes[magic.count]
        guard version == Self.currentFormatVersion else { throw StorageError.unsupportedFormat }
        guard let algorithm = Algorithm(rawValue: bytes[magic.count + 1]) else { throw StorageError.unsupportedFormat }
        let idLength = Int(bytes[magic.count + 2])
        let nonceStart = fixedHeader + idLength
        guard bytes.count >= nonceStart + Self.nonceSize + Self.tagSize,
              let keyID = String(bytes: bytes[fixedHeader..<nonceStart], encoding: .utf8) else {
            throw StorageError.unsupportedFormat
        }
        let tagStart = bytes.count - Self.tagSize
        self.formatVersion = version
        self.algorithm = algorithm
        self.keyID = keyID
        self.nonce = Data(bytes[nonceStart..<nonceStart + Self.nonceSize])
        self.ciphertext = Data(bytes[nonceStart + Self.nonceSize..<tagStart])
        self.tag = Data(bytes[tagStart...])
    }

    /// The authenticated header bytes.
    var header: Data {
        Self.header(keyID: keyID, version: formatVersion, algorithm: algorithm)
    }

    static func header(keyID: String, version: UInt8 = currentFormatVersion, algorithm: Algorithm = .aes256GCM) -> Data {
        var header = magic
        header.append(version)
        header.append(algorithm.rawValue)
        let id = Data(keyID.utf8)
        header.append(UInt8(id.count))
        header.append(id)
        return header
    }

    public func serialized() -> Data {
        var data = header
        data.append(nonce)
        data.append(ciphertext)
        data.append(tag)
        return data
    }

    /// Reads just the key id, for routing data to the right key during rotation.
    public static func keyID(of data: Data) throws -> String {
        try CipherEnvelope(serialized: data).keyID
    }
}
