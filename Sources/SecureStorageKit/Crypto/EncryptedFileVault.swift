import CryptoKit
import Foundation

/// Authenticated, streaming file encryption.
///
/// Files are encrypted in chunks so large files never have to fit in memory.
/// Each chunk is sealed with AES-256-GCM using a nonce built from a random
/// per-file prefix, the chunk index and a final-chunk flag, and the file header
/// is authenticated with every chunk. Reordering, dropping, duplicating or
/// truncating chunks, or editing the header, is detected as `.tamperedData`.
///
/// ```
/// "SSKF" | version (1) | chunkSize (4, BE) | keyID length (1) | keyID | noncePrefix (7)
/// chunk*: ciphertext (≤ chunkSize) | tag (16)
/// ```
///
/// Output is written to a temporary file next to the destination and moved
/// into place only after every chunk is processed, so a failed decryption never
/// leaves partial plaintext at the destination.
public struct EncryptedFileVault: Sendable {
    public let keyManager: KeyManager
    public let keyName: String
    public let chunkSize: Int

    static let magic = Data("SSKF".utf8)
    static let version: UInt8 = 1
    static let prefixSize = 7
    static let tagSize = 16

    public init(keyManager: KeyManager, keyName: String = "file-vault", chunkSize: Int = 64 * 1024) {
        self.keyManager = keyManager
        self.keyName = keyName
        self.chunkSize = max(1024, min(chunkSize, 16 * 1024 * 1024))
    }

    // MARK: Files

    public func encryptFile(at source: URL, to destination: URL) async throws {
        let (keyID, key) = try await keyManager.currentKey(named: keyName)
        let chunkSize = self.chunkSize
        try await Self.offMain {
            let input = try FileHandle(forReadingFrom: source)
            defer { try? input.close() }
            try Self.writeAtomically(to: destination) { output in
                var prefix = Data(count: Self.prefixSize)
                prefix.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, Self.prefixSize, $0.baseAddress!) }
                let header = Self.header(chunkSize: chunkSize, keyID: keyID, prefix: prefix)
                try output.write(contentsOf: header)

                var index: UInt32 = 0
                var chunk = try input.read(upToCount: chunkSize) ?? Data()
                while true {
                    let next = try input.read(upToCount: chunkSize) ?? Data()
                    let isFinal = next.isEmpty
                    let box = try AES.GCM.seal(chunk, using: key, nonce: try Self.nonce(prefix, index, isFinal), authenticating: header)
                    try output.write(contentsOf: box.ciphertext + box.tag)
                    if isFinal { break }
                    guard index < UInt32.max else { throw StorageError.invalidConfiguration("file too large") }
                    index += 1
                    chunk = next
                }
            }
        }
    }

    public func decryptFile(at source: URL, to destination: URL) async throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let (header, chunkSize, keyID, prefix) = try Self.readHeader { try input.read(upToCount: $0) }
        let key = try await keyManager.key(withID: keyID)
        try await Self.offMain {
            try Self.writeAtomically(to: destination) { output in
                try Self.decryptChunks({ try input.read(upToCount: $0) }, header: header, chunkSize: chunkSize, prefix: prefix, key: key) {
                    try output.write(contentsOf: $0)
                }
            }
        }
    }

    // MARK: In memory

    /// Encrypts data into the vault file format, without touching the disk.
    public func encrypt(_ data: Data) async throws -> Data {
        let (keyID, key) = try await keyManager.currentKey(named: keyName)
        var prefix = Data(count: Self.prefixSize)
        prefix.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, Self.prefixSize, $0.baseAddress!) }
        let header = Self.header(chunkSize: chunkSize, keyID: keyID, prefix: prefix)
        var output = header
        var offset = data.startIndex
        var index: UInt32 = 0
        repeat {
            let end = min(offset + chunkSize, data.endIndex)
            let isFinal = end == data.endIndex
            let box = try AES.GCM.seal(data[offset..<end], using: key, nonce: try Self.nonce(prefix, index, isFinal), authenticating: header)
            output.append(box.ciphertext + box.tag)
            offset = end
            index += 1
        } while offset < data.endIndex
        return output
    }

    /// Decrypts vault-format data in memory, so no plaintext is written to disk.
    public func decrypt(_ data: Data) async throws -> Data {
        var offset = data.startIndex
        let read: (Int) -> Data? = { count in
            guard offset < data.endIndex else { return nil }
            let end = min(offset + count, data.endIndex)
            defer { offset = end }
            return Data(data[offset..<end])
        }
        let (header, chunkSize, keyID, prefix) = try Self.readHeader(read)
        let key = try await keyManager.key(withID: keyID)
        var output = Data()
        try Self.decryptChunks(read, header: header, chunkSize: chunkSize, prefix: prefix, key: key) { output.append($0) }
        return output
    }

    /// The key id a vault file was encrypted with, for rotation.
    public static func keyID(ofFileAt url: URL) throws -> String {
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        return try readHeader { try input.read(upToCount: $0) }.keyID
    }

    // MARK: Format

    static func header(chunkSize: Int, keyID: String, prefix: Data) -> Data {
        var header = magic
        header.append(version)
        withUnsafeBytes(of: UInt32(chunkSize).bigEndian) { header.append(contentsOf: $0) }
        let id = Data(keyID.utf8)
        header.append(UInt8(id.count))
        header.append(id)
        header.append(prefix)
        return header
    }

    static func readHeader(_ read: (Int) throws -> Data?) throws -> (header: Data, chunkSize: Int, keyID: String, prefix: Data) {
        guard let fixed = try read(10), fixed.count == 10,
              fixed.prefix(4) == magic, fixed[fixed.startIndex + 4] == version else {
            throw StorageError.unsupportedFormat
        }
        let bytes = [UInt8](fixed)
        let chunkSize = Int(UInt32(bytes[5]) << 24 | UInt32(bytes[6]) << 16 | UInt32(bytes[7]) << 8 | UInt32(bytes[8]))
        let idLength = Int(bytes[9])
        guard chunkSize >= 1024, chunkSize <= 16 * 1024 * 1024,
              let rest = try read(idLength + prefixSize), rest.count == idLength + prefixSize,
              let keyID = String(data: rest.prefix(idLength), encoding: .utf8) else {
            throw StorageError.unsupportedFormat
        }
        return (fixed + rest, chunkSize, keyID, Data(rest.suffix(prefixSize)))
    }

    static func nonce(_ prefix: Data, _ index: UInt32, _ isFinal: Bool) throws -> AES.GCM.Nonce {
        var bytes = prefix
        withUnsafeBytes(of: index.bigEndian) { bytes.append(contentsOf: $0) }
        bytes.append(isFinal ? 1 : 0)
        return try AES.GCM.Nonce(data: bytes)
    }

    static func decryptChunks(_ read: (Int) throws -> Data?, header: Data, chunkSize: Int, prefix: Data, key: SymmetricKey,
                              emit: (Data) throws -> Void) throws {
        let sealedSize = chunkSize + tagSize
        var index: UInt32 = 0
        guard var chunk = try read(sealedSize), chunk.count >= tagSize else { throw StorageError.tamperedData }
        while true {
            let next = try read(sealedSize) ?? Data()
            let isFinal = next.isEmpty
            // A non-final chunk must be full size; a short one means truncation or splicing.
            if !isFinal && chunk.count != sealedSize { throw StorageError.tamperedData }
            do {
                let box = try AES.GCM.SealedBox(nonce: try nonce(prefix, index, isFinal),
                                                ciphertext: chunk.prefix(chunk.count - tagSize),
                                                tag: chunk.suffix(tagSize))
                try emit(try AES.GCM.open(box, using: key, authenticating: header))
            } catch {
                throw StorageError.tamperedData
            }
            if isFinal { return }
            guard next.count >= tagSize, index < UInt32.max else { throw StorageError.tamperedData }
            index += 1
            chunk = next
        }
    }

    static func writeAtomically(to destination: URL, _ body: (FileHandle) throws -> Void) throws {
        let fm = FileManager.default
        let temp = destination.deletingLastPathComponent().appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
        var attributes: [FileAttributeKey: Any] = [:]
        #if os(iOS) || os(visionOS)
        attributes[.protectionKey] = FileProtectionType.complete
        #endif
        guard fm.createFile(atPath: temp.path, contents: nil, attributes: attributes) else {
            throw StorageError.invalidConfiguration("can't create a file next to \(destination.lastPathComponent)")
        }
        do {
            let output = try FileHandle(forWritingTo: temp)
            do {
                try body(output)
                try output.synchronize()
                try output.close()
            } catch {
                try? output.close()
                throw error
            }
            if fm.fileExists(atPath: destination.path) {
                _ = try fm.replaceItemAt(destination, withItemAt: temp)
            } else {
                try fm.moveItem(at: temp, to: destination)
            }
        } catch {
            try? fm.removeItem(at: temp)
            if let storageError = error as? StorageError { throw storageError }
            if error is CryptoKitError { throw StorageError.cryptoFailure }
            throw error
        }
    }

    static func offMain(_ work: @escaping @Sendable () throws -> Void) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try work() })
            }
        }
    }
}
