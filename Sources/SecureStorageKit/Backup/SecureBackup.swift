import CommonCrypto
import CryptoKit
import Foundation

/// Password-protected, authenticated backup of one `SecureStorage` namespace.
///
/// Format: `"SSKB" | header length (4, BE) | header JSON | CipherEnvelope`.
/// The key is derived from the password with PBKDF2-HMAC-SHA256 and a random
/// salt; the header (format, KDF, iterations, salt) is authenticated with the
/// payload, so it can't be swapped or downgraded.
///
/// **Recovery policy.** There is no escrow and no recovery: a forgotten password
/// means the backup can't be opened. A wrong password and a corrupted file both
/// throw `.tamperedData`. Items that need Face ID / Touch ID / passcode are
/// skipped by default and listed in the report, so a backup never weakens an
/// item's protection; imported items get the destination's default protection.
public enum SecureBackup {
    public static let minimumPasswordLength = 10
    public static let defaultIterations = 600_000

    static let magic = Data("SSKB".utf8)

    public struct ExportReport: Sendable, Equatable {
        public var exported: [String] = []
        public var skippedProtected: [String] = []
    }

    public struct ImportReport: Sendable, Equatable {
        public var imported: [String] = []
        public var skippedExisting: [String] = []
    }

    struct Header: Codable {
        var format = "ssk-backup"
        var version = 1
        var kdf = "pbkdf2-hmac-sha256"
        var iterations: Int
        var salt: Data
        var createdAt: Date
    }

    struct Payload: Codable {
        var namespace: String
        var items: [String: Data]
    }

    /// Exports every readable item in `storage`'s namespace.
    public static func export(from storage: SecureStorage, password: String,
                              iterations: Int = defaultIterations) async throws -> (backup: Data, report: ExportReport) {
        guard password.count >= minimumPasswordLength else {
            throw StorageError.invalidConfiguration("backup password must be at least \(minimumPasswordLength) characters")
        }
        guard iterations >= 100_000 else { throw StorageError.invalidConfiguration("use at least 100,000 PBKDF2 iterations") }

        var report = ExportReport()
        var items: [String: Data] = [:]
        for key in try await storage.allKeys() {
            do {
                if let data = try await storage.retrieveData(key, prompt: .noInteraction) {
                    items[key] = data
                    report.exported.append(key)
                }
            } catch StorageError.interactionNotAllowed {
                report.skippedProtected.append(key)
            }
        }

        let salt = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
        let header = Header(iterations: iterations, salt: salt, createdAt: Date())
        let headerBytes = try encoder().encode(header)
        let payload = try encoder().encode(Payload(namespace: storage.configuration.namespace, items: items))
        let key = try deriveKey(password: password, salt: salt, iterations: iterations)

        var prefix = magic
        withUnsafeBytes(of: UInt32(headerBytes.count).bigEndian) { prefix.append(contentsOf: $0) }
        prefix.append(headerBytes)
        let sealed = try EncryptionManager().seal(payload, using: key, keyID: "backup", associatedData: prefix)
        storage.configuration.eventHandler?(StorageEvent(operation: .export, namespace: storage.configuration.namespace, key: nil, outcome: .success))
        return (prefix + sealed, report)
    }

    /// Restores items into `storage`'s namespace.
    public static func `import`(_ backup: Data, password: String, into storage: SecureStorage,
                                overwrite: Bool = false) async throws -> ImportReport {
        let bytes = [UInt8](backup)
        guard bytes.count > 8, Data(bytes[0..<4]) == magic else { throw StorageError.unsupportedFormat }
        let headerLength = Int(UInt32(bytes[4]) << 24 | UInt32(bytes[5]) << 16 | UInt32(bytes[6]) << 8 | UInt32(bytes[7]))
        guard headerLength < 4096, bytes.count > 8 + headerLength else { throw StorageError.unsupportedFormat }
        let headerBytes = Data(bytes[8..<8 + headerLength])
        guard let header = try? JSONDecoder.iso().decode(Header.self, from: headerBytes),
              header.format == "ssk-backup", header.version == 1, header.kdf == "pbkdf2-hmac-sha256",
              (100_000...10_000_000).contains(header.iterations), header.salt.count >= 16 else {
            throw StorageError.unsupportedFormat
        }

        let key = try deriveKey(password: password, salt: header.salt, iterations: header.iterations)
        let plaintext = try EncryptionManager().open(Data(bytes[(8 + headerLength)...]), using: key,
                                                     associatedData: Data(bytes[0..<8 + headerLength]))
        guard let payload = try? JSONDecoder.iso().decode(Payload.self, from: plaintext) else { throw StorageError.unsupportedFormat }

        var report = ImportReport()
        for (itemKey, data) in payload.items.sorted(by: { $0.key < $1.key }) {
            if !overwrite, try await storage.contains(itemKey) {
                report.skippedExisting.append(itemKey)
                continue
            }
            try await storage.saveData(data, forKey: itemKey)
            report.imported.append(itemKey)
        }
        storage.configuration.eventHandler?(StorageEvent(operation: .import, namespace: storage.configuration.namespace, key: nil, outcome: .success))
        return report
    }

    static func deriveKey(password: String, salt: Data, iterations: Int) throws -> SymmetricKey {
        var derived = Data(count: 32)
        let passwordBytes = Array(password.utf8)
        let status = derived.withUnsafeMutableBytes { out in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                     passwordBytes.map { CChar(bitPattern: $0) }, passwordBytes.count,
                                     saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                                     out.bindMemory(to: UInt8.self).baseAddress, 32)
            }
        }
        guard status == kCCSuccess else { throw StorageError.cryptoFailure }
        return SymmetricKey(data: derived)
    }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        return encoder
    }
}

private extension JSONDecoder {
    static func iso() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
