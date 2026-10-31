import CryptoKit
import Foundation

/// AES-256-GCM authenticated encryption into a versioned `CipherEnvelope`.
///
/// Use it for data that lives outside the Keychain (files, databases, caches);
/// the Keychain already encrypts its own items. To manage keys and rotation,
/// use `KeyManager`, which calls this for you.
public struct EncryptionManager: Sendable {
    public init() {}

    /// Encrypts with a fresh random nonce.
    ///
    /// - Parameters:
    ///   - keyID: Recorded in the envelope so the right key can be found later. Max 255 bytes.
    ///   - associatedData: Authenticated but not encrypted context, such as a record id.
    ///     The same bytes must be passed to `decrypt`.
    public func encrypt(_ plaintext: Data, using key: SymmetricKey, keyID: String, associatedData: Data = Data()) throws -> CipherEnvelope {
        try Self.validate(key)
        guard Data(keyID.utf8).count <= 255 else { throw StorageError.invalidConfiguration("key id longer than 255 bytes") }
        let header = CipherEnvelope.header(keyID: keyID)
        do {
            let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: header + associatedData)
            return CipherEnvelope(keyID: keyID, nonce: Data(box.nonce), ciphertext: box.ciphertext, tag: box.tag)
        } catch {
            throw StorageError.cryptoFailure
        }
    }

    /// Decrypts and verifies. Throws `.tamperedData` if the ciphertext, tag,
    /// header or associated data were changed, or the key is wrong.
    public func decrypt(_ envelope: CipherEnvelope, using key: SymmetricKey, associatedData: Data = Data()) throws -> Data {
        try Self.validate(key)
        guard envelope.algorithm == .aes256GCM else { throw StorageError.unsupportedFormat }
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: envelope.nonce), ciphertext: envelope.ciphertext, tag: envelope.tag)
            return try AES.GCM.open(box, using: key, authenticating: envelope.header + associatedData)
        } catch CryptoKitError.authenticationFailure {
            throw StorageError.tamperedData
        } catch {
            throw StorageError.tamperedData
        }
    }

    /// Encrypts and serializes in one step.
    public func seal(_ plaintext: Data, using key: SymmetricKey, keyID: String, associatedData: Data = Data()) throws -> Data {
        try encrypt(plaintext, using: key, keyID: keyID, associatedData: associatedData).serialized()
    }

    /// Parses and decrypts in one step.
    public func open(_ sealed: Data, using key: SymmetricKey, associatedData: Data = Data()) throws -> Data {
        try decrypt(CipherEnvelope(serialized: sealed), using: key, associatedData: associatedData)
    }

    /// A new random 256-bit key from the system's secure random generator.
    public static func generateKey() -> SymmetricKey {
        SymmetricKey(size: .bits256)
    }

    /// Derives a 256-bit sub-key with HKDF-SHA256, for example one key per
    /// account or purpose from a single master key.
    public static func deriveKey(from key: SymmetricKey, salt: Data, info: Data, outputByteCount: Int = 32) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: outputByteCount)
    }

    static func validate(_ key: SymmetricKey) throws {
        guard key.bitCount == 256 else { throw StorageError.invalidKey }
    }
}
