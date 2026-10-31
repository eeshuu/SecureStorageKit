import CryptoKit
import Foundation
import LocalAuthentication

/// P-256 keys generated inside the Secure Enclave.
///
/// The private key never leaves the Secure Enclave. What is stored in the
/// Keychain is an opaque, device-bound handle that only this device's Secure
/// Enclave can use. The Secure Enclave does not run AES-GCM itself: `seal`/`open`
/// use it for ECDH key agreement and derive an AES-256-GCM key from the result.
public struct SecureEnclaveManager: Sendable {
    private let storage: SecureStorage

    /// - Parameter storage: Where key handles are kept. Use a dedicated namespace.
    public init(storage: SecureStorage) {
        self.storage = storage
    }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    // MARK: Signing

    /// Creates (or replaces) a signing key and returns its public key.
    ///
    /// - Parameter protection: Authentication the Secure Enclave requires before each signature.
    @discardableResult
    public func createSigningKey(tag: String, protection: ItemProtection = .none) async throws -> P256.Signing.PublicKey {
        try Self.requireAvailable()
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: try Self.accessControl(protection))
        try await storage.saveData(key.dataRepresentation, forKey: Self.signingKey(tag))
        return key.publicKey
    }

    public func signingPublicKey(tag: String) async throws -> P256.Signing.PublicKey {
        try await signingPrivateKey(tag: tag, prompt: nil).publicKey
    }

    /// Signs `data` with ECDSA P-256 / SHA-256. Returns the DER signature.
    public func sign(_ data: Data, tag: String, prompt: AuthenticationPrompt? = nil) async throws -> Data {
        let key = try await signingPrivateKey(tag: tag, prompt: prompt)
        do {
            return try key.signature(for: data).derRepresentation
        } catch {
            throw StorageError(authenticationError: error)
        }
    }

    /// Verifies a DER signature with any P-256 public key (no Secure Enclave needed).
    public static func verify(_ signature: Data, for data: Data, publicKey: P256.Signing.PublicKey) -> Bool {
        guard let parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
        return publicKey.isValidSignature(parsed, for: data)
    }

    // MARK: Sealing via key agreement

    /// Creates (or replaces) a key-agreement key used by `seal` and `open`.
    @discardableResult
    public func createAgreementKey(tag: String, protection: ItemProtection = .none) async throws -> P256.KeyAgreement.PublicKey {
        try Self.requireAvailable()
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: try Self.accessControl(protection))
        try await storage.saveData(key.dataRepresentation, forKey: Self.agreementKey(tag))
        return key.publicKey
    }

    public func agreementPublicKey(tag: String) async throws -> P256.KeyAgreement.PublicKey {
        try await agreementPrivateKey(tag: tag, prompt: nil).publicKey
    }

    /// Encrypts `data` so only the Secure Enclave key `tag` can decrypt it.
    /// Needs only the public key, so it never prompts.
    public func seal(_ data: Data, toKeyTag tag: String, associatedData: Data = Data()) async throws -> Data {
        try Self.seal(data, to: try await agreementPublicKey(tag: tag), associatedData: associatedData)
    }

    /// Encrypts `data` for a P-256 public key (ECIES-style: ephemeral ECDH, HKDF-SHA256, AES-256-GCM).
    public static func seal(_ data: Data, to recipient: P256.KeyAgreement.PublicKey, associatedData: Data = Data()) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralPublic = ephemeral.publicKey.x963Representation
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let key = derive(secret, ephemeralPublic: ephemeralPublic, recipient: recipient.x963Representation)
        let sealed = try EncryptionManager().seal(data, using: key, keyID: "se-ecies", associatedData: ephemeralPublic + associatedData)
        return Data([sealFormatVersion]) + ephemeralPublic + sealed
    }

    /// Decrypts data produced by `seal`. Prompts if the key is protected.
    public func open(_ sealed: Data, keyTag tag: String, associatedData: Data = Data(), prompt: AuthenticationPrompt? = nil) async throws -> Data {
        let key = try await agreementPrivateKey(tag: tag, prompt: prompt)
        let bytes = [UInt8](sealed)
        guard bytes.count > 66, bytes[0] == Self.sealFormatVersion else { throw StorageError.unsupportedFormat }
        let ephemeralPublic = Data(bytes[1...65])
        do {
            let sender = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
            let secret = try key.sharedSecretFromKeyAgreement(with: sender)
            let symmetric = Self.derive(secret, ephemeralPublic: ephemeralPublic, recipient: key.publicKey.x963Representation)
            return try EncryptionManager().open(Data(bytes[66...]), using: symmetric, associatedData: ephemeralPublic + associatedData)
        } catch let error as StorageError {
            throw error
        } catch {
            throw StorageError(authenticationError: error)
        }
    }

    // MARK: Management

    public func deleteKey(tag: String) async throws {
        try await storage.delete(Self.signingKey(tag))
        try await storage.delete(Self.agreementKey(tag))
    }

    public func hasKey(tag: String) async throws -> Bool {
        let signing = try await storage.contains(Self.signingKey(tag))
        let agreement = try await storage.contains(Self.agreementKey(tag))
        return signing || agreement
    }

    // MARK: Internals

    private static let sealFormatVersion: UInt8 = 1

    private static func signingKey(_ tag: String) -> String { "se.sign.\(tag)" }
    private static func agreementKey(_ tag: String) -> String { "se.agree.\(tag)" }

    private static func requireAvailable() throws {
        guard SecureEnclave.isAvailable else { throw StorageError.secureEnclaveUnavailable }
    }

    private static func accessControl(_ protection: ItemProtection) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        switch protection {
        case .none: break
        case .userPresence: flags.insert(.userPresence)
        case .biometryAny: flags.insert(.biometryAny)
        case .biometryCurrentSet: flags.insert(.biometryCurrentSet)
        case .devicePasscode: flags.insert(.devicePasscode)
        case .biometryAnyOrPasscode: flags.formUnion([.biometryAny, .or, .devicePasscode])
        case .biometryCurrentSetOrPasscode: flags.formUnion([.biometryCurrentSet, .or, .devicePasscode])
        default: throw StorageError.invalidConfiguration("unsupported Secure Enclave protection \(protection)")
        }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw StorageError.invalidConfiguration("could not create Secure Enclave access control")
        }
        return control
    }

    private static func context(_ prompt: AuthenticationPrompt?) -> LAContext? {
        prompt.map(SystemKeychain.context(for:))
    }

    private func handle(_ key: String, tag: String) async throws -> Data {
        try Self.requireAvailable()
        guard let data = try await storage.retrieveData(key) else { throw StorageError.keyNotFound(id: tag) }
        return data
    }

    private func signingPrivateKey(tag: String, prompt: AuthenticationPrompt?) async throws -> SecureEnclave.P256.Signing.PrivateKey {
        let data = try await handle(Self.signingKey(tag), tag: tag)
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: Self.context(prompt))
        } catch {
            throw StorageError.invalidKey
        }
    }

    private func agreementPrivateKey(tag: String, prompt: AuthenticationPrompt?) async throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        let data = try await handle(Self.agreementKey(tag), tag: tag)
        do {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data, authenticationContext: Self.context(prompt))
        } catch {
            throw StorageError.invalidKey
        }
    }

    private static func derive(_ secret: SharedSecret, ephemeralPublic: Data, recipient: Data) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralPublic,
                                       sharedInfo: Data("SecureStorageKit SE seal v1".utf8) + recipient,
                                       outputByteCount: 32)
    }
}
