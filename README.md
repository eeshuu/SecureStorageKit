# SecureStorageKit

A Swift package for storing secrets on iOS, iPadOS and macOS. It is serverless and built on the Keychain, LocalAuthentication, CryptoKit and the Secure Enclave. It has no third-party dependencies.

Free and open: one library, every feature included.

| Area | Features |
|---|---|
| Keychain | Save, read, update and delete Strings, Data and Codable values. Scoped clear, accessibility options, access groups, iCloud sync, typed errors, migration from legacy Keychain wrappers. |
| Biometrics | Item-level Face ID / Touch ID / passcode protection, `biometryCurrentSet`, availability checks and lockout. |
| Crypto | AES-256-GCM in a versioned envelope, HKDF, key manager (create, rotate, retire), recoverable key rotation engine, streaming encrypted file vault, Secure Enclave signing and sealing. |
| Accounts | Token store with refresh, per-account isolation and logout cleanup; multi-account vault. |
| Ops | Redacted logging, audit log, in-memory mock, versioned Codable migrations, password-protected backup and restore. |

**Requirements:** iOS 15+, macOS 12+, Mac Catalyst 15+, Swift 6 toolchain (Xcode 16 or later).

## Installation

In Xcode, choose **File ▸ Add Package Dependencies…** and add the repository URL. Alternatively, add it to `Package.swift`:

```swift
.package(url: "https://github.com/eeshuu/SecureStorageKit.git", from: "1.0.0"),
// …
.target(name: "App", dependencies: [
    .product(name: "SecureStorageKit", package: "SecureStorageKit"),
]),
```

## Quick start

```swift
import SecureStorageKit

let storage = SecureStorage(service: "my-app")

try await storage.save("secret", forKey: "access_token")
let token: String? = try await storage.retrieve("access_token", as: String.self)
try await storage.delete("access_token")
try await storage.clearAll()               // only this namespace, nothing else

// Protected by the Keychain item itself: no Face ID, no data.
try await storage.save("private", forKey: "vault", protection: .biometryCurrentSet)
let value: String? = try await storage.retrieve("vault", as: String.self,
                                                authenticationReason: "Unlock secure data")
```

`retrieve` returns `nil` when the key doesn't exist. Every failure is a typed `StorageError`.

### Codable values and schema migrations

```swift
struct Profile: Codable { var name: String }
try await storage.save(Profile(name: "Asha"), forKey: "profile")
let profile = try await storage.retrieve("profile", as: Profile.self)

// Models whose layout changes between releases:
struct SettingsV2: VersionedCodable {
    static let schemaVersion = 2
    var firstName: String
    var lastName: String
    static func migrate(from version: Int, data: Data, serializer: any StorageSerializer) throws -> Self { … }
}
try await storage.saveVersioned(settings, forKey: "settings")
let settings = try await storage.retrieveVersioned("settings", as: SettingsV2.self, onObsolete: .delete)
```

### Configuration and isolation

```swift
let config = StorageConfiguration(
    service: "my-app",
    namespace: "payments",                    // clearAll() only touches this namespace
    environment: .development,                // debug builds never see production data
    accessibility: .afterFirstUnlockThisDeviceOnly,
    protection: .none,
    accessGroup: "<TeamID>.shared", // share with app extensions (entitlement required)
    synchronizable: false,                    // true = iCloud Keychain (not with ThisDeviceOnly/protection)
    eventHandler: SecureLogger.unifiedLog)
let payments = SecureStorage(configuration: config)
let other = payments.namespaced("drafts")
```

All SDK items are stored under the account prefix `ssk/<namespace>/`. That prefix is how `clearAll()` leaves Keychain items written by other code untouched.

### Biometrics

```swift
let bio = BiometricManager()
switch bio.availability() {
case .available(.faceID): …
case .notEnrolled, .lockedOut, .passcodeNotSet, .notSupported, .available: …
}

let saved = bio.enrollmentState()
if bio.hasEnrollmentChanged(since: saved) { /* .biometryCurrentSet items are gone */ }

let prompt = AuthenticationPrompt(reason: "Unlock your vault", fallbackTitle: "Use Passcode", cancelTitle: "Not now")
let secret = try await storage.retrieve("vault", as: String.self, prompt: prompt)
```

| `ItemProtection` | Meaning |
|---|---|
| `.none` | Accessibility only |
| `.userPresence` | Biometry or device passcode |
| `.biometryAny` | Any enrolled biometry |
| `.biometryCurrentSet` | The biometry enrolled now. Adding a face or finger invalidates the item. |
| `.biometryCurrentSetOrPasscode`, `.biometryAnyOrPasscode` | Biometry with passcode fallback |
| `.devicePasscode` | Passcode only |

Errors are mapped for you: `.userCancelled`, `.userFallback`, `.authenticationFailed`, `.biometryLockout`, `.biometryNotEnrolled` and `.interactionNotAllowed`.

### Encryption and keys

```swift
let keys = KeyManager(storage: SecureStorage(service: "my-app", namespace: "keys"))
let sealed = try await keys.encrypt(data, associatedData: Data(recordID.utf8))
let plain = try await keys.decrypt(sealed, associatedData: Data(recordID.utf8))

try await keys.rotate()                       // new data uses default#2; default#1 still decrypts
try await keys.retire(version: 1)             // destroys default#1 once nothing uses it
let perUser = try await keys.derivedKey(info: Data("user-42".utf8))   // HKDF
```

Envelope format: `"SSKE" | version | algorithm | keyID | nonce(12) | ciphertext | tag(16)`. The header is authenticated, and any change throws `.tamperedData`. If you need raw primitives, `EncryptionManager` exposes them.

### Tokens and sessions

```swift
struct AuthAPI: TokenRefresher {
    func refreshTokens(using refreshToken: String, account: String) async throws -> TokenSet { … }
}
let tokens = SecureTokenStore(service: "my-app", refresher: AuthAPI())
try await tokens.save(TokenSet(accessToken: at, refreshToken: rt, expiresIn: 3600), for: "alice")
let bearer = try await tokens.validAccessToken(for: "alice")   // refreshes once, even if called concurrently
try await tokens.sessionStorage(for: "alice").save(pin, forKey: "pin")
try await tokens.logout(account: "alice")                      // tokens + session secrets
```

`print(tokenSet)` shows `<redacted>` in place of token values.

### Testing your app

```swift
let mock = InMemoryKeychain()
let storage = SecureStorage(configuration: .init(service: "test"), backend: mock)
mock.authenticationResult = .failure(.userCancelled)   // simulate Face ID cancel
mock.simulateBiometryEnrollmentChange()                // simulate a new fingerprint
mock.isDeviceLocked = true                             // simulate a locked device
```

`SecureStorage` conforms to `SecureStoring`, so you can inject it behind that protocol.

## Advanced features

```swift
// Secure Enclave: the private key never leaves the chip
let se = SecureEnclaveManager(storage: storage.namespaced("se"))
let publicKey = try await se.createSigningKey(tag: "device", protection: .biometryCurrentSet)
let signature = try await se.sign(challenge, tag: "device", prompt: .init(reason: "Approve sign-in"))
try await se.createAgreementKey(tag: "wrap")
let wrapped = try await se.seal(secretKeyBytes, toKeyTag: "wrap")      // ECDH + HKDF + AES-GCM

// Encrypted files, streamed in chunks, written atomically
let files = EncryptedFileVault(keyManager: keys)
try await files.encryptFile(at: photoURL, to: vaultURL)
try await files.decryptFile(at: vaultURL, to: exportURL)

// Rotate a key and re-encrypt every record; resumable, retires old keys only when done
let report = try await KeyRotationEngine(keyManager: keys).rotateAndMigrate(myRecordStore)

// Per-account partitions
let vault = MultiAccountVault(configuration: .init(service: "my-app", namespace: "vault"))
try await vault.storage(for: "tenant-7").save(apiKey, forKey: "api-key")
try await vault.remove(account: "tenant-7")

// Import from KeychainAccess / SwiftKeychainWrapper / raw SecItem code
let migration = MigrationManager(destination: storage)
let result = try await migration.migrate(from: .init(service: "legacy-service"), deleteSource: true)

// Password-protected backup (PBKDF2-SHA256 600k + AES-GCM)
let (backup, exportReport) = try await SecureBackup.export(from: storage, password: userPassword)
_ = try await SecureBackup.import(backup, password: userPassword, into: storage)

// Audit trail without secrets
let audit = AuditLog(capacity: 500, forward: SecureLogger.unifiedLog)
var config = StorageConfiguration(service: "my-app")
config.eventHandler = audit.handler
```

## Example app

Open `Examples/SecureStorageDemo/SecureStorageDemo.xcodeproj` and run it. It is a SwiftUI app with four tabs: Keychain, Biometrics, Encryption and Tokens. It uses the package from this folder.

## Running tests

```bash
swift test                                              # 66 unit tests (in-memory Keychain, CryptoKit, Secure Enclave if present)
SSK_KEYCHAIN_TESTS=1 swift test --filter SystemKeychain # real macOS Keychain
xcodebuild test -scheme SecureStorageKit-Package -destination 'platform=iOS Simulator,name=iPhone 16'
```

> **Simulator note:** the iOS Simulator does not enforce biometric access control on Keychain items. Test protected items on a physical device with Face ID or Touch ID enrolled. The release checklist in [Docs/ReleaseChecklist.md](Docs/ReleaseChecklist.md) requires this.

## Documentation

- [Docs/API-Reference.md](Docs/API-Reference.md): every public type and method
- [Docs/ThreatModel.md](Docs/ThreatModel.md): security assumptions, what is and isn't protected, recovery limits
- [Docs/ReleaseChecklist.md](Docs/ReleaseChecklist.md): acceptance criteria before a release
- [CHANGELOG.md](CHANGELOG.md)

## Security status

The package has a full test suite but **has not had an independent security audit yet**. Don't market it as production-hardened until that review is done (see the release checklist).

## License

SecureStorageKit is released under the MIT License. See [LICENSE](LICENSE).
