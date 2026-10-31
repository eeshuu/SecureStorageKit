# API reference

Every method is `async throws` and fails with `StorageError`, unless noted otherwise. Source files carry full doc comments; Xcode's Quick Help and **Product ▸ Build Documentation** show them.

## Core

### `SecureStorage` (`Sendable`, conforms to `SecureStoring`)

| Member | Description |
|---|---|
| `init(service:namespace:)` | Real Keychain, default settings |
| `init(configuration:backend:)` | Full configuration; inject `InMemoryKeychain()` in tests |
| `namespaced(_:) -> SecureStorage` | Same settings and backend, different namespace |
| `save(_:forKey:protection:accessibility:mode:)` | String and Data are stored raw; other Encodable values go through the serializer |
| `saveData(_:forKey:protection:accessibility:mode:)` | Raw bytes |
| `update(_:forKey:protection:)` | `.updateOnly` save; throws `.itemNotFound` |
| `retrieve(_:as:authenticationReason:) -> T?` | `nil` if missing |
| `retrieve(_:as:prompt:) -> T?` | With an `AuthenticationPrompt` |
| `retrieveData(_:prompt:) -> Data?` | Raw bytes |
| `saveVersioned(_:forKey:protection:)` / `retrieveVersioned(_:as:prompt:onObsolete:)` | `VersionedCodable` with migration |
| `delete(_:) -> Bool` | `false` if missing; never prompts |
| `contains(_:) -> Bool` | Never prompts |
| `allKeys() -> [String]` | Keys in this namespace |
| `clearAll()` | Deletes only this namespace |

`SaveMode`: `.upsert` (default), `.insertOnly`, `.updateOnly`.

### `StorageConfiguration`

`service`, `namespace` (default `"default"`, no `/`), `environment` (`.production` / `.development` / `.custom(String)`), `accessibility` (default `.whenUnlockedThisDeviceOnly`), `protection` (default `.none`), `accessGroup`, `synchronizable`, `serializer` (default `JSONStorageSerializer()`), `eventHandler`, `resolvedService`, `namespaced(_:)`.

### Keychain

- `KeychainAccessibility`: `.whenUnlocked`, `.whenUnlockedThisDeviceOnly`, `.afterFirstUnlock`, `.afterFirstUnlockThisDeviceOnly`, `.whenPasscodeSetThisDeviceOnly`.
- `ItemProtection`: `.none`, `.userPresence`, `.biometryAny`, `.biometryCurrentSet`, `.devicePasscode`, `.biometryCurrentSetOrPasscode`, `.biometryAnyOrPasscode`. It also has the properties `requiresAuthentication` and `invalidatedByEnrollmentChange`.
- `AuthenticationPrompt(reason:fallbackTitle:cancelTitle:allowsInteraction:reuseDuration:)`, plus `.noInteraction`.
- The `KeychainBackend` protocol has `add`, `read`, `exists`, `delete` and `accounts` (synchronous, called off the main thread). There are two implementations:
  - `SystemKeychain(useDataProtectionKeychain:)`
  - `InMemoryKeychain`, which adds `authenticationResult`, `isDeviceLocked`, `promptCount`, `count`, `simulateBiometryEnrollmentChange()` and `removeAll()`.
- `KeychainItemKey`, `KeychainWriteRequest`.

### Biometrics

`BiometricManager` (synchronous unless noted):

| Member | Description |
|---|---|
| `biometryType` | `.none`, `.touchID`, `.faceID` or `.opticID` |
| `availability(for:)` | Returns `.available(type)`, `.notEnrolled(type)`, `.lockedOut(type)`, `.passcodeNotSet` or `.notSupported` |
| `authenticate(reason:policy:fallbackTitle:cancelTitle:)` | async throws |
| `enrollmentState() -> Data?` | Opaque value that changes with enrollment |
| `hasEnrollmentChanged(since:) -> Bool` | Compares with a saved `enrollmentState()` |

`AuthenticationPolicy`: `.biometrics`, `.biometricsOrPasscode`.

### Serialization

- `StorageSerializer` protocol: `encode` / `decode`. `JSONStorageSerializer(encoder:decoder:)` uses ISO-8601 dates and sorted keys by default.
- `VersionedCodable` protocol:
  - `schemaVersion`;
  - `minimumSupportedVersion` (default 1);
  - `migrate(from:data:serializer:)`.
- `ObsoleteRecordPolicy`: `.throw`, `.delete`.

### Crypto

`EncryptionManager`:

| Member | Description |
|---|---|
| `encrypt(_:using:keyID:associatedData:) -> CipherEnvelope` | AES-256-GCM, fresh random nonce |
| `decrypt(_:using:associatedData:) -> Data` | Throws `.tamperedData` on any change |
| `seal(...) -> Data` / `open(...) -> Data` | Serialized form |
| `static generateKey()` | Random 256-bit key |
| `static deriveKey(from:salt:info:outputByteCount:)` | HKDF-SHA256 |

`CipherEnvelope`:
- `formatVersion`, `algorithm`, `keyID`, `nonce`, `ciphertext`, `tag`;
- `init(serialized:)`, `serialized()`;
- `static keyID(of:)`.

`KeyManager` (actor):

| Member | Description |
|---|---|
| `init(storage:protection:)` | Key material is kept in `storage` |
| `currentKey(named:) -> (id, key)` | Creates version 1 if none exists |
| `key(withID:)` | Throws `.keyRetired` for retired versions |
| `rotate(named:) -> KeyVersion` | New active version; the previous one becomes decrypt-only |
| `retire(named:version:)` | Destroys a decrypt-only version |
| `retireInactiveVersions(named:)` | Retires every decrypt-only version |
| `versions(named:)` | All versions, oldest first |
| `destroy(named:)` | Deletes every version |
| `encrypt(_:keyName:associatedData:)` / `decrypt(_:associatedData:)` | Uses the active version / the version named in the envelope |
| `isCurrent(_:)` | True if encrypted with the active version |
| `derivedKey(named:salt:info:)` | HKDF sub-key of the active version |

`KeyVersion.State`: `.active`, `.decryptOnly`, `.retired`.

### Tokens

- `TokenSet`:
  - `accessToken`, `refreshToken`, `expiresAt`, `tokenType`, `scope`, `issuedAt`;
  - `init(...expiresIn:)`, `isExpired(leeway:now:)`;
  - prints redacted.
- `TokenRefresher` protocol: `refreshTokens(using:account:) -> TokenSet`.
- `SecureTokenStore` (actor):

| Member | Description |
|---|---|
| `init(service:refresher:)` / `init(configuration:backend:refresher:)` | |
| `save(_:for:)` / `tokens(for:)` | Store and read tokens |
| `validAccessToken(for:leeway:)` | Refreshes if expired; concurrent calls share one refresh |
| `refresh(account:)` | Forces a refresh now |
| `deleteTokens(for:)` | |
| `sessionStorage(for:)` | Session secrets, wiped on logout |
| `logout(account:)` / `logoutAll()` | Removes tokens and session secrets |
| `accounts()` | Accounts with stored tokens |

### Diagnostics and utilities

- `StorageEvent`: `operation`, `namespace`, `keyFingerprint`, `outcome`, `timestamp`; `static fingerprint(_:)`.
- `SecureLogger.unifiedLog`: an event handler that writes to `os.Logger`.
- `Redacted<Value>`: prints `<redacted>`.
- `ProtectedData.isAvailable` / `requireAvailable()` (`@MainActor`).

### `StorageError`

| Group | Cases |
|---|---|
| Keychain | `itemNotFound`, `duplicateItem`, `interactionNotAllowed`, `missingEntitlement`, `protectedDataUnavailable`, `unexpectedStatus(OSStatus)` |
| Authentication | `userCancelled`, `userFallback`, `authenticationFailed`, `biometryNotAvailable`, `biometryNotEnrolled`, `biometryLockout`, `passcodeNotSet` |
| Serialization | `encodingFailed(type:)`, `decodingFailed(type:)`, `obsoleteRecord(foundVersion:minimumSupported:)`, `unsupportedSchemaVersion(_)` |
| Crypto | `invalidKey`, `keyNotFound(id:)`, `keyRetired(id:)`, `cryptoFailure`, `tamperedData`, `unsupportedFormat`, `secureEnclaveUnavailable` |
| Tokens | `tokenExpired`, `noRefreshToken` |
| Configuration | `invalidConfiguration(String)` |

Helpers: `init(status:)`, `init(authenticationError:)` and `isCancellation`. `StorageError` also conforms to `LocalizedError`.

## Advanced features

### `SecureEnclaveManager`

| Member | Description |
|---|---|
| `init(storage:)` | Key handles are kept in `storage` |
| `isAvailable` | static |
| `createSigningKey(tag:protection:)` | Returns the public key |
| `signingPublicKey(tag:)` | |
| `sign(_:tag:prompt:)` | Returns a DER signature |
| `static verify(_:for:publicKey:)` | Works without the Secure Enclave |
| `createAgreementKey(tag:protection:)` / `agreementPublicKey(tag:)` | Key-agreement key for sealing |
| `seal(_:toKeyTag:associatedData:)` / `static seal(_:to:associatedData:)` | Never prompts |
| `open(_:keyTag:associatedData:prompt:)` | Prompts if the key is protected |
| `deleteKey(tag:)` / `hasKey(tag:)` | |

### `EncryptedFileVault`

- `init(keyManager:keyName:chunkSize:)`.
- `encryptFile(at:to:)` and `decryptFile(at:to:)`.
- `encrypt(_:)` and `decrypt(_:)`, which work in memory.
- `static keyID(ofFileAt:)`.

### `KeyRotationEngine`

- `init(keyManager:keyName:associatedData:)`.
- `rotateAndMigrate(_:retireWhenComplete:)` and `migrate(_:retireWhenComplete:)`, both returning a `RotationReport`.
  - Report fields: `activeKeyID`, `migrated`, `alreadyCurrent`, `failed`, `retiredVersions`, `isComplete`.
- `EncryptedRecordStore` protocol: `recordIDs`, `load`, `store`. Implementations: `InMemoryRecordStore` (actor) and `SecureStorageRecordStore`.

### `MultiAccountVault` (actor)

`init(configuration:backend:)`, `storage(for:)`, `accounts()`, `remove(account:)`, `removeAll()`.

### `MigrationManager`

- `init(destination:backend:)`.
- `migrate(from: LegacyKeychainSource, overwrite:deleteSource:) -> MigrationReport`.
  - Report fields: `imported`, `skippedExisting`, `skippedProtected`, `skippedByMapping`, `failed`.
- `LegacyKeychainSource(service:accessGroup:keyMapping:)`.

### `SecureBackup`

- `static export(from:password:iterations:) -> (Data, ExportReport)`.
- `static import(_:password:into:overwrite:) -> ImportReport`.
- `minimumPasswordLength` (10) and `defaultIterations` (600,000).

### `AuditLog` (`Sendable`, thread-safe)

`init(capacity:forward:)`, `handler`, `record(_:)`, `events(operation:failuresOnly:)`, `clear()`.
