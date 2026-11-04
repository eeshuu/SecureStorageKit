# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-11-04

Security and reliability fixes. No API changes; upgrading is a drop-in replacement.

### Fixed
- **Versioned records keep their protection when migrated.** Before, `retrieveVersioned` re-saved an upgraded record with the configuration's default protection, so an item saved with `.biometryCurrentSet` stopped requiring Face ID / Touch ID. The record is now rewritten in place, keeping its access control and accessibility.
- **A failed replace no longer loses the old value.** Before, `update` and `save` deleted the old item before adding the new one, so an add that failed (for example, a `whenUnlocked` item written while the device is locked) left neither value. The new value is now staged first: nothing is deleted unless the write can succeed. If the final step is interrupted, reads return the staged value.
- **Tokens can't reappear after logout.** Before, a refresh running during `logout` saved the new tokens afterwards. Such a refresh is now discarded and throws `.itemNotFound`. A refresh also re-reads the stored tokens first, so a refresh token that was already rotated is never sent again.
- **Accounts are isolated by name.** Before, the tokens of an account named `session.<name>` shared a namespace with the session storage of account `<name>`. Tokens now live in their own namespace (`<ns>.tok.<account>`, with `.` escaped).
  - Tokens saved by 1.0.0 are moved there on first read.
  - `logout` also clears the old location.
- **Key versions are created one at a time.** Before, concurrent first use or rotation of a `KeyManager` key could create the same version twice, and the second write silently replaced the first key's material. Data encrypted with the first key was then unreadable. Creation is now serialized per key name, and key material is written insert-only, so it is never overwritten.

### Security hardening
- `EncryptedFileVault` checks the result of random nonce-prefix generation and fails instead of continuing with predictable bytes.
- `KeyRotationEngine.migrate` documents that `retireWhenComplete` should only be used when the store holds all data encrypted with the key.

### Added
- `KeychainBackend.updateData(_:data:prompt:)`: updates an item's data in place, keeping its protection. Custom backends get a default implementation that returns `false`, so existing conformances still compile.
- `InMemoryKeychain.protection(of:)`, for tests.

## [1.0.0] - 2026-10-31

### Added

**Core**
- `SecureStorage`:
  - async save, read, update and delete for `String`, `Data` and Codable values, with `upsert`, `insertOnly` and `updateOnly` save modes;
  - `contains`, `allKeys` and a namespace-scoped `clearAll`.
- `StorageConfiguration`:
  - service, namespace and environment (dev/prod isolation);
  - accessibility, default item protection, access group and iCloud sync;
  - pluggable serializer and event handler.
- `KeychainAccessibility` covering the `WhenUnlocked`, `AfterFirstUnlock` and `ThisDeviceOnly` variants.
- `ItemProtection`: Keychain access control for biometry, `biometryCurrentSet`, user presence and passcode.
- `AuthenticationPrompt` with localized reason, fallback and cancel titles, and a no-UI mode.
- `BiometricManager`: availability, enrollment and lockout detection, standalone authentication and enrollment-change tracking.
- `StorageError` with typed `OSStatus` and `LAError` mapping; errors never include secret values.
- `VersionedCodable` schema migrations with an obsolete-record policy.
- `EncryptionManager` (AES-256-GCM with associated data, HKDF) and the versioned `CipherEnvelope` format.
- `KeyManager`: named keys with create, rotate, retire and destroy, decrypting with any active or decrypt-only version.
- `SecureTokenStore`:
  - access and refresh tokens with expiry;
  - coalesced refresh through a host-supplied `TokenRefresher`;
  - per-account isolation, session storage, and logout cleanup.
- `SecureLogger`, `StorageEvent` and `Redacted` for privacy-preserving diagnostics.
- `InMemoryKeychain`, which simulates authentication results, a locked device and enrollment changes.
- `ProtectedData` availability checks.

**Advanced**
- `SecureEnclaveManager`: P-256 signing, plus ECDH sealing and opening, with access policies.
- `EncryptedFileVault`: chunked, streaming, authenticated file encryption with atomic writes.
- `KeyRotationEngine`: resumable re-encryption that retires old keys only when migration completes, along with `InMemoryRecordStore` and `SecureStorageRecordStore`.
- `MultiAccountVault` for account and tenant partitioning and cleanup.
- `MigrationManager` to import from legacy Keychain wrappers without prompting.
- `SecureBackup`: PBKDF2 and AES-GCM password-protected export and import, with an explicit recovery policy.
- `AuditLog`: a bounded, thread-safe event buffer.

**Project**
- 66 unit tests plus an opt-in real-Keychain integration test.
- A SwiftUI example app.
- The README, an API reference, a threat model, a release checklist and the GitHub Actions CI configuration.
