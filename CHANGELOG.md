# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

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
