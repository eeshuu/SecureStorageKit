# Threat model and security assumptions

This document describes what SecureStorageKit protects against, what it relies on, and where its protection ends.

## Assets

- Secrets stored through `SecureStorage`: tokens, passwords, PINs, API keys and small Codable records.
- AES-256 keys managed by `KeyManager`, and data encrypted with them.
- Secure Enclave private keys.
- Backups produced by `SecureBackup`.

## Trust assumptions

1. **The OS and hardware are trusted.** These are the Keychain, data protection, Secure Enclave, LocalAuthentication and CryptoKit. A jailbroken or otherwise compromised device is out of scope.
2. **The app's own code is trusted.** Any code running in your process can call the same APIs your app calls.
3. **The device passcode is reasonably strong.** Data protection and Keychain encryption are only as strong as the passcode they are entangled with.

## What is protected

| Threat | Mitigation |
|---|---|
| Another app reads your secrets | The Keychain sandboxes items by access group. Items are shared with extensions only through an explicit `accessGroup`. |
| Device stolen while locked | `whenUnlocked*` accessibility (the default is `whenUnlockedThisDeviceOnly`) keeps items encrypted until unlock. |
| Backup or device migration extracts secrets | `ThisDeviceOnly` accessibility is the default. Secure Enclave handles are device-bound. |
| Someone with the unlocked phone opens a sensitive item | `ItemProtection` places access control on the Keychain item, so the system will not return the data without Face ID, Touch ID or the passcode. This is not just an app-level prompt that can be skipped. |
| A new fingerprint or face is added by an attacker | `.biometryCurrentSet` invalidates the item when enrollment changes. |
| Encrypted data is modified, truncated or reordered | AES-GCM authentication covers ciphertext, tag, header, key id and caller-supplied associated data. File vault chunks are bound to their index and a final-chunk flag. |
| Ciphertext is moved between records | Pass the record id as `associatedData`. |
| A compromised key is used indefinitely | Rotate with `KeyManager.rotate`, migrate with `KeyRotationEngine`, then retire the old version. |
| Secrets leak through logs or crash reports | `StorageError` and `StorageEvent` never contain values. Key names appear only as a truncated SHA-256 fingerprint. `TokenSet` and `Redacted` print `<redacted>`. `SecureLogger` marks fingerprints `.private`. |
| `clearAll()` deletes data that belongs to other code | Deletion is limited to the `ssk/<namespace>/` account prefix within the configured service, access group and environment. |
| Plaintext temp files | Nothing in the SDK writes plaintext to temporary files. File decryption writes to a temp file next to the destination, which already receives plaintext. That temp file is moved into place only after every chunk authenticates, and it is deleted on failure. On iOS, files are created with `FileProtectionType.complete`. |
| Offline brute force of a backup | PBKDF2-HMAC-SHA256 with 600,000 iterations by default (at least 100,000), a 32-byte random salt and a minimum password length of 10. |

## What is not protected

- **Memory zeroization.** Swift `String` and `Data` are copy-on-write, value-typed and managed by the runtime. Copies can be made by the compiler, by Foundation, by the Keychain APIs and by UI frameworks, and freed memory is not guaranteed to be wiped. SecureStorageKit keeps decrypted data short-lived and never caches plaintext, but it **cannot reliably erase secrets from memory**. CryptoKit's `SymmetricKey` zeroes its own storage. Bytes you extract from it do not get this guarantee.
- **A compromised or jailbroken device**, debugger attachment and runtime hooking.
- **Secrets shown on screen** (screen recording, shoulder surfing). Use your own UI measures.
- **Server-side security.** Token refresh is delegated to your `TokenRefresher`.
- **iCloud Keychain.** When `synchronizable` is true, items are protected by Apple's end-to-end iCloud Keychain encryption. They then leave the device, and `ThisDeviceOnly` and item protection can't be used.
- **The iOS Simulator** does not enforce biometric access control. Test protected items on hardware.

## Recovery limitations

- **`.biometryCurrentSet` items are permanently lost** when Face ID or Touch ID enrollment changes. Keep a recovery path, such as re-login or a server-side copy.
- **Secure Enclave keys are device-bound.** They do not survive a device migration, an erase or a restore to new hardware. Data sealed only to an SE key is lost with the device.
- **Retired key versions are destroyed.** Retire a version only after `KeyRotationEngine` reports `isComplete`.
- **Backup passwords have no escrow.** A forgotten password means the backup can't be opened. A wrong password and a corrupted file are deliberately indistinguishable (`.tamperedData`).
- **Backups skip items that need authentication.** Exporting them would bypass their protection, so they are listed in `ExportReport.skippedProtected`. Re-create them after a restore.
- **Upserts replace items with a delete followed by an add**, so the new protection and accessibility take effect. If the process dies between the two calls, the item is missing rather than stale.

## Cryptographic choices

| Purpose | Algorithm |
|---|---|
| Symmetric encryption | AES-256-GCM (CryptoKit), random 96-bit nonce per message |
| File vault nonces | 56-bit random per-file prefix, 32-bit chunk counter and an 8-bit final flag |
| Key derivation | HKDF-SHA256 |
| Password KDF | PBKDF2-HMAC-SHA256 (CommonCrypto) |
| Signatures | ECDSA P-256 / SHA-256 in the Secure Enclave |
| Key wrapping | ECDH P-256 (Secure Enclave), HKDF-SHA256 and AES-256-GCM |

The Secure Enclave does not perform AES-GCM itself. It only does P-256 signing and key agreement, which protect symmetric keys.
