# Release acceptance checklist

The status reflects version 1.0.0 as built and tested on macOS 15 (Intel with T2) and the iOS 18 Simulator.

| # | Criterion | How it's verified | Status |
|---|---|---|---|
| 1 | All storage APIs tested for save, read, update, delete, duplicate and missing-item behavior | `SecureStorageTests` (in-memory), `SystemKeychainTests` (real macOS Keychain), demo app self-check on the iOS Simulator | ✅ |
| 2 | Biometric-protected items tested on physical supported devices | Run the demo app's **Biometrics** tab on a Face ID device and a Touch ID device. Check cancel, fallback, lockout and enrollment change. | ⬜ Manual. The Simulator does not enforce access control. |
| 3 | No unrelated Keychain entries removed by clear-all | `clearAllOnlyRemovesOwnNamespace` (other namespace, other environment, foreign item) | ✅ |
| 4 | Crypto round-trip, tamper detection, migration and key rotation tests pass | `EncryptionTests`, `KeyManagerTests`, `FileVaultTests`, `RotationTests`, `VersionedCodableTests`, `MigrationTests`, `BackupTests` | ✅ |
| 5 | Concurrency and app-extension entitlement cases documented and tested | Concurrency: `concurrentOperationsAreSafe`, `concurrentFirstUseCreatesOneVersion`, `refreshesExpiredTokenOnce`; Swift 6 strict concurrency enabled. Extensions: `accessGroup` documented in README. | ✅ Concurrency. ⬜ Extension sharing needs a signed app + extension pair on device. |
| 6 | Security review completed before marketing the SDK as production-hardened | Independent review of [ThreatModel.md](ThreatModel.md) and the source | ⬜ Not started |

## Before tagging a release

1. `swift test` and `SSK_KEYCHAIN_TESTS=1 swift test --filter SystemKeychain` pass.
2. CI is green: macOS tests, iOS Simulator tests and the example app build.
3. Manual device checks for rows 2 and 5 are done.
4. `CHANGELOG.md` is updated and the version is tagged.
