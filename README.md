# ND Secure

ND Secure is a local-first Tauri v2 application that combines an encrypted media gallery and a credential manager in one cross-platform vault. The same Svelte frontend and Rust security core target Windows, Apple Silicon macOS, and Android.

> **Security status:** this repository contains security-focused pre-audit software and has not received an independent cryptographic or application-security audit. Do not treat it as the sole copy of irreplaceable data. Review the threat model in [SECURITY.md](SECURITY.md) before relying on it for high-value credentials.

## Implemented features

### Shared vault session

- Vault-header v3 with a random 256-bit vault root key for new vaults.
- Argon2id master-password derivation with a persisted non-secret salt and parameters.
- HKDF-separated AES-256-GCM wrapping of the stable vault root key.
- Authenticated v3 header metadata covering the password envelope, security preferences, and optional recovery envelope.
- In-place v1/v2 migration without re-encrypting existing gallery or credential objects or changing their derived data keys.
- Master-password changes re-wrap the stable root key under fresh Argon2id/HKDF key material instead of rewriting vault ciphertext.
- Optional offline recovery key that can reset a forgotten master password while preserving the same root key. The recovery key itself is never persisted by ND Secure.
- Separate HKDF domains for gallery and credentials.
- Manual lock and configurable inactivity lock.
- Lock on Android suspension/background, optional lock when the desktop window loses focus, and lock on application shutdown events.
- Process-local exponential delay after failed authentication attempts.
- Best-effort operating-system content protection requested for the main desktop window.

### Gallery vault

- JPEG, PNG, MP4, and WebM allowlist based on authenticated signature bytes.
- Opaque UUID `.enc` filenames; source names and paths are not stored.
- Versioned AES-256-GCM container with independently authenticated 64 KiB records.
- Per-file salt, per-file derived key, and deterministic unique record nonces.
- Direct ciphertext ingestion with encrypted `.partial` crash staging; no app-created plaintext staging file.
- Encrypted container files are synced before final rename, with a best-effort parent-directory sync before the index commit for stronger crash durability.
- Pre-generated image thumbnails decoded, orientation-corrected, resized, and encoded only in memory, then stored as separate authenticated encrypted containers. Decode panics and resource-limit failures are contained as a missing-thumbnail result. Existing encrypted JPEG and PNG items are authenticated and backfilled on their first bounded thumbnail request; unsupported, malformed, or oversized legacy images remain placeholders.
- Gallery cards request only the bounded `/thumbnail/<media-id>` object and never fall back to the encrypted original.
- Android `content://` ingestion through a Kotlin `ContentResolver` plugin and detached file descriptor.
- Cursor-paginated SQLite index.
- Bounded asynchronous `vault` custom protocol for encrypted images/thumbnails and a loopback capability-token stream server for seekable encrypted video playback.
- Viewport-row virtualization in the Svelte gallery.
- Permanent media deletion requires an explicit native warning confirmation in the UI.
- Optional source removal after import. It is disabled by default and is attempted only after the encrypted object is authenticated and the database transaction commits. Desktop files are reopened, same-file checked, and hash-verified; Android documents are reopened through the same content URI and hash-verified before provider deletion is requested.

### Credential manager

- Independently encrypted credential records with random per-record salts and nonces.
- Login, secure-note, TOTP, and generic secret records.
- Central or project-scoped secrets with environment and encrypted folder metadata.
- Encrypted custom fields, including hidden values that are excluded from search.
- Bounded encrypted password history.
- Encrypted recoverable Trash. Delete/restore transitions authenticate the current record, increment its revision, and re-encrypt with a fresh salt and nonce.
- Permanent purge and empty-trash actions require a recent master-password reauthentication enforced in Rust.
- Credential search is performed only while unlocked after Rust-side record decryption; sensitive metadata is not stored as a plaintext search index.
- Rust-generated passwords using operating-system entropy, explicit character classes, ambiguous-character exclusion, and enforced minimum number/symbol counts.
- Rust-side TOTP generation; the TOTP seed is not returned for ordinary code display.
- Native clipboard copy command with configurable conditional clearing. ND Secure clears only when the clipboard still contains the exact value it copied.
- Cursor pagination and encrypted SQLite payloads.

## Architecture

```text
Svelte application
    │ narrow Tauri commands
    ▼
Rust session manager
    │ stable vault root key
    ├── HKDF gallery domain
    │   ├── chunked original-media containers
    │   ├── encrypted image-thumbnail containers
    │   ├── gallery SQLite index
    │   ├── vault:// image/thumbnail protocol
    │   └── capability-token loopback video streaming
    └── HKDF credentials domain
        ├── encrypted credential records
        ├── password history/custom fields/trash
        ├── TOTP/password services
        └── credentials SQLite index
```

The Android source plugin passes an open file descriptor to Rust. Selected media is read into a reusable bounded buffer and encrypted directly to application-private storage. Image sources within the configured memory bound are captured during that same pass for in-memory thumbnail generation; no plaintext derivative is written to disk. Legacy encrypted image items are fully authenticated and decrypted into the same bounded zeroizing memory path only when a visible card first requests a missing thumbnail.

## Repository layout

```text
src/                              Svelte UI
src-tauri/src/session.rs          root envelope, authentication, recovery, lifecycle
src-tauri/src/gallery/            encrypted media/thumbnail formats and index
src-tauri/src/credentials/        encrypted records, search, trash, TOTP
src-tauri/src/media_server.rs     bounded capability-token video streaming
src-tauri/src/protocol.rs         vault custom URI and Range handling
plugins/tauri-plugin-vault-source Android content URI and deletion bridge
```

## Development

### Prerequisites

- Node.js 22 recommended
- Rust 1.88.0 or newer
- Tauri v2 platform prerequisites
- Windows: Visual Studio C++ build tools and WebView2
- macOS: Xcode command-line tools; Apple Silicon builds use `aarch64-apple-darwin`
- Android: Android Studio, SDK 36, NDK, Java 17 or newer, and Rust Android targets

### Install and run

```bash
npm ci --no-audit --no-fund
npm run tauri dev
```

### Checks

```bash
npm run lint
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo fmt --manifest-path plugins/tauri-plugin-vault-source/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets -- -D warnings
cargo check --manifest-path src-tauri/Cargo.toml --locked --all-targets
cargo test --manifest-path src-tauri/Cargo.toml --locked
```

### Platform builds

Windows x64:

```powershell
npm run tauri build -- --target x86_64-pc-windows-msvc
```

Apple Silicon macOS:

```bash
rustup target add aarch64-apple-darwin
npm run tauri build -- --target aarch64-apple-darwin
```

Android ARM64:

```bash
npm run tauri android init
npm run tauri android build -- --aab --target aarch64
```

Android emulator:

```bash
npm run tauri android build -- --apk --target x86_64
```

## On-disk data

```text
<AppLocalData>/vault/
├── vault-header.json
├── gallery/
│   ├── gallery.sqlite3*
│   ├── objects/<media-uuid>.enc
│   └── thumbnails/<media-uuid>.enc
└── credentials/
    └── credentials.sqlite3*
```

Credential payloads, original media content, and thumbnail pixels are encrypted. Operational metadata remains visible in SQLite and the vault header, including record type/state, UUID, timestamps, media MIME type, media size, thumbnail availability, KDF parameters, and configured lifecycle/import policies. See [SECURITY.md](SECURITY.md) for the exact threat model.

## Source-removal policy

`Remove original after verified import` is **off by default**. In vault-header v3 the setting is authenticated by the vault-root verifier. A successfully unlocked v1 header migrates with this setting forced off; a v2 vault preserves its previously authenticated value. With the setting off, importing only reads the selected source and never asks the file system or Android document provider to erase it.

With the setting on, ND Secure performs these steps in order:

1. stream-encrypt and authenticate the vault object;
2. generate and encrypt an image thumbnail when supported;
3. commit the gallery index transaction;
4. reopen the selected source and compare its byte length and SHA-256 digest with the imported stream; desktop imports also require the reopened path to identify the same file;
5. on desktop, atomically move the verified path into a unique same-directory quarantine, recheck that it is still the imported file identity, and then remove it; on Android, request provider deletion only when verification succeeds.

A provider rejection, permission failure, symlink, changed source, or deletion error retains the source bytes and returns a warning; ordinary desktop failures restore the original path before reporting the warning. This feature removes a directory entry or provider document; it is not secure erasure and cannot guarantee that storage media, backups, cloud providers, snapshots, or other hard links no longer contain the bytes.

## Recovery and backups

Offline recovery is optional and must be enabled before the master password is lost. The generated recovery key should be stored separately from the vault, preferably on paper or in an independently encrypted offline location. Replacing or disabling recovery invalidates the previous key.

A recovery key is not a backup of the vault files. Keep encrypted backups of the application data and test restoration before relying on them. ND Secure currently does not include an in-app backup/import/export workflow.

## Release automation

Pushes to `main` run a release pipeline that first performs the same locked frontend/Rust validation used by CI, then builds the supported signed artifacts when platform signing credentials are configured. Release assets include SHA-256 checksums. Windows and macOS production distribution still depends on valid code-signing/notarization secrets; Android release artifacts are omitted when its signing secret group is not configured.

## Important limitations

- The project has not received an independent security audit.
- There is no cloud synchronization, shared vault, browser extension, or server-side account recovery.
- Forgotten-password recovery works only if offline recovery was enabled beforehand and the recovery key is still available.
- In-app encrypted backup/import/export is not implemented yet.
- Biometric/OS-keystore wrapping, Android Credential Manager/Autofill, passkeys, security keys, and Safari AutoFill extensions are not implemented yet.
- Video poster thumbnails are not generated. Image thumbnails may be unavailable when a source exceeds the bounded capture/decode limits, is malformed, or cannot be decoded safely; cards show a placeholder and never use the original as a preview fallback.
- Gallery media deletion is permanent after confirmation; unlike credentials, gallery media does not currently have a recoverable Trash.
- The application cannot prevent a privileged operating-system user, debugger, swap/hibernation mechanism, process dump, screenshot service, injected code, external camera, malicious accessibility service, or compromised device from observing plaintext while the vault is unlocked.
- Operating-system content-protection APIs are defense in depth, not a security boundary, and support varies by platform and capture method.
- Source removal is disabled by default and is not secure erasure when enabled.

## License

No license has been selected. All rights are reserved by the repository owner until a license is added.
