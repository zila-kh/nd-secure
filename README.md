# ND Secure

ND Secure is a local-first Tauri v2 application that combines an encrypted media gallery and a password manager in one cross-platform vault. The same Svelte frontend and Rust security core target Windows, Apple Silicon macOS, and Android.

> **Security status:** this repository contains security-focused pre-audit software and has not received an independent cryptographic or application-security audit. Do not use it as the sole copy of irreplaceable data or as a production password manager until it has been reviewed and hardened for your deployment environment.

## Implemented features

### Shared vault session

- Argon2id master-password derivation with persisted, non-secret salt and parameters.
- AES-256-GCM authenticated password verifier. Version 2 also authenticates the persisted auto-lock and source-removal policy fields; version-1 vaults migrate on successful unlock with source removal forced off.
- Master key retained only in Rust process memory while unlocked and wrapped in `Zeroizing`.
- Separate HKDF domains for gallery and credentials.
- Manual lock and configurable inactivity lock.
- Lock on Android suspension and application window shutdown.
- Process-local exponential delay after failed unlock attempts.
- Best-effort operating-system content protection requested for the main application window.

### Gallery vault

- JPEG, PNG, MP4, and WebM allowlist based on authenticated signature bytes.
- Opaque UUID `.enc` filenames; source names and paths are not stored.
- Versioned AES-256-GCM container with independently authenticated 64 KiB records.
- Per-file salt, per-file derived key, and deterministic unique record nonces.
- Direct ciphertext ingestion with encrypted `.partial` crash staging; no app-created plaintext staging file.
- Pre-generated image thumbnails decoded, orientation-corrected, resized, and encoded only in memory, then stored as separate authenticated encrypted containers. Decode panics and resource-limit failures are contained as a missing-thumbnail result. Existing encrypted JPEG and PNG items are authenticated and backfilled on their first bounded thumbnail request; unsupported, malformed, or oversized legacy images remain placeholders.
- Gallery cards request only the bounded `/thumbnail/<media-id>` object and never fall back to the encrypted original.
- Android `content://` ingestion through a Kotlin `ContentResolver` plugin and detached file descriptor.
- Cursor-paginated SQLite index.
- Asynchronous `vault` custom protocol with bounded byte-range responses and video seeking.
- Viewport-row virtualization in the Svelte gallery.
- Optional source removal after import. It is disabled by default and is attempted only after the encrypted object is authenticated and the database transaction commits. Desktop files are reopened, same-file checked, and hash-verified; Android documents are reopened through the same content URI and hash-verified before provider deletion is requested.

### Password manager

- Independently encrypted credential records with random per-record salts and nonces.
- Login, secure-note, and TOTP record types.
- Credential search performed only while unlocked after Rust-side record decryption.
- Rust-generated passwords using operating-system entropy.
- Rust-side TOTP generation; the TOTP seed is not returned for ordinary code display.
- Native clipboard copy command with conditional 30-second clearing.
- Cursor pagination and encrypted SQLite payloads.

## Architecture

```text
Svelte application
    │ narrow Tauri commands
    ▼
Rust session manager
    ├── HKDF gallery domain
    │   ├── chunked original-media containers
    │   ├── encrypted image-thumbnail containers
    │   ├── gallery SQLite index
    │   └── vault:// media and thumbnail protocols
    └── HKDF credentials domain
        ├── encrypted credential records
        ├── TOTP/password services
        └── credentials SQLite index
```

The Android source plugin passes an open file descriptor to Rust. Selected media is read into a reusable bounded buffer and encrypted directly to application-private storage. Image sources within the configured memory bound are captured during that same pass for in-memory thumbnail generation; no plaintext derivative is written to disk. Legacy encrypted image items are fully authenticated and decrypted into the same bounded zeroizing memory path only when a visible card first requests a missing thumbnail.

## Repository layout

```text
src/                              Svelte UI
src-tauri/src/session.rs          unlock, key lifecycle, auto-lock, import policy
src-tauri/src/gallery/            encrypted media/thumbnail formats and index
src-tauri/src/credentials/        encrypted records, search, TOTP
src-tauri/src/protocol.rs         vault custom URI and Range handling
plugins/tauri-plugin-vault-source Android content URI and deletion bridge
```

## Development

### Prerequisites

- Node.js 20 or newer
- Rust 1.88.0 or newer
- Tauri v2 platform prerequisites
- Windows: Visual Studio C++ build tools and WebView2
- macOS: Xcode command-line tools; Apple Silicon builds use `aarch64-apple-darwin`
- Android: Android Studio, SDK 36, NDK, Java 17 or newer, and Rust Android targets

### Install and run

```bash
npm install
npm run tauri dev
```

### Checks

```bash
npm run lint
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
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

Credential payloads, original media content, and thumbnail pixels are encrypted. Operational metadata remains visible in SQLite, including record type, UUID, timestamps, media MIME type, media size, and thumbnail availability. See [SECURITY.md](SECURITY.md) for the exact threat model.

## Source-removal policy

`Remove original after verified import` is **off by default** for new and existing vaults. The setting is authenticated together with the password verifier in vault-header version 2. A successfully unlocked version-1 header is migrated with this setting forced off, so a legacy or missing field cannot enable deletion. With the setting off, importing only reads the selected source and never asks the file system or Android document provider to erase it.

With the setting on, ND Secure performs these steps in order:

1. stream-encrypt and authenticate the vault object;
2. generate and encrypt an image thumbnail when supported;
3. commit the gallery index transaction;
4. reopen the selected source and compare its byte length and SHA-256 digest with the imported stream; desktop imports also require the reopened path to identify the same file;
5. on desktop, atomically move the verified path into a unique same-directory quarantine, recheck that it is still the imported file identity, and then remove it; on Android, request provider deletion only when verification succeeds.

A provider rejection, permission failure, symlink, changed source, or deletion error retains the source bytes and returns a warning; ordinary desktop failures restore the original path before reporting the warning. This feature removes a directory entry or provider document; it is not secure erasure and cannot guarantee that storage media, backups, cloud providers, snapshots, or other hard links no longer contain the bytes.

## Important limitations

- There is no cloud synchronization, account recovery, shared vault, or forgotten-password recovery.
- Biometric key wrapping, browser extensions, Android Credential Manager/Autofill, passkeys, and Safari AutoFill extensions are not implemented yet.
- Video poster thumbnails are not generated. Image thumbnails may be unavailable when a source exceeds the bounded capture/decode limits, is malformed, or cannot be decoded safely; cards show a placeholder and never use the original as a preview fallback.
- The application cannot prevent a privileged operating-system user, debugger, swap/hibernation mechanism, process dump, screenshot service, injected code, external camera, or compromised device from observing plaintext while the vault is unlocked.
- Operating-system content-protection APIs are defense in depth, not a security boundary, and support varies by platform and capture method.
- Source removal is disabled by default and is not secure erasure when enabled.

## License

No license has been selected. All rights are reserved by the repository owner until a license is added.
