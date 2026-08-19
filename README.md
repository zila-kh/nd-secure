# ND Secure

ND Secure is a local-first Tauri v2 application that combines an encrypted media gallery and a password manager in one cross-platform vault. The same Svelte frontend and Rust security core target Windows, Apple Silicon macOS, and Android.

> **Security status:** this repository contains a security-focused MVP and has not received an independent cryptographic or application-security audit. Do not use it as the sole copy of irreplaceable data or as a production password manager until it has been reviewed and hardened for your deployment environment.

## Implemented features

### Shared vault session

- Argon2id master-password derivation with persisted, non-secret salt and parameters.
- AES-256-GCM authenticated password verifier.
- Master key retained only in Rust process memory while unlocked and wrapped in `Zeroizing`.
- Separate HKDF domains for gallery and credentials.
- Manual lock and configurable inactivity lock.
- Lock on Android suspension and application window shutdown.
- Process-local exponential delay after failed unlock attempts.

### Gallery vault

- JPEG, PNG, MP4, and WebM allowlist based on authenticated signature bytes.
- Opaque UUID `.enc` filenames; source names and paths are not stored.
- Versioned AES-256-GCM container with independently authenticated 64 KiB records.
- Per-file salt, per-file derived key, and deterministic unique record nonces.
- Direct ciphertext ingestion with encrypted `.partial` crash staging; no app-created plaintext staging file.
- Android `content://` ingestion through a Kotlin `ContentResolver` plugin and detached file descriptor.
- Cursor-paginated SQLite index.
- Asynchronous `vault` custom protocol with bounded byte-range responses and video seeking.
- Viewport-row virtualization in the Svelte gallery.

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
    │   ├── chunked media container
    │   ├── gallery SQLite index
    │   └── vault:// range protocol
    └── HKDF credentials domain
        ├── encrypted credential records
        ├── TOTP/password services
        └── credentials SQLite index
```

The Android source plugin passes an open file descriptor to Rust. Selected media is read into a reusable bounded buffer and encrypted directly to application-private storage.

## Repository layout

```text
src/                              Svelte UI
src-tauri/src/session.rs          unlock, key lifecycle, auto-lock
src-tauri/src/gallery/            encrypted media format and index
src-tauri/src/credentials/        encrypted records, search, TOTP
src-tauri/src/protocol.rs         vault custom URI and Range handling
plugins/tauri-plugin-vault-source Android content URI bridge
```

## Development

### Prerequisites

- Node.js 20 or newer
- Rust 1.77.2 or newer
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
│   └── objects/<uuid>.enc
└── credentials/
    └── credentials.sqlite3*
```

Credential payloads and media content are encrypted. The current MVP intentionally leaves some operational metadata visible in SQLite, including record type, UUID, timestamps, media MIME type, and media size. See [SECURITY.md](SECURITY.md) for the exact threat model.

## Important limitations

- There is no cloud synchronization, account recovery, shared vault, or forgotten-password recovery.
- Biometric key wrapping, browser extensions, Android Credential Manager/Autofill, passkeys, and Safari AutoFill extensions are not implemented yet.
- Gallery thumbnails are not pre-generated in this MVP; image cards request the encrypted original through the bounded custom protocol.
- The application cannot prevent a privileged operating-system user, debugger, swap/hibernation mechanism, screenshot service, or compromised device from observing plaintext while the vault is unlocked.
- Importing an existing source file does not erase the user's original file.

## License

No license has been selected. All rights are reserved by the repository owner until a license is added.
