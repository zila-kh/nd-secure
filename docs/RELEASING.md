# Automated releases

`.github/workflows/release.yml` creates a GitHub release after every successful push to `main`, including merged pull requests. It can also be started manually with **Actions → Release → Run workflow**.

The pipeline is deliberately staged:

1. Derive a unique release version and Android `versionCode` from the version in `src-tauri/tauri.conf.json` and the workflow run number.
2. Run frontend and Rust validation.
3. Build Windows x64 and Apple Silicon macOS in parallel.
4. Build Android ARM64 only when a complete Android signing configuration is present.
5. Create one release only after every required build succeeds, then attach `SHA256SUMS`.

For example, a base app version of `0.1.0` and workflow run `12` produces release version `0.1.12` and tag `v0.1.12`. Bump the base major/minor version in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, and `package.json` when starting a new release line.

## Release assets

Each complete desktop release contains:

- `ND-Secure_<version>_windows-x64-setup.exe`
- `ND-Secure_<version>_macos-arm64.dmg`
- `SHA256SUMS`

When Android signing is configured, the same release also contains:

- `ND-Secure_<version>_android-arm64.apk`
- `ND-Secure_<version>_android-arm64.aab`

The workflow never publishes an unsigned Android package. Without all Android secrets, Android is intentionally omitted while the desktop release continues.

## Repository secrets

Configure secrets under **Settings → Secrets and variables → Actions**. A platform's secret group must be either complete or absent; partial configuration fails the release rather than silently producing the wrong artifact.

### Android signing

Required together:

- `ANDROID_KEY_BASE64`: base64-encoded upload keystore (`.jks` or `.keystore`)
- `ANDROID_KEY_ALIAS`: upload key alias
- `ANDROID_KEYSTORE_PASSWORD`: keystore password
- `ANDROID_KEY_PASSWORD`: key password

The workflow signs the APK with `apksigner`, signs the AAB with `jarsigner`, and verifies both before upload.

### Windows Authenticode signing

Optional, but recommended for public production distribution. Required together:

- `WINDOWS_CERTIFICATE`: base64-encoded `.pfx` certificate
- `WINDOWS_CERTIFICATE_PASSWORD`: `.pfx` export password
- `WINDOWS_TIMESTAMP_URL`: timestamp service supplied by the certificate issuer

Without this group, the NSIS installer is built unsigned and Windows may display reputation warnings.

### macOS Developer ID signing and notarization

Optional, but recommended for public production distribution. Required together:

- `APPLE_CERTIFICATE`: base64-encoded Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`: `.p12` export password
- `KEYCHAIN_PASSWORD`: temporary CI keychain password
- `APPLE_ID`: Apple account email
- `APPLE_PASSWORD`: Apple app-specific password
- `APPLE_TEAM_ID`: Apple Developer Team ID

Without this group, the Apple Silicon build receives an ad-hoc signature. It is not notarized and users may need to approve it in macOS Privacy & Security.

## Versioning and retries

A workflow run always maps to one deterministic version and tag. Re-running the same workflow run updates that release's assets; a different commit is never allowed to reuse the tag.

The release job is serialized with a concurrency group and does not cancel an in-progress release. This prevents two merges from racing to publish overlapping assets.

## Dependency reproducibility

This repository currently has no committed `package-lock.json` or `Cargo.lock`. The workflow therefore uses `npm install` and normal Cargo resolution. For fully reproducible production builds, generate, review, and commit both lockfiles, then change the workflow to `npm ci` and Cargo commands with `--locked`.
