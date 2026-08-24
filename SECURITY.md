# Security Policy and Threat Model

## Supported branch

Security fixes are applied to the latest `main` branch. The application is pre-audit software and does not yet claim independently audited password-manager assurance.

## Security objectives

ND Secure is designed to protect vault contents against offline inspection of application storage after the application has been locked or terminated, assuming the master password has sufficient entropy and the cryptographic implementation is correct.

The application aims to prevent:

- app-created plaintext media files, thumbnails, or credential databases;
- persistence of plaintext master-password-derived key material or the unwrapped vault root key;
- original media filename and source-path storage;
- unauthenticated media or thumbnail modification, reordering, truncation, and splicing;
- direct JavaScript access to the password-derived key, vault root key, or TOTP seed during ordinary use;
- unbounded gallery DOM growth and unbounded custom-protocol response bodies;
- gallery cards from decrypting full original images when an encrypted thumbnail is available;
- accidental deletion of selected originals under the default import policy;
- accidental permanent credential deletion through recoverable encrypted Trash.

## Out of scope

The current design does not protect against:

- a compromised kernel, root/administrator user, debugger, injected process, or malicious accessibility service;
- plaintext already present in source files selected for import;
- screen capture, cameras, shoulder surfing, or clipboard history controlled by the operating system;
- swap, hibernation, process dumps, or device-memory acquisition on every supported platform;
- malicious code running inside a compromised application build or WebView;
- weak or reused master passwords;
- denial of service, deletion, rollback, or replacement by an attacker with write access to application storage;
- secure erasure of source data from flash media, cloud providers, backups, snapshots, or alternate hard links.

The application requests operating-system content protection for its main window. This is defense in depth only. It does not change the out-of-scope conditions above and cannot guarantee that every screenshot, recording, privileged capture path, or external camera is blocked.

## Cryptographic design

### Vault envelope and key hierarchy

- Password KDF: Argon2id derives 32 bytes from the master password and a persisted random salt. Current defaults are 64 MiB memory, 3 iterations, and parallelism 1.
- Vault root: new version-3 vaults generate a random 256-bit root key from operating-system randomness.
- Password wrapping: HKDF-SHA-256 derives a dedicated wrapping key from the Argon2id output; AES-256-GCM wraps the vault root key.
- Root verification: an AES-256-GCM verifier under the vault root authenticates the v3 vault identity, KDF parameters, wrapped-root envelope, auto-lock/import/lifecycle/clipboard settings, and optional recovery envelope.
- Domain separation: HKDF-SHA-256 derives separate gallery, credential, password-wrap, recovery-wrap, and per-object key domains.
- Legacy migration: a successful version-1 or version-2 unlock promotes the existing 256-bit password-derived vault key to the stable v3 root before wrapping it. This preserves existing gallery and credential domain keys and avoids bulk data re-encryption during migration.
- Password changes: changing the master password generates a fresh salt and Argon2id key and re-wraps the stable root key. Gallery and credential ciphertext is not rewritten.

The password-derived key and unwrapped vault root key remain inside Rust while needed and use `Zeroizing` where practical. They are not returned through Tauri commands.

### Optional offline recovery

Recovery is opt-in. When enabled, ND Secure generates a random 256-bit recovery key and derives a dedicated recovery wrapping key with HKDF. The vault root is wrapped under AES-256-GCM and the authenticated recovery envelope is persisted in the v3 header. The recovery key itself is returned once for the user to store independently and is not persisted by ND Secure.

A valid recovery key can unwrap the existing root key and set a new master password without re-encrypting gallery or credential data. Creating a replacement recovery key invalidates the previous one. Disabling recovery removes the recovery envelope. Anyone who obtains both the recovery key and the vault files can reset the master password, so the recovery key must be protected independently from the vault.

### Gallery encryption

- Gallery originals: random per-file salt, derived per-file key, four-byte random nonce prefix plus a 64-bit record counter.
- Gallery thumbnails: the same authenticated container format, a fresh random salt, and a deterministic container UUID derived from the parent media UUID under a dedicated domain label.
- AEAD: AES-256-GCM.
- Media metadata and each 64 KiB content record are independently authenticated.
- AAD binds the container UUID, total size, chunk count, chunk index, record length, and final-record marker.

No plaintext is released from a media record until its AES-GCM tag verifies. Encrypted container files are synced before the final rename, and the containing directory is synced on platforms where that operation is supported before the gallery index commit proceeds.

Image thumbnails are generated only in process memory. Source capture and encoded PNG output have hard size bounds; image dimensions and a conservative decoded-pixel budget are checked before decode, and the decoder receives an additional best-effort allocation limit. Embedded image orientation is applied to the bounded derivative. Decoder unwinds are caught at the thumbnail boundary and degrade to a missing-thumbnail result. Only the encrypted thumbnail container is written to application storage. For legacy JPEG and PNG items, the original container is fully authenticated and read through the same bounded zeroizing source path when the thumbnail endpoint is first requested. Decode failures or configured resource-limit failures produce no thumbnail, and the original bytes are never returned to the gallery card.

### Credential encryption

Credential payloads use AES-256-GCM under a credential-domain key and a fresh random per-record salt and nonce. Record AAD binds the credential UUID, record type, and monotonically increasing revision. The encrypted payload contains sensitive fields including titles, usernames, passwords, notes, websites, TOTP seeds, folders, project/environment assignments, custom fields, and bounded password history.

Credential Trash transitions decrypt and authenticate the existing record, update the authenticated timestamp, increment the revision, and re-encrypt with a fresh salt and nonce before changing its active/trash state. Permanent purge and empty-trash commands require a recent master-password reauthentication enforced by Rust.

## Import and source-deletion policy

The persisted `deleteSourceAfterImport` setting defaults to `false`. In vault-header version 3 it is authenticated by the vault-root verifier. A successfully unlocked version-1 header is migrated with the setting forced to `false`; version-2 migration preserves its previously authenticated value. With the setting disabled, import opens the selected source read-only and never asks the platform to delete it.

When enabled, deletion is attempted only after:

1. the original encrypted container has been fully authenticated;
2. any generated thumbnail container has been authenticated;
3. the SQLite transaction has committed;
4. the source has been reopened and its file identity, length, and SHA-256 digest match the imported stream (desktop), or its length and digest match through the same Android document URI;
5. desktop paths have been atomically moved into a unique same-directory quarantine and rechecked as the same imported file identity immediately before unlinking.

Desktop symbolic-link sources are never deleted. Android deletion is delegated to the selected document provider after the same reopen-and-hash verification. Verification or deletion failure does not roll back a successful encrypted import; it retains the source bytes and returns a warning. The quarantine-and-recheck step prevents an ordinary path replacement from being unlinked, but a privileged actor that can manipulate the process, filesystem namespace, or provider remains outside the threat model.

## Runtime exposure controls

- Idle sessions auto-lock in Rust and drop the in-memory root key.
- Mobile suspension locking is enabled by default; optional focus-loss locking is available.
- Active media-stream grants are revoked when the vault explicitly locks or the relevant media is deleted. Stream requests also require an unlocked session.
- Copied credential values are conditionally cleared after the configured timeout only if the clipboard still contains the exact value ND Secure copied.
- Permanent credential purge requires recent master-password confirmation in Rust.

These controls reduce exposure but do not make an unlocked device or operating-system clipboard a trusted boundary.

## Metadata disclosure

The following values are currently visible to offline inspection of SQLite, the vault header, and public media-container headers:

- vault format, vault identifier, KDF parameters, and encrypted key-envelope sizes;
- whether an optional recovery envelope is configured;
- item and credential counts;
- UUID identifiers;
- credential record type, active/trash state, and timestamps;
- media MIME type, size, import timestamp, dimensions when known, and thumbnail availability;
- encrypted original and thumbnail file sizes and chunk counts;
- configured auto-lock, source-removal, lifecycle-lock, and clipboard timeout preferences.

Credential titles, usernames, passwords, notes, websites, TOTP seeds, custom-field contents, project/folder metadata, original media bytes, and thumbnail pixels are encrypted.

## Password and recovery model

The master password is never stored. On unlock it derives a wrapping key that decrypts the stable vault root key. A forgotten master password can be reset only when the user previously enabled offline recovery and still possesses the recovery key. Without that key, ND Secure has no server-side account or backdoor that can recover the vault.

The recovery key is not a backup of the encrypted data itself. Back up the application data as encrypted data, protect any recovery key separately, and test restoration before relying on either mechanism.

## Reporting a vulnerability

Do not publish exploitable security reports in a public issue. Contact the repository owner privately through GitHub's private vulnerability reporting or another private channel. Include the affected commit, platform, reproduction steps, impact, and proposed mitigation when available.
