# Security Policy and Threat Model

## Supported branch

Security fixes are applied to the latest `main` branch. The application is pre-audit software and does not yet claim production password-manager assurance.

## Security objectives

ND Secure is designed to protect vault contents against offline inspection of application storage after the application has been locked or terminated, assuming the master password has sufficient entropy and the cryptographic implementation is correct.

The application aims to prevent:

- app-created plaintext media files, thumbnails, or credential databases;
- persistence of the master or domain keys;
- original media filename and source-path storage;
- unauthenticated media or thumbnail modification, reordering, truncation, and splicing;
- direct JavaScript access to the master key or TOTP seed during ordinary use;
- unbounded gallery DOM growth and unbounded custom-protocol response bodies;
- gallery cards from decrypting full original images when an encrypted thumbnail is available;
- accidental deletion of selected originals under the default import policy.

## Out of scope

The current design does not protect against:

- a compromised kernel, root/administrator user, debugger, injected process, or malicious accessibility service;
- plaintext already present in source files selected for import;
- screen capture, cameras, shoulder surfing, or clipboard history controlled by the operating system;
- swap, hibernation, process dumps, or device-memory acquisition on every supported platform;
- malicious code running inside a compromised application build or WebView;
- weak or reused master passwords;
- denial of service, deletion, or rollback by an attacker with write access to application storage;
- secure erasure of source data from flash media, cloud providers, backups, snapshots, or alternate hard links.

The application requests operating-system content protection for its main window. This is defense in depth only. It does not change the out-of-scope conditions above and cannot guarantee that every screenshot, recording, privileged capture path, or external camera is blocked.

## Cryptographic design

- Master key: Argon2id output, 32 bytes.
- Root separation: HKDF-SHA-256 domain labels.
- AEAD: AES-256-GCM.
- Vault header: version 2 authenticates the KDF parameters, auto-lock interval, and source-removal preference as verifier AAD. A successful version-1 unlock migrates to version 2 with source removal forced off.
- Gallery originals: random per-file salt, derived per-file key, four-byte random nonce prefix plus a 64-bit record counter.
- Gallery thumbnails: the same authenticated container format, a fresh random salt, and a deterministic container UUID derived from the parent media UUID under a dedicated domain label. This binds each thumbnail object to its gallery item without storing a second public identifier.
- Credentials: random per-record salt and 96-bit random nonce under a distinct derived record key.
- Owned secret and plaintext byte buffers use `zeroize` where practical.

No plaintext is released from a media record until its AES-GCM tag verifies. Media metadata and each 64 KiB content record are independently authenticated. AAD binds the container UUID, total size, chunk count, chunk index, record length, and final-record marker.

Image thumbnails are generated only in process memory. Source capture and encoded PNG output have hard size bounds; image dimensions and a conservative decoded-pixel budget are checked before decode, and the decoder receives an additional best-effort allocation limit. Embedded image orientation is applied to the bounded derivative. Decoder unwinds are caught at the thumbnail boundary and degrade to a missing-thumbnail result. Only the encrypted thumbnail container is written to application storage. For legacy JPEG and PNG items, the original container is fully authenticated and read through the same bounded zeroizing source path when the thumbnail endpoint is first requested. Decode failures or configured resource-limit failures produce no thumbnail, and the original bytes are never returned to the gallery card.

## Import and source-deletion policy

The persisted `deleteSourceAfterImport` setting defaults to `false`. In vault-header version 2 it is authenticated as part of the verifier AAD. A successfully unlocked version-1 header is migrated with the setting forced to `false`, including when a legacy serialized header contains a forged or stale deletion field. With the setting disabled, import opens the selected source read-only and never asks the platform to delete it.

When enabled, deletion is attempted only after:

1. the original encrypted container has been fully authenticated;
2. any generated thumbnail container has been authenticated;
3. the SQLite transaction has committed;
4. the source has been reopened and its file identity, length, and SHA-256 digest match the imported stream (desktop), or its length and digest match through the same Android document URI;
5. desktop paths have been atomically moved into a unique same-directory quarantine and rechecked as the same imported file identity immediately before unlinking.

Desktop symbolic-link sources are never deleted. Android deletion is delegated to the selected document provider after the same reopen-and-hash verification. Verification or deletion failure does not roll back a successful encrypted import; it retains the source bytes and returns a warning. The quarantine-and-recheck step prevents an ordinary path replacement from being unlinked, but a privileged actor that can manipulate the process, filesystem namespace, or provider remains outside the threat model.

## Metadata disclosure

The following values are currently visible to offline inspection of SQLite and the public media-container headers:

- vault format and KDF parameters;
- item and credential counts;
- UUID identifiers;
- credential record type and timestamps;
- media MIME type, size, import timestamp, dimensions when known, and thumbnail availability;
- encrypted original and thumbnail file sizes and chunk counts;
- the default-off source-removal preference in the vault header; it is visible but authenticated in header version 2.

Titles, usernames, passwords, notes, websites, TOTP seeds, original media bytes, and thumbnail pixels are encrypted.

## Password and recovery model

The master key is derived again on every unlock. No recovery key is stored, and forgotten master passwords cannot be recovered. Back up the application data only as encrypted data and test restoration before relying on it.

## Reporting a vulnerability

Do not publish exploitable security reports in a public issue. Contact the repository owner privately through GitHub's private vulnerability reporting or another private channel. Include the affected commit, platform, reproduction steps, impact, and proposed mitigation when available.
