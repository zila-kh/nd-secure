# Security Policy and Threat Model

## Supported branch

Security fixes are applied to the latest `main` branch. The application is pre-audit software and does not yet claim production password-manager assurance.

## Security objectives

ND Secure is designed to protect vault contents against offline inspection of application storage after the application has been locked or terminated, assuming the master password has sufficient entropy and the cryptographic implementation is correct.

The application aims to prevent:

- app-created plaintext media files, thumbnails, or credential databases;
- persistence of the master or domain keys;
- original media filename and source-path storage;
- unauthenticated media chunk modification, reordering, truncation, and splicing;
- direct JavaScript access to the master key or TOTP seed during ordinary use;
- unbounded gallery DOM growth and unbounded custom-protocol response bodies.

## Out of scope

The current design does not protect against:

- a compromised kernel, root/administrator user, debugger, injected process, or malicious accessibility service;
- plaintext already present in source files selected for import;
- screen capture, cameras, shoulder surfing, or clipboard history controlled by the operating system;
- swap, hibernation, process dumps, or device-memory acquisition on every supported platform;
- malicious code running inside a compromised application build or WebView;
- weak or reused master passwords;
- denial of service, deletion, or rollback by an attacker with write access to application storage.

## Cryptographic design

- Master key: Argon2id output, 32 bytes.
- Root separation: HKDF-SHA-256 domain labels.
- AEAD: AES-256-GCM.
- Gallery: random per-file salt, derived per-file key, four-byte random nonce prefix plus a 64-bit record counter.
- Credentials: random per-record salt and 96-bit random nonce under a distinct derived record key.
- Owned secret buffers use `zeroize` where practical.

No plaintext is released from a media record until its AES-GCM tag verifies. Media metadata and each 64 KiB content record are independently authenticated. AAD binds the file UUID, total size, chunk count, chunk index, record length, and final-record marker.

## Metadata disclosure

The following values are currently visible to offline inspection of SQLite and the public media-container header:

- vault format and KDF parameters;
- item and credential counts;
- UUID identifiers;
- credential record type and timestamps;
- media MIME type, size, and import timestamp;
- encrypted file sizes and chunk counts.

Titles, usernames, passwords, notes, websites, TOTP seeds, and media bytes are encrypted.

## Password and recovery model

The master key is derived again on every unlock. No recovery key is stored, and forgotten master passwords cannot be recovered. Back up the application data only as encrypted data and test restoration before relying on it.

## Reporting a vulnerability

Do not publish exploitable security reports in a public issue. Contact the repository owner privately through GitHub's private vulnerability reporting or another private channel. Include the affected commit, platform, reproduction steps, impact, and proposed mitigation when available.
