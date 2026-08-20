# NDVAULT1 Media Container

All integer fields are unsigned and big-endian. The same authenticated container format is used for original media and generated PNG thumbnails.

## Public header (54 bytes)

| Offset | Length | Field |
|---:|---:|---|
| 0 | 8 | ASCII `NDVAULT1` |
| 8 | 2 | format version |
| 10 | 4 | plaintext chunk size |
| 14 | 8 | total plaintext size |
| 22 | 8 | chunk count |
| 30 | 16 | per-file HKDF salt |
| 46 | 4 | random nonce prefix |
| 50 | 4 | encrypted metadata length including tag |

The header is authenticated as AAD for the metadata record.

## Nonces

```text
nonce = 4-byte random file prefix || 8-byte record counter
```

Counter zero is reserved for metadata. Content chunk `i` uses counter `i + 1`. A unique per-file key is derived from the gallery domain key, the random file salt, and container UUID, so nonce reuse across files does not reuse an AES-GCM key.

## Container identities

Original media uses its public gallery UUID as the container UUID.

A thumbnail container UUID is deterministically derived as:

```text
UUIDv8(first_16_bytes(SHA-256(
  "nd-secure/gallery-thumbnail-id/v1" || media_uuid
)))
```

The thumbnail filename remains `<media_uuid>.enc` inside the dedicated `gallery/thumbnails` directory. The derived container UUID is supplied to key derivation and every AAD record, binding the encrypted thumbnail to its parent media item without exposing a second random identifier in SQLite.

## Metadata

The encrypted JSON metadata contains MIME type, plaintext size, chunk count, and initial authenticated signature bytes. It does not contain the original filename, extension, or source path. Thumbnail metadata identifies only `image/png` content and is verified against the thumbnail index before serving.

## Content records

Each content record contains up to 65,536 plaintext bytes plus a 16-byte GCM tag. AAD binds:

```text
format domain || container UUID || plaintext size || chunk count || chunk index ||
plaintext record length || final-record flag
```

The fixed record size permits direct mapping from a plaintext range to the minimum encrypted records needed for authenticated decryption.

## Thumbnail generation and storage

JPEG and PNG inputs within the configured source-capture bound are copied only into zeroizing process-memory buffers while the original stream is encrypted. Strict dimension checks and a conservative decoded-pixel budget run before decode; the decoder also receives a best-effort allocation limit. Embedded orientation is applied to the derivative, and decoder unwinds are caught at the thumbnail boundary so malformed input becomes a missing thumbnail instead of escaping into the import or protocol worker. A maximum 512 x 512 PNG is encoded in memory, encrypted into `NDVAULT1`, authenticated, and inserted into the same SQLite transaction as the original media row. Any import failure removes both final encrypted objects or leaves only recoverable encrypted crash artifacts. Existing image rows from schema version 1 are lazily backfilled: the original container is fully authenticated, bounded plaintext is held in zeroizing memory, and the new thumbnail row is committed only after its encrypted container verifies.

Gallery cards use `vault://.../thumbnail/<media_uuid>`. They do not request the original image when a thumbnail is unavailable. The full-screen viewer continues to use `vault://.../media/<media_uuid>`.
