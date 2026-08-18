# NDVAULT1 Media Container

All integer fields are unsigned and big-endian.

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

Counter zero is reserved for metadata. Content chunk `i` uses counter `i + 1`. A unique per-file key is derived from the gallery domain key, the random file salt, and file UUID, so nonce reuse across files does not reuse an AES-GCM key.

## Metadata

The encrypted JSON metadata contains MIME type, plaintext size, chunk count, and initial authenticated signature bytes. It does not contain the original filename, extension, or path.

## Content records

Each content record contains up to 65,536 plaintext bytes plus a 16-byte GCM tag. AAD binds:

```text
format domain || UUID || plaintext size || chunk count || chunk index ||
plaintext record length || final-record flag
```

The fixed record size permits direct mapping from a plaintext range to the minimum encrypted records needed for authenticated decryption.
