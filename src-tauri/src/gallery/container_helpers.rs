fn file_key(root_key: &[u8; 32], salt: &[u8; 16], id: Uuid) -> Result<Zeroizing<[u8; 32]>> {
    let mut context = Vec::with_capacity(48);
    context.extend_from_slice(b"nd-secure/gallery-file/v1");
    context.extend_from_slice(id.as_bytes());
    derive_object_key(root_key, salt, &context)
}

fn read_exact_plain<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<()> {
    reader
        .read_exact(buffer)
        .map_err(|_| VaultError::InvalidInput("media source ended before its declared size".into()))
}

fn detect_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 3 && bytes[..3] == [0xff, 0xd8, 0xff] {
        return Some("image/jpeg");
    }
    if bytes.len() >= 8 && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a] {
        return Some("image/png");
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        return Some("video/mp4");
    }
    if bytes.len() >= 8
        && bytes[..4] == [0x1a, 0x45, 0xdf, 0xa3]
        && bytes.windows(4).any(|window| window == b"webm")
    {
        return Some("video/webm");
    }
    None
}

fn chunk_plain_len(total_size: u64, index: u64) -> Result<usize> {
    let start = index
        .checked_mul(CHUNK_SIZE as u64)
        .ok_or(VaultError::MalformedContainer)?;
    if start >= total_size {
        return Err(VaultError::MalformedContainer);
    }
    usize::try_from((total_size - start).min(CHUNK_SIZE as u64))
        .map_err(|_| VaultError::MalformedContainer)
}

fn record_nonce(prefix: [u8; 4], counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn metadata_aad(id: Uuid, header: &[u8; HEADER_SIZE]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + HEADER_SIZE);
    aad.extend_from_slice(b"nd-secure/gallery-metadata/v1");
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(header);
    aad
}

fn chunk_aad(
    id: Uuid,
    total_size: u64,
    chunk_count: u64,
    index: u64,
    plain_len: u32,
    final_chunk: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(80);
    aad.extend_from_slice(b"nd-secure/gallery-chunk/v1");
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&total_size.to_be_bytes());
    aad.extend_from_slice(&chunk_count.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plain_len.to_be_bytes());
    aad.push(u8::from(final_chunk));
    aad
}

fn encode_header(header: &Header) -> [u8; HEADER_SIZE] {
    let mut output = [0_u8; HEADER_SIZE];
    output[0..8].copy_from_slice(MAGIC);
    output[8..10].copy_from_slice(&VERSION.to_be_bytes());
    output[10..14].copy_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
    output[14..22].copy_from_slice(&header.total_size.to_be_bytes());
    output[22..30].copy_from_slice(&header.chunk_count.to_be_bytes());
    output[30..46].copy_from_slice(&header.salt);
    output[46..50].copy_from_slice(&header.nonce_prefix);
    output[50..54].copy_from_slice(&header.metadata_cipher_len.to_be_bytes());
    output
}

fn decode_header(bytes: &[u8; HEADER_SIZE]) -> Result<Header> {
    if &bytes[0..8] != MAGIC {
        return Err(VaultError::MalformedContainer);
    }
    let version = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(bytes[10..14].try_into().unwrap());
    if version != VERSION || chunk_size as usize != CHUNK_SIZE {
        return Err(VaultError::MalformedContainer);
    }
    let total_size = u64::from_be_bytes(bytes[14..22].try_into().unwrap());
    let chunk_count = u64::from_be_bytes(bytes[22..30].try_into().unwrap());
    let salt = bytes[30..46].try_into().unwrap();
    let nonce_prefix = bytes[46..50].try_into().unwrap();
    let metadata_cipher_len = u32::from_be_bytes(bytes[50..54].try_into().unwrap());
    if total_size == 0
        || total_size > MAX_FILE_BYTES
        || chunk_count == 0
        || chunk_count != (total_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
        || metadata_cipher_len as usize <= TAG_SIZE
        || metadata_cipher_len as usize > MAX_METADATA_CIPHER_BYTES
    {
        return Err(VaultError::MalformedContainer);
    }
    Ok(Header {
        total_size,
        chunk_count,
        salt,
        nonce_prefix,
        metadata_cipher_len,
    })
}

fn validate_container_length(header: &Header, actual: u64) -> Result<()> {
    let full_chunks = header.chunk_count.saturating_sub(1);
    let final_plain = chunk_plain_len(header.total_size, header.chunk_count - 1)? as u64;
    let expected = (HEADER_SIZE as u64)
        .checked_add(u64::from(header.metadata_cipher_len))
        .and_then(|value| value.checked_add(full_chunks.checked_mul((CHUNK_SIZE + TAG_SIZE) as u64)?))
        .and_then(|value| value.checked_add(final_plain + TAG_SIZE as u64))
        .ok_or(VaultError::MalformedContainer)?;
    if expected != actual {
        return Err(VaultError::MalformedContainer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_allowlist_detects_supported_formats() {
        assert_eq!(detect_mime(&[0xff, 0xd8, 0xff, 0x00]), Some("image/jpeg"));
        assert_eq!(
            detect_mime(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
            Some("image/png")
        );
        assert_eq!(detect_mime(&[0, 0, 0, 24, b'f', b't', b'y', b'p', 0, 0, 0, 0]), Some("video/mp4"));
        assert_eq!(
            detect_mime(&[0x1a, 0x45, 0xdf, 0xa3, 0x42, 0x82, 0x84, b'w', b'e', b'b', b'm']),
            Some("video/webm")
        );
        assert_eq!(detect_mime(b"not-media"), None);
    }

    #[test]
    fn nonces_change_with_record_counter() {
        let prefix = [1, 2, 3, 4];
        assert_ne!(record_nonce(prefix, 0), record_nonce(prefix, 1));
    }

    #[test]
    fn encrypted_container_round_trips_ranges_and_detects_tampering() {
        use std::io::Cursor;

        let directory = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let partial = directory.path().join(format!("{id}.partial"));
        let final_path = directory.path().join(format!("{id}.enc"));
        let root_key = [42_u8; 32];
        let mut plaintext = vec![0_u8; CHUNK_SIZE * 2 + 113];
        plaintext[..3].copy_from_slice(&[0xff, 0xd8, 0xff]);
        for (index, byte) in plaintext.iter_mut().enumerate().skip(3) {
            *byte = (index % 251) as u8;
        }
        let mut source = Cursor::new(plaintext.clone());
        encrypt_reader(
            &root_key,
            id,
            &mut source,
            plaintext.len() as u64,
            &partial,
            &final_path,
        )
        .unwrap();

        let mut reader = ContainerReader::open(&root_key, id, &final_path).unwrap();
        let start = CHUNK_SIZE as u64 - 17;
        let end = CHUNK_SIZE as u64 + 79;
        let decrypted = reader.decrypt_range(start, end, 1024).unwrap();
        assert_eq!(decrypted, plaintext[start as usize..=end as usize]);
        reader.verify_all().unwrap();

        let mut bytes = fs::read(&final_path).unwrap();
        let final_byte = bytes.last_mut().unwrap();
        *final_byte ^= 0x80;
        fs::write(&final_path, bytes).unwrap();

        let mut tampered = ContainerReader::open(&root_key, id, &final_path).unwrap();
        assert!(matches!(
            tampered.verify_all(),
            Err(VaultError::AuthenticationFailed)
        ));
    }
}
