pub fn encrypt_reader<R: Read>(
    root_key: &[u8; 32],
    id: Uuid,
    reader: &mut R,
    total_size: u64,
    partial_path: &Path,
    final_path: &Path,
) -> Result<MediaMetadata> {
    if total_size == 0 || total_size > MAX_FILE_BYTES {
        return Err(VaultError::InvalidInput("media size is outside supported bounds".into()));
    }
    let chunk_count = total_size
        .checked_add(CHUNK_SIZE as u64 - 1)
        .ok_or(VaultError::InvalidInput("media size overflow".into()))?
        / CHUNK_SIZE as u64;
    let salt = random_array::<16>();
    let nonce_prefix = random_array::<4>();
    let key = file_key(root_key, &salt, id)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;

    let first_plain_len = chunk_plain_len(total_size, 0)?;
    let mut chunk = Zeroizing::new(vec![0_u8; CHUNK_SIZE]);
    read_exact_plain(reader, &mut chunk[..first_plain_len])?;
    let mime_type = detect_mime(&chunk[..first_plain_len])
        .ok_or(VaultError::UnsupportedMedia)?
        .to_owned();
    let signature_len = first_plain_len.min(SIGNATURE_BYTES);
    let metadata = MediaMetadata {
        mime_type,
        total_size,
        chunk_count,
        signature: BASE64.encode(&chunk[..signature_len]),
        width: None,
        height: None,
        duration_ms: None,
    };
    let metadata_plain = serde_json::to_vec(&metadata)?;
    let metadata_cipher_len = metadata_plain
        .len()
        .checked_add(TAG_SIZE)
        .ok_or(VaultError::MalformedContainer)?;
    if metadata_cipher_len > MAX_METADATA_CIPHER_BYTES {
        return Err(VaultError::MalformedContainer);
    }
    let header = Header {
        total_size,
        chunk_count,
        salt,
        nonce_prefix,
        metadata_cipher_len: u32::try_from(metadata_cipher_len)
            .map_err(|_| VaultError::MalformedContainer)?,
    };
    let header_bytes = encode_header(&header);

    if let Some(parent) = partial_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut destination = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(partial_path)?;
    let operation = (|| -> Result<()> {
        destination.write_all(&header_bytes)?;
        let mut encrypted_metadata = Zeroizing::new(metadata_plain);
        let metadata_tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&record_nonce(nonce_prefix, 0)),
                &metadata_aad(id, &header_bytes),
                encrypted_metadata.as_mut_slice(),
            )
            .map_err(|_| VaultError::Crypto)?;
        destination.write_all(encrypted_metadata.as_slice())?;
        destination.write_all(metadata_tag.as_slice())?;

        for index in 0..chunk_count {
            let plain_len = chunk_plain_len(total_size, index)?;
            if index > 0 {
                read_exact_plain(reader, &mut chunk[..plain_len])?;
            }
            let aad = chunk_aad(
                id,
                total_size,
                chunk_count,
                index,
                plain_len as u32,
                index + 1 == chunk_count,
            );
            let tag = cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&record_nonce(nonce_prefix, index + 1)),
                    &aad,
                    &mut chunk[..plain_len],
                )
                .map_err(|_| VaultError::Crypto)?;
            destination.write_all(&chunk[..plain_len])?;
            destination.write_all(tag.as_slice())?;
        }

        let mut extra = [0_u8; 1];
        if reader.read(&mut extra)? != 0 {
            return Err(VaultError::InvalidInput(
                "media source changed size while being imported".into(),
            ));
        }
        destination.flush()?;
        destination.sync_all()?;
        Ok(())
    })();

    if let Err(error) = operation {
        drop(destination);
        let _ = fs::remove_file(partial_path);
        return Err(error);
    }
    drop(destination);
    if final_path.exists() {
        let _ = fs::remove_file(partial_path);
        return Err(VaultError::Storage("generated media identifier already exists".into()));
    }
    fs::rename(partial_path, final_path)?;
    Ok(metadata)
}

