impl ContainerReader {
    pub fn open(root_key: &[u8; 32], id: Uuid, path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut header_bytes = [0_u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)
            .map_err(|_| VaultError::MalformedContainer)?;
        let header = decode_header(&header_bytes)?;
        validate_container_length(&header, file_len)?;

        let key = file_key(root_key, &header.salt, id)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
        let metadata_cipher_len = usize::try_from(header.metadata_cipher_len)
            .map_err(|_| VaultError::MalformedContainer)?;
        let mut encrypted_metadata = Zeroizing::new(vec![0_u8; metadata_cipher_len]);
        file.read_exact(encrypted_metadata.as_mut_slice())
            .map_err(|_| VaultError::MalformedContainer)?;
        let metadata_plain_len = metadata_cipher_len
            .checked_sub(TAG_SIZE)
            .ok_or(VaultError::MalformedContainer)?;
        let (metadata_ciphertext, metadata_tag_bytes) =
            encrypted_metadata.split_at_mut(metadata_plain_len);
        let tag = Tag::from_slice(metadata_tag_bytes);
        let metadata_aad = metadata_aad(id, &header_bytes);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&record_nonce(header.nonce_prefix, 0)),
                &metadata_aad,
                metadata_ciphertext,
                tag,
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;
        let metadata: MediaMetadata =
            serde_json::from_slice(&encrypted_metadata[..metadata_plain_len])
                .map_err(|_| VaultError::MalformedContainer)?;
        if metadata.total_size != header.total_size || metadata.chunk_count != header.chunk_count {
            return Err(VaultError::AuthenticationFailed);
        }

        let data_offset = (HEADER_SIZE as u64)
            .checked_add(u64::from(header.metadata_cipher_len))
            .ok_or(VaultError::MalformedContainer)?;
        let mut reader = Self {
            id,
            file,
            header,
            metadata,
            key,
            data_offset,
        };
        let first = reader.decrypt_chunk(0)?;
        let detected = detect_mime(&first).ok_or(VaultError::UnsupportedMedia)?;
        if detected != reader.metadata.mime_type {
            return Err(VaultError::AuthenticationFailed);
        }
        let recorded_signature = Zeroizing::new(
            BASE64
                .decode(reader.metadata.signature.as_bytes())
                .map_err(|_| VaultError::MalformedContainer)?,
        );
        let expected_signature_len =
            usize::try_from(reader.header.total_size.min(SIGNATURE_BYTES as u64))
                .map_err(|_| VaultError::MalformedContainer)?;
        if recorded_signature.len() != expected_signature_len
            || first.len() < expected_signature_len
            || recorded_signature.as_slice() != &first[..expected_signature_len]
        {
            return Err(VaultError::AuthenticationFailed);
        }
        reader.metadata.signature.zeroize();
        Ok(reader)
    }

    pub fn metadata(&self) -> &MediaMetadata {
        &self.metadata
    }

    pub fn decrypt_range(
        &mut self,
        start: u64,
        end: u64,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>> {
        if start > end || end >= self.header.total_size {
            return Err(VaultError::InvalidRange);
        }
        let length = end
            .checked_sub(start)
            .and_then(|value| value.checked_add(1))
            .ok_or(VaultError::InvalidRange)?;
        if length > maximum_bytes {
            return Err(VaultError::RangeTooLarge);
        }
        self.decrypt_range_unchecked(start, end)
    }

    pub fn decrypt_all_bounded(
        &mut self,
        maximum_bytes: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.header.total_size == 0 || self.header.total_size > maximum_bytes {
            return Err(VaultError::RangeTooLarge);
        }
        let output_len = usize::try_from(self.header.total_size)
            .map_err(|_| VaultError::RangeTooLarge)?;
        let mut output = Zeroizing::new(Vec::new());
        output
            .try_reserve_exact(output_len)
            .map_err(|_| VaultError::RangeTooLarge)?;

        for index in 0..self.header.chunk_count {
            let plaintext = self.decrypt_chunk(index)?;
            output.extend_from_slice(plaintext.as_slice());
        }
        if output.len() != output_len {
            return Err(VaultError::MalformedContainer);
        }
        Ok(output)
    }

    pub fn verify_all(&mut self) -> Result<()> {
        for index in 0..self.header.chunk_count {
            let _ = self.decrypt_chunk(index)?;
        }
        Ok(())
    }

    fn decrypt_range_unchecked(&mut self, start: u64, end: u64) -> Result<Vec<u8>> {
        let first_chunk = start / CHUNK_SIZE as u64;
        let last_chunk = end / CHUNK_SIZE as u64;
        let output_len = usize::try_from(end - start + 1).map_err(|_| VaultError::RangeTooLarge)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| VaultError::RangeTooLarge)?;

        for index in first_chunk..=last_chunk {
            let plaintext = self.decrypt_chunk(index)?;
            let chunk_start = index * CHUNK_SIZE as u64;
            let take_start = start.saturating_sub(chunk_start) as usize;
            let take_end = ((end - chunk_start + 1) as usize).min(plaintext.len());
            if take_start >= take_end || take_end > plaintext.len() {
                return Err(VaultError::MalformedContainer);
            }
            output.extend_from_slice(&plaintext[take_start..take_end]);
        }
        if output.len() != output_len {
            return Err(VaultError::MalformedContainer);
        }
        Ok(output)
    }

    fn decrypt_chunk(&mut self, index: u64) -> Result<Zeroizing<Vec<u8>>> {
        if index >= self.header.chunk_count {
            return Err(VaultError::InvalidRange);
        }
        let plain_len = chunk_plain_len(self.header.total_size, index)?;
        let record_stride = (CHUNK_SIZE + TAG_SIZE) as u64;
        let offset = self
            .data_offset
            .checked_add(
                index
                    .checked_mul(record_stride)
                    .ok_or(VaultError::MalformedContainer)?,
            )
            .ok_or(VaultError::MalformedContainer)?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut encrypted = Zeroizing::new(vec![0_u8; plain_len + TAG_SIZE]);
        self.file
            .read_exact(encrypted.as_mut_slice())
            .map_err(|_| VaultError::MalformedContainer)?;
        let (chunk_ciphertext, tag_bytes) = encrypted.split_at_mut(plain_len);
        let tag = Tag::from_slice(tag_bytes);
        let aad = chunk_aad(
            self.id,
            self.header.total_size,
            self.header.chunk_count,
            index,
            plain_len as u32,
            index + 1 == self.header.chunk_count,
        );
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| VaultError::Crypto)?;
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&record_nonce(self.header.nonce_prefix, index + 1)),
                &aad,
                chunk_ciphertext,
                tag,
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;
        encrypted.truncate(plain_len);
        Ok(encrypted)
    }
}
