use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{derive_object_key, random_array},
    error::{Result, VaultError},
};

const MAGIC: &[u8; 8] = b"NDVAULT1";
const VERSION: u16 = 1;
pub const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const HEADER_SIZE: usize = 54;
const MAX_METADATA_CIPHER_BYTES: usize = 64 * 1024;
const SIGNATURE_BYTES: usize = 4096;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaMetadata {
    pub mime_type: String,
    pub total_size: u64,
    pub chunk_count: u64,
    pub signature: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
}

impl Drop for MediaMetadata {
    fn drop(&mut self) {
        self.signature.zeroize();
    }
}

#[derive(Debug, Clone)]
struct Header {
    total_size: u64,
    chunk_count: u64,
    salt: [u8; 16],
    nonce_prefix: [u8; 4],
    metadata_cipher_len: u32,
}

pub struct ContainerReader {
    id: Uuid,
    file: File,
    header: Header,
    metadata: MediaMetadata,
    key: Zeroizing<[u8; 32]>,
    data_offset: u64,
}

include!("container_reader.rs");
include!("container_writer.rs");
include!("container_helpers.rs");
