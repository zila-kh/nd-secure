use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::{derive_object_key, random_array},
    error::{Result, VaultError},
};

use super::totp::validate_totp_secret;

const FORMAT_VERSION: i64 = 1;
const MAX_TITLE_BYTES: usize = 512;
const MAX_USERNAME_BYTES: usize = 4096;
const MAX_PASSWORD_BYTES: usize = 16 * 1024;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_NOTES_BYTES: usize = 1024 * 1024;
const MAX_PROJECT_BYTES: usize = 256;
const MAX_ENVIRONMENT_BYTES: usize = 64;
const MAX_FOLDER_BYTES: usize = 256;
const MAX_WEBSITES: usize = 64;
const MAX_WEBSITE_BYTES: usize = 4096;
const MAX_CUSTOM_FIELDS: usize = 32;
const MAX_CUSTOM_FIELD_NAME_BYTES: usize = 256;
const MAX_CUSTOM_FIELD_VALUE_BYTES: usize = 64 * 1024;
const MAX_PASSWORD_HISTORY: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Login,
    SecureNote,
    Totp,
    Secret,
}

impl CredentialType {
    fn as_i64(self) -> i64 {
        match self {
            Self::Login => 1,
            Self::SecureNote => 2,
            Self::Totp => 3,
            Self::Secret => 4,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Login),
            2 => Ok(Self::SecureNote),
            3 => Ok(Self::Totp),
            4 => Ok(Self::Secret),
            _ => Err(VaultError::AuthenticationFailed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialScope {
    #[default]
    Central,
    Project,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialField {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInput {
    pub id: Option<String>,
    pub record_type: CredentialType,
    pub title: String,
    #[serde(default)]
    pub scope: CredentialScope,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub secret_value: Option<String>,
    pub websites: Vec<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CredentialField>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDetail {
    pub id: String,
    pub record_type: CredentialType,
    pub title: String,
    #[serde(default)]
    pub scope: CredentialScope,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub secret_value: Option<String>,
    pub websites: Vec<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CredentialField>,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSummary {
    pub id: String,
    pub record_type: CredentialType,
    pub title: String,
    pub scope: CredentialScope,
    pub project: Option<String>,
    pub environment: Option<String>,
    pub folder: Option<String>,
    pub username: Option<String>,
    pub favorite: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPage {
    pub items: Vec<CredentialSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cursor {
    updated_at: i64,
    id: String,
}

struct EncryptedRow {
    id: Uuid,
    record_type: CredentialType,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    format_version: i64,
    revision: i64,
    created_at: i64,
    updated_at: i64,
}

pub struct CredentialRepository {
    db_path: PathBuf,
    writer: Mutex<()>,
}

include!("repository_write.rs");
include!("repository_read.rs");
include!("repository_project.rs");
include!("repository_helpers.rs");
