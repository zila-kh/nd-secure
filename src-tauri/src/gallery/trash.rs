use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
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
    crypto::random_array,
    error::{Result, VaultError},
};

use super::{container::ContainerReader, thumbnail::thumbnail_container_id};

const TRASH_SCHEMA_VERSION: i64 = 1;
const CONTAINER_VERSION: i64 = 1;
const THUMBNAIL_MIME: &str = "image/png";
const THUMBNAIL_PENDING: i64 = 0;
const THUMBNAIL_READY: i64 = 1;
const THUMBNAIL_UNAVAILABLE: i64 = 2;
const TRASH_AAD_DOMAIN: &[u8] = b"nd-secure/gallery-trash/v1";
const MAX_TRASH_PAGE: u32 = 500;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GalleryTrashItem {
    pub id: String,
    pub mime_type: String,
    pub file_size_bytes: u64,
    pub timestamp_added: i64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub thumbnail_available: bool,
    pub deleted_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GalleryTrashPage {
    pub items: Vec<GalleryTrashItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrashCursor {
    deleted_at: i64,
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrashThumbnail {
    masked_name: String,
    mime_type: String,
    file_size_bytes: u64,
    container_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrashMetadata {
    id: String,
    masked_name: String,
    mime_type: String,
    file_size_bytes: u64,
    timestamp_added: i64,
    container_version: i64,
    width: Option<u32>,
    height: Option<u32>,
    duration_ms: Option<u64>,
    thumbnail_state: i64,
    thumbnail: Option<TrashThumbnail>,
}

pub struct GalleryTrash {
    db_path: PathBuf,
    objects_dir: PathBuf,
    thumbnails_dir: PathBuf,
    operation: Mutex<()>,
}

impl GalleryTrash {
    pub fn new(db_path: PathBuf, objects_dir: PathBuf, thumbnails_dir: PathBuf) -> Result<Self> {
        let trash = Self { db_path, objects_dir, thumbnails_dir, operation: Mutex::new(()) };
        trash.initialize_schema()?;
        trash.recover()?;
        Ok(trash)
    }

    pub fn page(&self, root_key: &[u8; 32], cursor: Option<&str>, limit: u32) -> Result<GalleryTrashPage> {
        let limit = limit.clamp(1, MAX_TRASH_PAGE) as usize;
        let requested = limit.saturating_add(1);
        let cursor = cursor.map(decode_cursor).transpose()?;
        let connection = self.connection()?;
        let mut items = Vec::with_capacity(requested);

        if let Some(cursor) = cursor {
            let mut statement = connection.prepare_cached(
                "SELECT id, nonce, ciphertext, deleted_at, format_version
                 FROM media_trash
                 WHERE deleted_at < ?1 OR (deleted_at = ?1 AND id < ?2)
                 ORDER BY deleted_at DESC, id DESC
                 LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![cursor.deleted_at, cursor.id, requested as i64],
                map_encrypted_trash_row,
            )?;
            for row in rows {
                let row = row?;
                if row.format_version != TRASH_SCHEMA_VERSION {
                    return Err(VaultError::AuthenticationFailed);
                }
                let metadata = decrypt_metadata(root_key, &row.id, &row.nonce, &row.ciphertext)?;
                items.push(trash_item(metadata, row.deleted_at)?);
            }
        } else {
            let mut statement = connection.prepare_cached(
                "SELECT id, nonce, ciphertext, deleted_at, format_version
                 FROM media_trash
                 ORDER BY deleted_at DESC, id DESC
                 LIMIT ?1",
            )?;
            let rows = statement.query_map(params![requested as i64], map_encrypted_trash_row)?;
            for row in rows {
                let row = row?;
                if row.format_version != TRASH_SCHEMA_VERSION {
                    return Err(VaultError::AuthenticationFailed);
                }
                let metadata = decrypt_metadata(root_key, &row.id, &row.nonce, &row.ciphertext)?;
                items.push(trash_item(metadata, row.deleted_at)?);
            }
        }

        let has_more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = if has_more {
            items
                .last()
                .map(|item| encode_cursor(&TrashCursor { deleted_at: item.deleted_at, id: item.id.clone() }))
                .transpose()?
        } else {
            None
        };
        Ok(GalleryTrashPage { items, next_cursor })
    }

    pub fn delete(&self, root_key: &[u8; 32], id: Uuid) -> Result<()> {
        let _operation = self.operation.lock();
        let metadata = self.active_metadata(id)?;
        validate_metadata(&metadata, id)?;

        let active_object = self.objects_dir.join(&metadata.masked_name);
        if !active_object.is_file() {
            return Err(VaultError::NotFound);
        }
        let object_trashing = self.objects_dir.join(format!("{id}.trashing"));
        let object_trash = self.objects_dir.join(format!("{id}.trash"));
        ensure_absent(&object_trashing)?;
        ensure_absent(&object_trash)?;

        let thumbnail_paths = metadata.thumbnail.as_ref().map(|thumbnail| {
            (
                self.thumbnails_dir.join(&thumbnail.masked_name),
                self.thumbnails_dir.join(format!("{id}.trashing")),
                self.thumbnails_dir.join(format!("{id}.trash")),
            )
        });
        if let Some((active, trashing, trash)) = thumbnail_paths.as_ref() {
            if !active.is_file() {
                return Err(VaultError::AuthenticationFailed);
            }
            ensure_absent(trashing)?;
            ensure_absent(trash)?;
        }

        let deleted_at = unix_timestamp()?;
        let (nonce, ciphertext) = encrypt_metadata(root_key, id, &metadata)?;
        {
            let connection = self.connection()?;
            let inserted = connection.execute(
                "INSERT INTO media_trash (id, nonce, ciphertext, deleted_at, format_version)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id.to_string(), nonce.as_slice(), ciphertext, deleted_at, TRASH_SCHEMA_VERSION,],
            )?;
            if inserted != 1 {
                return Err(VaultError::Database("unable to journal gallery trash operation".into()));
            }
        }

        if let Err(error) = fs::rename(&active_object, &object_trashing) {
            self.remove_trash_row(id)?;
            return Err(error.into());
        }
        if let Some((active, trashing, _)) = thumbnail_paths.as_ref() {
            if let Err(error) = fs::rename(active, trashing) {
                let _ = fs::rename(&object_trashing, &active_object);
                if active_object.is_file() {
                    let _ = self.remove_trash_row(id);
                }
                return Err(error.into());
            }
        }

        let database_result = (|| -> Result<()> {
            let mut connection = self.connection()?;
            let transaction = connection.transaction()?;
            let deleted =
                transaction.execute("DELETE FROM media_items WHERE id = ?1", params![id.to_string()])?;
            if deleted != 1 {
                return Err(VaultError::NotFound);
            }
            transaction.commit()?;
            Ok(())
        })();
        if let Err(error) = database_result {
            let object_restored = fs::rename(&object_trashing, &active_object).is_ok();
            let thumbnail_restored = thumbnail_paths
                .as_ref()
                .is_none_or(|(active, trashing, _)| fs::rename(trashing, active).is_ok());
            if object_restored && thumbnail_restored {
                let _ = self.remove_trash_row(id);
            }
            return Err(error);
        }

        fs::rename(&object_trashing, &object_trash)?;
        if let Some((_, trashing, trash)) = thumbnail_paths.as_ref() {
            fs::rename(trashing, trash)?;
        }
        Ok(())
    }

    pub fn restore(&self, root_key: &[u8; 32], id: Uuid) -> Result<()> {
        let _operation = self.operation.lock();
        let metadata = self.trash_metadata(root_key, id)?;
        validate_metadata(&metadata, id)?;

        if self.active_row_exists(id)? {
            return Err(VaultError::InvalidInput("media item is already active".into()));
        }
        let active_object = self.objects_dir.join(format!("{id}.enc"));
        ensure_absent(&active_object)?;
        let object_source = find_trash_source(&self.objects_dir, id)?.ok_or(VaultError::NotFound)?;
        let object_restoring = self.objects_dir.join(format!("{id}.restoring"));
        if object_source != object_restoring {
            ensure_absent(&object_restoring)?;
            fs::rename(&object_source, &object_restoring)?;
        }

        let thumbnail = metadata.thumbnail.as_ref().and_then(|thumbnail| {
            find_trash_source(&self.thumbnails_dir, id)
                .ok()
                .flatten()
                .map(|source| (thumbnail.clone(), source))
        });
        let thumbnail_restoring = self.thumbnails_dir.join(format!("{id}.restoring"));
        if let Some((_, source)) = thumbnail.as_ref() {
            if source != &thumbnail_restoring {
                ensure_absent(&thumbnail_restoring)?;
                if let Err(error) = fs::rename(source, &thumbnail_restoring) {
                    let _ = fs::rename(&object_restoring, self.objects_dir.join(format!("{id}.trash")));
                    return Err(error.into());
                }
            }
        }

        let restore_thumbnail = thumbnail.is_some();
        let thumbnail_state = if restore_thumbnail {
            THUMBNAIL_READY
        } else if matches!(metadata.mime_type.as_str(), "image/jpeg" | "image/png") {
            THUMBNAIL_PENDING
        } else {
            THUMBNAIL_UNAVAILABLE
        };

        let database_result = (|| -> Result<()> {
            let mut connection = self.connection()?;
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO media_items (
                    id, masked_name, mime_type, file_size_bytes, timestamp_added,
                    container_version, width, height, duration_ms, thumbnail_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    id.to_string(),
                    &metadata.masked_name,
                    &metadata.mime_type,
                    sqlite_integer(metadata.file_size_bytes, "media size")?,
                    metadata.timestamp_added,
                    metadata.container_version,
                    metadata.width.map(i64::from),
                    metadata.height.map(i64::from),
                    metadata.duration_ms.map(|value| sqlite_integer(value, "media duration")).transpose()?,
                    thumbnail_state,
                ],
            )?;
            if let Some((thumbnail, _)) = thumbnail.as_ref() {
                transaction.execute(
                    "INSERT INTO media_thumbnails (
                        media_id, masked_name, mime_type, file_size_bytes, container_version
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        id.to_string(),
                        &thumbnail.masked_name,
                        &thumbnail.mime_type,
                        sqlite_integer(thumbnail.file_size_bytes, "thumbnail size")?,
                        thumbnail.container_version,
                    ],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })();
        if let Err(error) = database_result {
            let _ = fs::rename(&object_restoring, self.objects_dir.join(format!("{id}.trash")));
            if restore_thumbnail {
                let _ = fs::rename(&thumbnail_restoring, self.thumbnails_dir.join(format!("{id}.trash")));
            }
            return Err(error);
        }

        let active_thumbnail = self.thumbnails_dir.join(format!("{id}.enc"));
        let file_result = (|| -> Result<()> {
            fs::rename(&object_restoring, &active_object)?;
            if restore_thumbnail {
                ensure_absent(&active_thumbnail)?;
                fs::rename(&thumbnail_restoring, &active_thumbnail)?;
            }
            Ok(())
        })();
        if let Err(error) = file_result {
            let connection = self.connection()?;
            let _ = connection.execute("DELETE FROM media_items WHERE id = ?1", params![id.to_string()]);
            if active_object.is_file() {
                let _ = fs::rename(&active_object, self.objects_dir.join(format!("{id}.trash")));
            } else if object_restoring.is_file() {
                let _ = fs::rename(&object_restoring, self.objects_dir.join(format!("{id}.trash")));
            }
            if active_thumbnail.is_file() {
                let _ = fs::rename(&active_thumbnail, self.thumbnails_dir.join(format!("{id}.trash")));
            } else if thumbnail_restoring.is_file() {
                let _ = fs::rename(&thumbnail_restoring, self.thumbnails_dir.join(format!("{id}.trash")));
            }
            return Err(error);
        }

        self.remove_trash_row(id)?;
        Ok(())
    }

    pub fn purge(&self, id: Uuid) -> Result<()> {
        let _operation = self.operation.lock();
        self.purge_locked(id)
    }

    pub fn empty(&self) -> Result<usize> {
        let _operation = self.operation.lock();
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT id FROM media_trash ORDER BY deleted_at DESC, id DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let ids = rows
            .map(|row| {
                let value = row?;
                Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        drop(connection);

        let mut purged = 0;
        for id in ids {
            self.purge_locked(id)?;
            purged += 1;
        }
        Ok(purged)
    }

    pub fn verify_item(&self, root_key: &[u8; 32], id: Uuid) -> Result<u64> {
        let metadata = self.trash_metadata(root_key, id)?;
        validate_metadata(&metadata, id)?;
        let object_path = find_trash_source(&self.objects_dir, id)?.ok_or(VaultError::NotFound)?;
        let mut object = ContainerReader::open(root_key, id, &object_path)?;
        object.verify_all()?;
        if object.metadata().mime_type != metadata.mime_type
            || object.metadata().total_size != metadata.file_size_bytes
        {
            return Err(VaultError::AuthenticationFailed);
        }
        let mut verified_bytes = metadata.file_size_bytes;

        if let Some(thumbnail) = metadata.thumbnail.as_ref() {
            if let Some(thumbnail_path) = find_trash_source(&self.thumbnails_dir, id)? {
                let thumbnail_id = thumbnail_container_id(id);
                let mut object = ContainerReader::open(root_key, thumbnail_id, &thumbnail_path)?;
                object.verify_all()?;
                if object.metadata().mime_type != THUMBNAIL_MIME
                    || object.metadata().total_size != thumbnail.file_size_bytes
                {
                    return Err(VaultError::AuthenticationFailed);
                }
                verified_bytes = verified_bytes.saturating_add(thumbnail.file_size_bytes);
            }
        }
        Ok(verified_bytes)
    }

    fn purge_locked(&self, id: Uuid) -> Result<()> {
        if self.active_row_exists(id)? {
            return Err(VaultError::AuthenticationFailed);
        }
        let connection = self.connection()?;
        let deleted = connection.execute("DELETE FROM media_trash WHERE id = ?1", params![id.to_string()])?;
        if deleted != 1 {
            return Err(VaultError::NotFound);
        }
        remove_trash_variants(&self.objects_dir, id);
        remove_trash_variants(&self.thumbnails_dir, id);
        Ok(())
    }

    fn active_metadata(&self, id: Uuid) -> Result<TrashMetadata> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT m.id, m.masked_name, m.mime_type, m.file_size_bytes, m.timestamp_added,
                        m.container_version, m.width, m.height, m.duration_ms, m.thumbnail_state,
                        t.masked_name, t.mime_type, t.file_size_bytes, t.container_version
                 FROM media_items m
                 LEFT JOIN media_thumbnails t ON t.media_id = m.id
                 WHERE m.id = ?1",
                params![id.to_string()],
                |row| {
                    let thumbnail_name: Option<String> = row.get(10)?;
                    let thumbnail_mime: Option<String> = row.get(11)?;
                    let thumbnail_size: Option<u64> = row.get(12)?;
                    let thumbnail_version: Option<i64> = row.get(13)?;
                    let thumbnail = match (thumbnail_name, thumbnail_mime, thumbnail_size, thumbnail_version)
                    {
                        (
                            Some(masked_name),
                            Some(mime_type),
                            Some(file_size_bytes),
                            Some(container_version),
                        ) => Some(TrashThumbnail {
                            masked_name,
                            mime_type,
                            file_size_bytes,
                            container_version,
                        }),
                        (None, None, None, None) => None,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    Ok(TrashMetadata {
                        id: row.get(0)?,
                        masked_name: row.get(1)?,
                        mime_type: row.get(2)?,
                        file_size_bytes: row.get(3)?,
                        timestamp_added: row.get(4)?,
                        container_version: row.get(5)?,
                        width: row.get(6)?,
                        height: row.get(7)?,
                        duration_ms: row.get(8)?,
                        thumbnail_state: row.get(9)?,
                        thumbnail,
                    })
                },
            )
            .optional()?
            .ok_or(VaultError::NotFound)
    }

    fn trash_metadata(&self, root_key: &[u8; 32], id: Uuid) -> Result<TrashMetadata> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT nonce, ciphertext, format_version FROM media_trash WHERE id = ?1",
                params![id.to_string()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?)),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        if row.2 != TRASH_SCHEMA_VERSION {
            return Err(VaultError::AuthenticationFailed);
        }
        let nonce: [u8; 12] = row.0.try_into().map_err(|_| VaultError::AuthenticationFailed)?;
        decrypt_metadata(root_key, &id.to_string(), &nonce, &row.1)
    }

    fn active_row_exists(&self, id: Uuid) -> Result<bool> {
        let connection = self.connection()?;
        let exists: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM media_items WHERE id = ?1)",
            params![id.to_string()],
            |row| row.get(0),
        )?;
        Ok(exists != 0)
    }

    fn remove_trash_row(&self, id: Uuid) -> Result<()> {
        let connection = self.connection()?;
        connection.execute("DELETE FROM media_trash WHERE id = ?1", params![id.to_string()])?;
        Ok(())
    }

    fn initialize_schema(&self) -> Result<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS media_trash (
                id TEXT PRIMARY KEY NOT NULL,
                nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16),
                deleted_at INTEGER NOT NULL,
                format_version INTEGER NOT NULL CHECK(format_version = 1)
             );
             CREATE INDEX IF NOT EXISTS idx_media_trash_deleted_id
             ON media_trash(deleted_at DESC, id DESC);",
        )?;
        Ok(())
    }

    fn recover(&self) -> Result<()> {
        let _operation = self.operation.lock();
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT id FROM media_trash")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut trash_ids = HashSet::new();
        for row in rows {
            let id = row?;
            if canonical_uuid(&id).is_some() {
                trash_ids.insert(id);
            } else {
                connection.execute("DELETE FROM media_trash WHERE id = ?1", params![id])?;
            }
        }
        drop(statement);

        let active_ids = collect_ids(&connection, "SELECT id FROM media_items")?;
        let mut completed_restores = Vec::new();
        let mut missing_primary = Vec::new();
        for id in trash_ids.iter() {
            let parsed = Uuid::parse_str(id).map_err(|_| VaultError::AuthenticationFailed)?;
            let active_path = self.objects_dir.join(format!("{id}.enc"));
            if active_ids.contains(id) && active_path.is_file() {
                completed_restores.push(id.clone());
                continue;
            }
            if normalize_trash_variant(&self.objects_dir, parsed)?.is_none() {
                missing_primary.push(id.clone());
                continue;
            }
            let _ = normalize_trash_variant(&self.thumbnails_dir, parsed)?;
        }
        for id in completed_restores.iter().chain(missing_primary.iter()) {
            connection.execute("DELETE FROM media_trash WHERE id = ?1", params![id])?;
            trash_ids.remove(id);
        }
        drop(connection);

        cleanup_orphan_trash_variants(&self.objects_dir, &trash_ids)?;
        cleanup_orphan_trash_variants(&self.thumbnails_dir, &trash_ids)?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.db_path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(connection)
    }
}

struct EncryptedTrashRow {
    id: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    deleted_at: i64,
    format_version: i64,
}

fn map_encrypted_trash_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedTrashRow> {
    let nonce: Vec<u8> = row.get(1)?;
    Ok(EncryptedTrashRow {
        id: row.get(0)?,
        nonce: nonce.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        ciphertext: row.get(2)?,
        deleted_at: row.get(3)?,
        format_version: row.get(4)?,
    })
}

fn trash_item(metadata: TrashMetadata, deleted_at: i64) -> Result<GalleryTrashItem> {
    let id = Uuid::parse_str(&metadata.id).map_err(|_| VaultError::AuthenticationFailed)?;
    validate_metadata(&metadata, id)?;
    Ok(GalleryTrashItem {
        id: metadata.id,
        mime_type: metadata.mime_type,
        file_size_bytes: metadata.file_size_bytes,
        timestamp_added: metadata.timestamp_added,
        width: metadata.width,
        height: metadata.height,
        duration_ms: metadata.duration_ms,
        thumbnail_available: metadata.thumbnail.is_some(),
        deleted_at,
    })
}

fn encrypt_metadata(root_key: &[u8; 32], id: Uuid, metadata: &TrashMetadata) -> Result<([u8; 12], Vec<u8>)> {
    let nonce = random_array::<12>();
    let plaintext = Zeroizing::new(serde_json::to_vec(metadata)?);
    let cipher = Aes256Gcm::new_from_slice(root_key).map_err(|_| VaultError::Crypto)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext.as_slice(), aad: &trash_aad(id) })
        .map_err(|_| VaultError::Crypto)?;
    Ok((nonce, ciphertext))
}

fn decrypt_metadata(
    root_key: &[u8; 32],
    id: &str,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<TrashMetadata> {
    let parsed = Uuid::parse_str(id).map_err(|_| VaultError::AuthenticationFailed)?;
    if parsed.to_string() != id {
        return Err(VaultError::AuthenticationFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(root_key).map_err(|_| VaultError::Crypto)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &trash_aad(parsed) })
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    serde_json::from_slice(plaintext.as_slice()).map_err(|_| VaultError::AuthenticationFailed)
}

fn trash_aad(id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TRASH_AAD_DOMAIN.len() + 16);
    aad.extend_from_slice(TRASH_AAD_DOMAIN);
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn validate_metadata(metadata: &TrashMetadata, id: Uuid) -> Result<()> {
    if metadata.id != id.to_string()
        || metadata.masked_name != format!("{id}.enc")
        || metadata.container_version != CONTAINER_VERSION
        || metadata.file_size_bytes == 0
        || !matches!(metadata.mime_type.as_str(), "image/jpeg" | "image/png" | "video/mp4" | "video/webm")
        || !matches!(metadata.thumbnail_state, THUMBNAIL_PENDING | THUMBNAIL_READY | THUMBNAIL_UNAVAILABLE)
    {
        return Err(VaultError::AuthenticationFailed);
    }
    if let Some(thumbnail) = metadata.thumbnail.as_ref() {
        if thumbnail.masked_name != format!("{id}.enc")
            || thumbnail.mime_type != THUMBNAIL_MIME
            || thumbnail.file_size_bytes == 0
            || thumbnail.container_version != CONTAINER_VERSION
        {
            return Err(VaultError::AuthenticationFailed);
        }
    }
    Ok(())
}

fn ensure_absent(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(())
}

fn find_trash_source(directory: &Path, id: Uuid) -> Result<Option<PathBuf>> {
    for extension in ["trash", "trashing", "restoring"] {
        let path = directory.join(format!("{id}.{extension}"));
        if path.is_file() {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn normalize_trash_variant(directory: &Path, id: Uuid) -> Result<Option<PathBuf>> {
    let target = directory.join(format!("{id}.trash"));
    if target.is_file() {
        remove_file_if_present(&directory.join(format!("{id}.trashing")));
        remove_file_if_present(&directory.join(format!("{id}.restoring")));
        return Ok(Some(target));
    }
    for extension in ["trashing", "restoring"] {
        let source = directory.join(format!("{id}.{extension}"));
        if source.is_file() {
            fs::rename(&source, &target)?;
            return Ok(Some(target));
        }
    }
    Ok(None)
}

fn remove_trash_variants(directory: &Path, id: Uuid) {
    for extension in ["trash", "trashing", "restoring"] {
        remove_file_if_present(&directory.join(format!("{id}.{extension}")));
    }
}

fn cleanup_orphan_trash_variants(directory: &Path, expected_ids: &HashSet<String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
        if !matches!(extension, "trash" | "trashing" | "restoring") {
            continue;
        }
        let stem = path.file_stem().and_then(|value| value.to_str()).unwrap_or_default();
        if !expected_ids.contains(stem) {
            remove_file_if_present(&path);
        }
    }
    Ok(())
}

fn collect_ids(connection: &Connection, query: &str) -> Result<HashSet<String>> {
    let mut ids = HashSet::new();
    let mut statement = connection.prepare(query)?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    for row in rows {
        ids.insert(row?);
    }
    Ok(ids)
}

fn remove_file_if_present(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {}
    }
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value).ok().filter(|parsed| parsed.to_string() == value)
}

fn sqlite_integer(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| VaultError::InvalidInput(format!("{label} exceeds SQLite integer range")))
}

fn encode_cursor(cursor: &TrashCursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

fn decode_cursor(value: &str) -> Result<TrashCursor> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| VaultError::InvalidInput("invalid gallery trash cursor".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidInput("invalid gallery trash cursor".into()))
}

fn unix_timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Storage("system clock is before UNIX epoch".into()))?;
    i64::try_from(duration.as_secs()).map_err(|_| VaultError::Storage("system clock overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gallery::GalleryRepository;
    use image::{DynamicImage, ImageFormat};
    use std::io::Cursor;

    #[test]
    fn delete_moves_media_to_authenticated_trash_and_restore_returns_it() {
        let directory = tempfile::tempdir().unwrap();
        let repository = test_repository(directory.path());
        let trash = test_trash(directory.path());
        let key = [61_u8; 32];
        let id = import_png(&repository, &key);

        trash.delete(&key, id).unwrap();
        assert!(matches!(repository.get(id), Err(VaultError::NotFound)));
        let page = trash.page(&key, None, 10).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, id.to_string());
        assert!(trash.verify_item(&key, id).unwrap() > 0);

        trash.restore(&key, id).unwrap();
        assert_eq!(repository.get(id).unwrap().id, id.to_string());
        assert!(trash.page(&key, None, 10).unwrap().items.is_empty());
    }

    #[test]
    fn purge_removes_only_trashed_media() {
        let directory = tempfile::tempdir().unwrap();
        let repository = test_repository(directory.path());
        let trash = test_trash(directory.path());
        let key = [67_u8; 32];
        let id = import_png(&repository, &key);

        assert!(matches!(trash.purge(id), Err(VaultError::AuthenticationFailed)));
        trash.delete(&key, id).unwrap();
        trash.purge(id).unwrap();
        assert!(trash.page(&key, None, 10).unwrap().items.is_empty());
        assert!(!directory.path().join("objects").join(format!("{id}.trash")).exists());
    }

    #[test]
    fn recovery_normalizes_interrupted_trash_rename() {
        let directory = tempfile::tempdir().unwrap();
        let repository = test_repository(directory.path());
        let trash = test_trash(directory.path());
        let key = [71_u8; 32];
        let id = import_png(&repository, &key);
        trash.delete(&key, id).unwrap();

        let object_trash = directory.path().join("objects").join(format!("{id}.trash"));
        let interrupted = directory.path().join("objects").join(format!("{id}.trashing"));
        fs::rename(&object_trash, &interrupted).unwrap();
        drop(trash);

        let recovered = test_trash(directory.path());
        assert!(object_trash.is_file());
        assert_eq!(recovered.page(&key, None, 10).unwrap().items.len(), 1);
    }

    fn test_repository(root: &Path) -> GalleryRepository {
        GalleryRepository::new(root.join("gallery.sqlite3"), root.join("objects"), root.join("thumbnails"))
            .unwrap()
    }

    fn test_trash(root: &Path) -> GalleryTrash {
        GalleryTrash::new(root.join("gallery.sqlite3"), root.join("objects"), root.join("thumbnails"))
            .unwrap()
    }

    fn import_png(repository: &GalleryRepository, key: &[u8; 32]) -> Uuid {
        let image = DynamicImage::new_rgb8(48, 32);
        let mut encoded = Cursor::new(Vec::new());
        image.write_to(&mut encoded, ImageFormat::Png).unwrap();
        let bytes = encoded.into_inner();
        let mut source = Cursor::new(bytes.as_slice());
        let id = repository.import_reader(key, &mut source, bytes.len() as u64).unwrap();
        Uuid::parse_str(&id).unwrap()
    }
}
