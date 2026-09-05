use std::{
    collections::HashSet,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, VaultError};

use super::{
    container::{encrypt_reader, ContainerReader},
    thumbnail::{
        generate_thumbnail, thumbnail_container_id, GeneratedThumbnail, ThumbnailCapture, MAX_SOURCE_BYTES,
    },
};

const SCHEMA_VERSION: i64 = 2;
const CONTAINER_VERSION: i64 = 1;
const THUMBNAIL_MIME: &str = "image/png";
const THUMBNAIL_PENDING: i64 = 0;
const THUMBNAIL_READY: i64 = 1;
const THUMBNAIL_UNAVAILABLE: i64 = 2;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GalleryItem {
    pub id: String,
    pub mime_type: String,
    pub file_size_bytes: u64,
    pub timestamp_added: i64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub thumbnail_available: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GalleryPage {
    pub items: Vec<GalleryItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GalleryObject {
    pub container_id: Uuid,
    pub path: PathBuf,
    pub mime_type: String,
    pub total_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CursorToken {
    timestamp: i64,
    id: String,
}

struct PreparedThumbnail {
    masked_name: String,
    total_size: u64,
    source_width: u32,
    source_height: u32,
}

pub struct GalleryRepository {
    db_path: PathBuf,
    objects_dir: PathBuf,
    thumbnails_dir: PathBuf,
    writer: Mutex<()>,
}

impl GalleryRepository {
    pub fn new(db_path: PathBuf, objects_dir: PathBuf, thumbnails_dir: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&objects_dir)?;
        fs::create_dir_all(&thumbnails_dir)?;
        let repository = Self { db_path, objects_dir, thumbnails_dir, writer: Mutex::new(()) };
        repository.initialize_schema()?;
        repository.recover()?;
        Ok(repository)
    }

    pub fn import_reader<R: Read>(
        &self,
        root_key: &[u8; 32],
        reader: &mut R,
        total_size: u64,
    ) -> Result<String> {
        let _writer = self.writer.lock();
        let id = Uuid::new_v4();
        let masked_name = format!("{id}.enc");
        let partial_path = self.objects_dir.join(format!("{id}.partial"));
        let final_path = self.objects_dir.join(&masked_name);
        let thumbnail_partial_path = self.thumbnails_dir.join(format!("{id}.partial"));
        let thumbnail_final_path = self.thumbnails_dir.join(format!("{id}.enc"));

        let operation = (|| -> Result<String> {
            let mut capture = ThumbnailCapture::new(reader, total_size);
            let metadata =
                encrypt_reader(root_key, id, &mut capture, total_size, &partial_path, &final_path)?;
            let captured_source = capture.finish();
            let source_capture_available = captured_source.is_some();
            verify_container(root_key, id, &final_path, &metadata.mime_type, metadata.total_size)?;

            let prepared_thumbnail = captured_source
                .and_then(|source| generate_thumbnail(source, &metadata.mime_type))
                .map(|generated| {
                    encrypt_generated_thumbnail(
                        root_key,
                        id,
                        generated,
                        &thumbnail_partial_path,
                        &thumbnail_final_path,
                    )
                })
                .transpose()?;

            let timestamp = unix_timestamp()?;
            let mut connection = self.connection()?;
            let transaction = connection.transaction()?;
            let width = prepared_thumbnail.as_ref().map(|thumbnail| i64::from(thumbnail.source_width));
            let height = prepared_thumbnail.as_ref().map(|thumbnail| i64::from(thumbnail.source_height));
            let thumbnail_state = if prepared_thumbnail.is_some() {
                THUMBNAIL_READY
            } else if is_thumbnail_source_mime(&metadata.mime_type)
                && metadata.total_size <= MAX_SOURCE_BYTES
                && !source_capture_available
            {
                THUMBNAIL_PENDING
            } else {
                THUMBNAIL_UNAVAILABLE
            };
            transaction.execute(
                "INSERT INTO media_items (
                    id, masked_name, mime_type, file_size_bytes, timestamp_added,
                    container_version, width, height, duration_ms, thumbnail_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9)",
                params![
                    id.to_string(),
                    &masked_name,
                    &metadata.mime_type,
                    sqlite_integer(metadata.total_size, "media size")?,
                    timestamp,
                    width,
                    height,
                    metadata.duration_ms.map(|value| sqlite_integer(value, "media duration")).transpose()?,
                    thumbnail_state,
                ],
            )?;

            if let Some(thumbnail) = prepared_thumbnail.as_ref() {
                insert_thumbnail_record(&transaction, id, thumbnail)?;
            }
            transaction.commit()?;
            Ok(id.to_string())
        })();

        if operation.is_err() {
            remove_file_if_present(&final_path);
            remove_file_if_present(&thumbnail_final_path);
            remove_file_if_present(&partial_path);
            remove_file_if_present(&thumbnail_partial_path);
        }
        operation
    }

    /// Ensures a legacy JPEG or PNG item has a separately encrypted thumbnail.
    ///
    /// The original container is fully authenticated before its bounded plaintext is passed to
    /// the decoder. Unsupported, oversized, or safely undecodable images return `Ok(false)` and
    /// are represented by a placeholder in the UI.
    pub fn ensure_thumbnail(&self, root_key: &[u8; 32], media_id: Uuid) -> Result<bool> {
        let _writer = self.writer.lock();
        match self.thumbnail_object(media_id) {
            Ok(_) => return Ok(true),
            Err(VaultError::NotFound) => {}
            Err(error) => return Err(error),
        }

        let item = self.get(media_id)?;
        let thumbnail_state = self.thumbnail_state(media_id)?;
        match thumbnail_state {
            THUMBNAIL_UNAVAILABLE => return Ok(false),
            THUMBNAIL_PENDING | THUMBNAIL_READY => {}
            _ => return Err(VaultError::AuthenticationFailed),
        }
        if !is_thumbnail_source_mime(&item.mime_type) || item.file_size_bytes > MAX_SOURCE_BYTES {
            self.mark_thumbnail_unavailable(media_id)?;
            return Ok(false);
        }

        let original_path = self.object_path(media_id)?;
        let mut original = ContainerReader::open(root_key, media_id, &original_path)?;
        if original.metadata().mime_type != item.mime_type
            || original.metadata().total_size != item.file_size_bytes
        {
            return Err(VaultError::AuthenticationFailed);
        }
        let source = original.decrypt_all_bounded(MAX_SOURCE_BYTES)?;
        let Some(generated) = generate_thumbnail(source, &item.mime_type) else {
            self.mark_thumbnail_unavailable(media_id)?;
            return Ok(false);
        };

        let partial_path = self.thumbnails_dir.join(format!("{media_id}.partial"));
        let final_path = self.thumbnails_dir.join(format!("{media_id}.enc"));
        self.remove_stale_thumbnail_record(media_id)?;
        remove_file_if_present(&partial_path);
        if final_path.exists() {
            fs::remove_file(&final_path)?;
        }

        let operation = (|| -> Result<()> {
            let thumbnail =
                encrypt_generated_thumbnail(root_key, media_id, generated, &partial_path, &final_path)?;
            let mut connection = self.connection()?;
            let transaction = connection.transaction()?;
            let updated = transaction.execute(
                "UPDATE media_items
                 SET width = ?1, height = ?2, thumbnail_state = ?3
                 WHERE id = ?4",
                params![
                    i64::from(thumbnail.source_width),
                    i64::from(thumbnail.source_height),
                    THUMBNAIL_READY,
                    media_id.to_string(),
                ],
            )?;
            if updated != 1 {
                return Err(VaultError::NotFound);
            }
            insert_thumbnail_record(&transaction, media_id, &thumbnail)?;
            transaction.commit()?;
            Ok(())
        })();

        if operation.is_err() {
            remove_file_if_present(&final_path);
            remove_file_if_present(&partial_path);
        }
        operation.map(|_| true)
    }

    pub fn page(&self, cursor: Option<&str>, limit: u32) -> Result<GalleryPage> {
        let limit = limit.clamp(1, 500) as usize;
        let cursor = cursor.map(decode_cursor).transpose()?;
        let connection = self.connection()?;
        let mut items = Vec::with_capacity(limit);

        if let Some(cursor) = cursor {
            let mut statement = connection.prepare_cached(
                "SELECT m.id, m.mime_type, m.file_size_bytes, m.timestamp_added,
                        m.width, m.height, m.duration_ms,
                        CASE WHEN t.media_id IS NULL THEN 0 ELSE 1 END
                 FROM media_items m
                 LEFT JOIN media_thumbnails t ON t.media_id = m.id
                 WHERE m.timestamp_added < ?1 OR (m.timestamp_added = ?1 AND m.id < ?2)
                 ORDER BY m.timestamp_added DESC, m.id DESC
                 LIMIT ?3",
            )?;
            let rows = statement.query_map(params![cursor.timestamp, cursor.id, limit as i64], map_item)?;
            for row in rows {
                items.push(row?);
            }
        } else {
            let mut statement = connection.prepare_cached(
                "SELECT m.id, m.mime_type, m.file_size_bytes, m.timestamp_added,
                        m.width, m.height, m.duration_ms,
                        CASE WHEN t.media_id IS NULL THEN 0 ELSE 1 END
                 FROM media_items m
                 LEFT JOIN media_thumbnails t ON t.media_id = m.id
                 ORDER BY m.timestamp_added DESC, m.id DESC
                 LIMIT ?1",
            )?;
            let rows = statement.query_map(params![limit as i64], map_item)?;
            for row in rows {
                items.push(row?);
            }
        }

        let next_cursor = if items.len() == limit {
            items
                .last()
                .map(|item| {
                    encode_cursor(&CursorToken { timestamp: item.timestamp_added, id: item.id.clone() })
                })
                .transpose()?
        } else {
            None
        };
        Ok(GalleryPage { items, next_cursor })
    }

    pub fn get(&self, id: Uuid) -> Result<GalleryItem> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT m.id, m.mime_type, m.file_size_bytes, m.timestamp_added,
                        m.width, m.height, m.duration_ms,
                        CASE WHEN t.media_id IS NULL THEN 0 ELSE 1 END
                 FROM media_items m
                 LEFT JOIN media_thumbnails t ON t.media_id = m.id
                 WHERE m.id = ?1",
                params![id.to_string()],
                map_item,
            )
            .optional()?
            .ok_or(VaultError::NotFound)
    }

    pub fn media_object(&self, id: Uuid) -> Result<GalleryObject> {
        let item = self.get(id)?;
        let path = self.object_path(id)?;
        Ok(GalleryObject {
            container_id: id,
            path,
            mime_type: item.mime_type,
            total_size: item.file_size_bytes,
        })
    }

    pub fn thumbnail_object(&self, media_id: Uuid) -> Result<GalleryObject> {
        let connection = self.connection()?;
        let record = connection
            .query_row(
                "SELECT masked_name, mime_type, file_size_bytes, container_version
                 FROM media_thumbnails WHERE media_id = ?1",
                params![media_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        let expected_name = format!("{media_id}.enc");
        if record.0 != expected_name
            || record.1 != THUMBNAIL_MIME
            || record.2 == 0
            || record.3 != CONTAINER_VERSION
        {
            return Err(VaultError::AuthenticationFailed);
        }
        let path = self.thumbnails_dir.join(record.0);
        if !path.is_file() {
            return Err(VaultError::NotFound);
        }
        Ok(GalleryObject {
            container_id: thumbnail_container_id(media_id),
            path,
            mime_type: record.1,
            total_size: record.2,
        })
    }

    pub fn object_path(&self, id: Uuid) -> Result<PathBuf> {
        let connection = self.connection()?;
        let (masked_name, container_version): (String, i64) = connection
            .query_row(
                "SELECT masked_name, container_version FROM media_items WHERE id = ?1",
                params![id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        if masked_name != format!("{id}.enc") || container_version != CONTAINER_VERSION {
            return Err(VaultError::AuthenticationFailed);
        }
        let path = self.objects_dir.join(masked_name);
        if !path.is_file() {
            return Err(VaultError::NotFound);
        }
        Ok(path)
    }

    fn thumbnail_state(&self, media_id: Uuid) -> Result<i64> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT thumbnail_state FROM media_items WHERE id = ?1",
                params![media_id.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)
    }

    fn remove_stale_thumbnail_record(&self, media_id: Uuid) -> Result<()> {
        let connection = self.connection()?;
        connection
            .execute("DELETE FROM media_thumbnails WHERE media_id = ?1", params![media_id.to_string()])?;
        Ok(())
    }

    fn mark_thumbnail_unavailable(&self, media_id: Uuid) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction
            .execute("DELETE FROM media_thumbnails WHERE media_id = ?1", params![media_id.to_string()])?;
        let updated = transaction.execute(
            "UPDATE media_items SET thumbnail_state = ?1 WHERE id = ?2",
            params![THUMBNAIL_UNAVAILABLE, media_id.to_string()],
        )?;
        if updated != 1 {
            return Err(VaultError::NotFound);
        }
        transaction.commit()?;
        remove_file_if_present(&self.thumbnails_dir.join(format!("{media_id}.enc")));
        Ok(())
    }

    fn initialize_schema(&self) -> Result<()> {
        let mut connection = self.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_info (
                version INTEGER NOT NULL
             );
             INSERT INTO schema_info(version)
             SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_info);

             CREATE TABLE IF NOT EXISTS media_items (
                id TEXT PRIMARY KEY NOT NULL,
                masked_name TEXT NOT NULL UNIQUE,
                mime_type TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL CHECK(file_size_bytes > 0),
                timestamp_added INTEGER NOT NULL,
                container_version INTEGER NOT NULL,
                width INTEGER,
                height INTEGER,
                duration_ms INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_media_added_id
             ON media_items(timestamp_added DESC, id DESC);",
        )?;
        let version: i64 =
            connection.query_row("SELECT version FROM schema_info LIMIT 1", [], |row| row.get(0))?;

        match version {
            1 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(
                    "ALTER TABLE media_items
                     ADD COLUMN thumbnail_state INTEGER NOT NULL DEFAULT 0
                     CHECK(thumbnail_state IN (0, 1, 2));
                     UPDATE media_items
                     SET thumbnail_state = CASE
                         WHEN mime_type IN ('image/jpeg', 'image/png') THEN 0
                         ELSE 2
                     END;",
                )?;
                transaction.execute_batch(thumbnail_schema_sql())?;
                transaction.execute("UPDATE schema_info SET version = ?1", [SCHEMA_VERSION])?;
                transaction.commit()?;
            }
            SCHEMA_VERSION => {
                connection.execute_batch(thumbnail_schema_sql())?;
                drop(connection.prepare("SELECT thumbnail_state FROM media_items LIMIT 0")?);
            }
            _ => {
                return Err(VaultError::Database("unsupported gallery database version".into()));
            }
        }
        Ok(())
    }

    fn recover(&self) -> Result<()> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;

        let mut expected_media = HashSet::new();
        let mut invalid_media = Vec::new();
        {
            let mut statement =
                connection.prepare("SELECT id, masked_name, container_version FROM media_items")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
            })?;
            for row in rows {
                let (id, masked_name, container_version) = row?;
                if canonical_uuid(&id).is_some()
                    && masked_name == format!("{id}.enc")
                    && container_version == CONTAINER_VERSION
                {
                    expected_media.insert(id);
                } else {
                    invalid_media.push(id);
                }
            }
        }
        recover_directory(&self.objects_dir, &expected_media)?;
        for id in expected_media.iter().filter(|id| !self.objects_dir.join(format!("{id}.enc")).is_file()) {
            invalid_media.push(id.clone());
        }
        for id in invalid_media {
            connection.execute("DELETE FROM media_items WHERE id = ?1", params![id])?;
        }

        let valid_media = collect_ids(&connection, "SELECT id FROM media_items")?;
        let mut expected_thumbnails = HashSet::new();
        let mut invalid_thumbnails = Vec::new();
        {
            let mut statement = connection
                .prepare("SELECT media_id, masked_name, container_version FROM media_thumbnails")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
            })?;
            for row in rows {
                let (media_id, masked_name, container_version) = row?;
                if valid_media.contains(&media_id)
                    && canonical_uuid(&media_id).is_some()
                    && masked_name == format!("{media_id}.enc")
                    && container_version == CONTAINER_VERSION
                {
                    expected_thumbnails.insert(media_id);
                } else {
                    invalid_thumbnails.push(media_id);
                }
            }
        }
        recover_directory(&self.thumbnails_dir, &expected_thumbnails)?;
        for media_id in expected_thumbnails
            .iter()
            .filter(|media_id| !self.thumbnails_dir.join(format!("{media_id}.enc")).is_file())
        {
            invalid_thumbnails.push(media_id.clone());
        }
        for media_id in invalid_thumbnails {
            connection.execute("DELETE FROM media_thumbnails WHERE media_id = ?1", params![&media_id])?;
            connection.execute(
                "UPDATE media_items
                 SET thumbnail_state = CASE
                     WHEN mime_type IN ('image/jpeg', 'image/png') THEN ?1
                     ELSE ?2
                 END
                 WHERE id = ?3",
                params![THUMBNAIL_PENDING, THUMBNAIL_UNAVAILABLE, &media_id],
            )?;
        }
        connection.execute(
            "UPDATE media_items SET thumbnail_state = ?1
             WHERE id IN (SELECT media_id FROM media_thumbnails)",
            params![THUMBNAIL_READY],
        )?;
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

fn encrypt_generated_thumbnail(
    root_key: &[u8; 32],
    media_id: Uuid,
    generated: GeneratedThumbnail,
    partial_path: &Path,
    final_path: &Path,
) -> Result<PreparedThumbnail> {
    let thumbnail_id = thumbnail_container_id(media_id);
    let thumbnail_size = u64::try_from(generated.bytes.len())
        .map_err(|_| VaultError::InvalidInput("thumbnail size overflow".into()))?;
    let mut thumbnail_source = Cursor::new(generated.bytes.as_slice());
    let metadata = encrypt_reader(
        root_key,
        thumbnail_id,
        &mut thumbnail_source,
        thumbnail_size,
        partial_path,
        final_path,
    )?;
    if metadata.mime_type != THUMBNAIL_MIME || metadata.total_size != thumbnail_size {
        return Err(VaultError::AuthenticationFailed);
    }
    verify_container(root_key, thumbnail_id, final_path, THUMBNAIL_MIME, thumbnail_size)?;
    Ok(PreparedThumbnail {
        masked_name: format!("{media_id}.enc"),
        total_size: thumbnail_size,
        source_width: generated.source_width,
        source_height: generated.source_height,
    })
}

fn insert_thumbnail_record(
    connection: &Connection,
    media_id: Uuid,
    thumbnail: &PreparedThumbnail,
) -> Result<()> {
    connection.execute(
        "INSERT INTO media_thumbnails (
            media_id, masked_name, mime_type, file_size_bytes, container_version
         ) VALUES (?1, ?2, ?3, ?4, 1)
         ON CONFLICT(media_id) DO UPDATE SET
            masked_name = excluded.masked_name,
            mime_type = excluded.mime_type,
            file_size_bytes = excluded.file_size_bytes,
            container_version = excluded.container_version",
        params![
            media_id.to_string(),
            &thumbnail.masked_name,
            THUMBNAIL_MIME,
            sqlite_integer(thumbnail.total_size, "thumbnail size")?,
        ],
    )?;
    Ok(())
}

fn verify_container(
    root_key: &[u8; 32],
    id: Uuid,
    path: &Path,
    expected_mime: &str,
    expected_size: u64,
) -> Result<()> {
    let mut verified = ContainerReader::open(root_key, id, path)?;
    verified.verify_all()?;
    if verified.metadata().mime_type != expected_mime || verified.metadata().total_size != expected_size {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(())
}

fn is_thumbnail_source_mime(mime_type: &str) -> bool {
    matches!(mime_type, "image/jpeg" | "image/png")
}

fn sqlite_integer(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| VaultError::InvalidInput(format!("{label} exceeds SQLite integer range")))
}

fn remove_file_if_present(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {}
    }
}

fn thumbnail_schema_sql() -> &'static str {
    "CREATE TABLE IF NOT EXISTS media_thumbnails (
        media_id TEXT PRIMARY KEY NOT NULL,
        masked_name TEXT NOT NULL UNIQUE,
        mime_type TEXT NOT NULL CHECK(mime_type = 'image/png'),
        file_size_bytes INTEGER NOT NULL CHECK(file_size_bytes > 0),
        container_version INTEGER NOT NULL CHECK(container_version = 1),
        FOREIGN KEY(media_id) REFERENCES media_items(id) ON DELETE CASCADE
     );"
}

fn recover_directory(directory: &Path, expected_ids: &HashSet<String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
        let stem = path.file_stem().and_then(|value| value.to_str()).unwrap_or_default();
        match extension {
            "partial" => remove_file_if_present(&path),
            "deleting" => {
                if expected_ids.contains(stem) {
                    let restored = directory.join(format!("{stem}.enc"));
                    if restored.exists() {
                        remove_file_if_present(&path);
                    } else {
                        let _ = fs::rename(path, restored);
                    }
                } else {
                    remove_file_if_present(&path);
                }
            }
            "enc" if !expected_ids.contains(stem) => remove_file_if_present(&path),
            _ => {}
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

fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value).ok().filter(|parsed| parsed.to_string() == value)
}

fn map_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<GalleryItem> {
    Ok(GalleryItem {
        id: row.get(0)?,
        mime_type: row.get(1)?,
        file_size_bytes: row.get(2)?,
        timestamp_added: row.get(3)?,
        width: row.get(4)?,
        height: row.get(5)?,
        duration_ms: row.get(6)?,
        thumbnail_available: row.get::<_, bool>(7)?,
    })
}

fn encode_cursor(cursor: &CursorToken) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

fn decode_cursor(value: &str) -> Result<CursorToken> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| VaultError::InvalidInput("invalid gallery cursor".into()))?;
    serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidInput("invalid gallery cursor".into()))
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
    use image::{DynamicImage, ImageFormat, ImageReader};

    #[test]
    fn cursor_round_trip() {
        let cursor = CursorToken { timestamp: 123, id: Uuid::new_v4().to_string() };
        let encoded = encode_cursor(&cursor).unwrap();
        let decoded = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.timestamp, cursor.timestamp);
        assert_eq!(decoded.id, cursor.id);
    }

    #[test]
    fn image_import_creates_authenticated_thumbnail_and_dimensions() {
        let directory = tempfile::tempdir().unwrap();
        let repository = test_repository(directory.path());
        let root_key = [17_u8; 32];
        let mut source = Cursor::new(png_bytes(640, 360));
        let source_size = source.get_ref().len() as u64;

        let id = repository.import_reader(&root_key, &mut source, source_size).unwrap();
        let id = Uuid::parse_str(&id).unwrap();
        let item = repository.get(id).unwrap();
        assert!(item.thumbnail_available);
        assert_eq!(item.width, Some(640));
        assert_eq!(item.height, Some(360));

        assert_thumbnail_dimensions(&repository, &root_key, id, (512, 288));
    }

    #[test]
    fn missing_legacy_thumbnail_is_backfilled_from_authenticated_original() {
        let directory = tempfile::tempdir().unwrap();
        let repository = test_repository(directory.path());
        let root_key = [29_u8; 32];
        let mut source = Cursor::new(png_bytes(320, 200));
        let source_size = source.get_ref().len() as u64;
        let id =
            Uuid::parse_str(&repository.import_reader(&root_key, &mut source, source_size).unwrap()).unwrap();

        repository
            .connection()
            .unwrap()
            .execute("DELETE FROM media_thumbnails WHERE media_id = ?1", params![id.to_string()])
            .unwrap();
        fs::remove_file(repository.thumbnails_dir.join(format!("{id}.enc"))).unwrap();
        repository
            .connection()
            .unwrap()
            .execute(
                "UPDATE media_items SET width = NULL, height = NULL WHERE id = ?1",
                params![id.to_string()],
            )
            .unwrap();

        assert!(repository.ensure_thumbnail(&root_key, id).unwrap());
        let item = repository.get(id).unwrap();
        assert!(item.thumbnail_available);
        assert_eq!(item.width, Some(320));
        assert_eq!(item.height, Some(200));
        assert_thumbnail_dimensions(&repository, &root_key, id, (320, 200));
    }

    #[test]
    fn video_import_never_creates_an_image_thumbnail() {
        let directory = tempfile::tempdir().unwrap();
        let repository = test_repository(directory.path());
        let root_key = [41_u8; 32];
        let mut source = Cursor::new(mp4_bytes());
        let source_size = source.get_ref().len() as u64;
        let id =
            Uuid::parse_str(&repository.import_reader(&root_key, &mut source, source_size).unwrap()).unwrap();

        assert!(!repository.get(id).unwrap().thumbnail_available);
        assert!(!repository.ensure_thumbnail(&root_key, id).unwrap());
        assert!(matches!(repository.thumbnail_object(id), Err(VaultError::NotFound)));
    }

    #[test]
    fn undecodable_image_is_persistently_marked_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let repository = test_repository(directory.path());
        let root_key = [53_u8; 32];
        let mut source = Cursor::new(invalid_png_bytes());
        let source_size = source.get_ref().len() as u64;
        let id =
            Uuid::parse_str(&repository.import_reader(&root_key, &mut source, source_size).unwrap()).unwrap();

        assert_eq!(repository.thumbnail_state(id).unwrap(), THUMBNAIL_UNAVAILABLE);
        assert!(!repository.ensure_thumbnail(&root_key, id).unwrap());
    }

    #[test]
    fn schema_version_one_migrates_without_touching_existing_media_rows() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("gallery.sqlite3");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_info (version INTEGER NOT NULL);
                 INSERT INTO schema_info(version) VALUES (1);
                 CREATE TABLE media_items (
                    id TEXT PRIMARY KEY NOT NULL,
                    masked_name TEXT NOT NULL UNIQUE,
                    mime_type TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL CHECK(file_size_bytes > 0),
                    timestamp_added INTEGER NOT NULL,
                    container_version INTEGER NOT NULL,
                    width INTEGER,
                    height INTEGER,
                    duration_ms INTEGER
                 );
                 CREATE INDEX idx_media_added_id
                 ON media_items(timestamp_added DESC, id DESC);",
            )
            .unwrap();
        drop(connection);

        let repository = GalleryRepository::new(
            db_path.clone(),
            directory.path().join("objects"),
            directory.path().join("thumbnails"),
        )
        .unwrap();
        drop(repository);

        let connection = Connection::open(db_path).unwrap();
        let version: i64 =
            connection.query_row("SELECT version FROM schema_info", [], |row| row.get(0)).unwrap();
        let thumbnail_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'media_thumbnails'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection.prepare("SELECT thumbnail_state FROM media_items LIMIT 0").unwrap());
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(thumbnail_table, 1);
    }

    fn test_repository(root: &Path) -> GalleryRepository {
        GalleryRepository::new(root.join("gallery.sqlite3"), root.join("objects"), root.join("thumbnails"))
            .unwrap()
    }

    fn assert_thumbnail_dimensions(
        repository: &GalleryRepository,
        root_key: &[u8; 32],
        id: Uuid,
        expected: (u32, u32),
    ) {
        let object = repository.thumbnail_object(id).unwrap();
        assert_eq!(object.container_id, thumbnail_container_id(id));
        assert_eq!(object.mime_type, THUMBNAIL_MIME);
        let mut reader = ContainerReader::open(root_key, object.container_id, &object.path).unwrap();
        reader.verify_all().unwrap();
        let bytes = reader.decrypt_range(0, object.total_size - 1, object.total_size).unwrap();
        let dimensions =
            ImageReader::with_format(Cursor::new(bytes), ImageFormat::Png).into_dimensions().unwrap();
        assert_eq!(dimensions, expected);
    }

    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let image = DynamicImage::new_rgb8(width, height);
        let mut encoded = Cursor::new(Vec::new());
        image.write_to(&mut encoded, ImageFormat::Png).unwrap();
        encoded.into_inner()
    }

    fn invalid_png_bytes() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[..8].copy_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        bytes
    }

    fn mp4_bytes() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[0..4].copy_from_slice(&24_u32.to_be_bytes());
        bytes[4..8].copy_from_slice(b"ftyp");
        bytes[8..12].copy_from_slice(b"isom");
        bytes
    }
}
