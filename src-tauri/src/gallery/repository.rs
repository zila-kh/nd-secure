use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, VaultError};

use super::container::{encrypt_reader, ContainerReader};

const SCHEMA_VERSION: i64 = 1;

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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GalleryPage {
    pub items: Vec<GalleryItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cursor {
    timestamp: i64,
    id: String,
}

pub struct GalleryRepository {
    db_path: PathBuf,
    objects_dir: PathBuf,
    writer: Mutex<()>,
}

impl GalleryRepository {
    pub fn new(db_path: PathBuf, objects_dir: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&objects_dir)?;
        let repository = Self {
            db_path,
            objects_dir,
            writer: Mutex::new(()),
        };
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
        let metadata = encrypt_reader(root_key, id, reader, total_size, &partial_path, &final_path)?;

        let verification = (|| -> Result<()> {
            let mut verified = ContainerReader::open(root_key, id, &final_path)?;
            verified.verify_all()?;
            if verified.metadata().mime_type != metadata.mime_type
                || verified.metadata().total_size != metadata.total_size
            {
                return Err(VaultError::AuthenticationFailed);
            }
            Ok(())
        })();
        if let Err(error) = verification {
            let _ = fs::remove_file(&final_path);
            return Err(error);
        }

        let timestamp = unix_timestamp()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let insert_result = transaction.execute(
            "INSERT INTO media_items (
                id, masked_name, mime_type, file_size_bytes, timestamp_added,
                container_version, width, height, duration_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8)",
            params![
                id.to_string(),
                masked_name,
                metadata.mime_type,
                i64::try_from(metadata.total_size)
                    .map_err(|_| VaultError::InvalidInput("media size exceeds SQLite integer range".into()))?,
                timestamp,
                metadata.width.map(i64::from),
                metadata.height.map(i64::from),
                metadata.duration_ms.and_then(|value| i64::try_from(value).ok()),
            ],
        );
        if let Err(error) = insert_result {
            let _ = fs::remove_file(&final_path);
            return Err(error.into());
        }
        if let Err(error) = transaction.commit() {
            let _ = fs::remove_file(&final_path);
            return Err(error.into());
        }
        Ok(id.to_string())
    }

    pub fn page(&self, cursor: Option<&str>, limit: u32) -> Result<GalleryPage> {
        let limit = limit.clamp(1, 500) as usize;
        let cursor = cursor.map(decode_cursor).transpose()?;
        let connection = self.connection()?;
        let mut items = Vec::with_capacity(limit);

        if let Some(cursor) = cursor {
            let mut statement = connection.prepare_cached(
                "SELECT id, mime_type, file_size_bytes, timestamp_added, width, height, duration_ms
                 FROM media_items
                 WHERE timestamp_added < ?1 OR (timestamp_added = ?1 AND id < ?2)
                 ORDER BY timestamp_added DESC, id DESC
                 LIMIT ?3",
            )?;
            let rows = statement.query_map(params![cursor.timestamp, cursor.id, limit as i64], map_item)?;
            for row in rows {
                items.push(row?);
            }
        } else {
            let mut statement = connection.prepare_cached(
                "SELECT id, mime_type, file_size_bytes, timestamp_added, width, height, duration_ms
                 FROM media_items
                 ORDER BY timestamp_added DESC, id DESC
                 LIMIT ?1",
            )?;
            let rows = statement.query_map(params![limit as i64], map_item)?;
            for row in rows {
                items.push(row?);
            }
        }

        let next_cursor = if items.len() == limit {
            items.last().map(|item| {
                encode_cursor(&Cursor {
                    timestamp: item.timestamp_added,
                    id: item.id.clone(),
                })
            }).transpose()?
        } else {
            None
        };
        Ok(GalleryPage { items, next_cursor })
    }

    pub fn get(&self, id: Uuid) -> Result<GalleryItem> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, mime_type, file_size_bytes, timestamp_added, width, height, duration_ms
                 FROM media_items WHERE id = ?1",
                params![id.to_string()],
                map_item,
            )
            .optional()?
            .ok_or(VaultError::NotFound)
    }

    pub fn object_path(&self, id: Uuid) -> Result<PathBuf> {
        let connection = self.connection()?;
        let masked_name: String = connection
            .query_row(
                "SELECT masked_name FROM media_items WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        if masked_name != format!("{id}.enc") {
            return Err(VaultError::AuthenticationFailed);
        }
        let path = self.objects_dir.join(masked_name);
        if !path.is_file() {
            return Err(VaultError::NotFound);
        }
        Ok(path)
    }

    pub fn delete(&self, id: Uuid) -> Result<()> {
        let _writer = self.writer.lock();
        let path = self.object_path(id)?;
        let deleting = self.objects_dir.join(format!("{id}.deleting"));
        fs::rename(&path, &deleting)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let result = transaction.execute("DELETE FROM media_items WHERE id = ?1", params![id.to_string()]);
        match result {
            Ok(1) => {
                if let Err(error) = transaction.commit() {
                    let _ = fs::rename(&deleting, &path);
                    return Err(error.into());
                }
                fs::remove_file(deleting)?;
                Ok(())
            }
            Ok(_) => {
                let _ = fs::rename(&deleting, &path);
                Err(VaultError::NotFound)
            }
            Err(error) => {
                let _ = fs::rename(&deleting, &path);
                Err(error.into())
            }
        }
    }

    fn initialize_schema(&self) -> Result<()> {
        let connection = self.connection()?;
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
        let version: i64 = connection.query_row("SELECT version FROM schema_info LIMIT 1", [], |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(VaultError::Database("unsupported gallery database version".into()));
        }
        Ok(())
    }

    fn recover(&self) -> Result<()> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let mut ids = HashSet::new();
        let mut statement = connection.prepare("SELECT id FROM media_items")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            ids.insert(row?);
        }
        drop(statement);

        for entry in fs::read_dir(&self.objects_dir)? {
            let entry = entry?;
            let path = entry.path();
            let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
            let stem = path.file_stem().and_then(|value| value.to_str()).unwrap_or_default();
            match extension {
                "partial" => {
                    let _ = fs::remove_file(path);
                }
                "deleting" => {
                    if ids.contains(stem) {
                        let restored = self.objects_dir.join(format!("{stem}.enc"));
                        let _ = fs::rename(path, restored);
                    } else {
                        let _ = fs::remove_file(path);
                    }
                }
                "enc" if !ids.contains(stem) => {
                    let _ = fs::remove_file(path);
                }
                _ => {}
            }
        }

        let mut missing = Vec::new();
        for id in ids {
            let canonical = Uuid::parse_str(&id)
                .ok()
                .filter(|parsed| parsed.to_string() == id);
            if canonical.is_none() || !self.objects_dir.join(format!("{id}.enc")).is_file() {
                missing.push(id);
            }
        }
        for id in missing {
            connection.execute("DELETE FROM media_items WHERE id = ?1", params![id])?;
        }
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

fn map_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<GalleryItem> {
    let file_size: i64 = row.get(2)?;
    let width: Option<i64> = row.get(4)?;
    let height: Option<i64> = row.get(5)?;
    let duration: Option<i64> = row.get(6)?;
    Ok(GalleryItem {
        id: row.get(0)?,
        mime_type: row.get(1)?,
        file_size_bytes: u64::try_from(file_size).unwrap_or_default(),
        timestamp_added: row.get(3)?,
        width: width.and_then(|value| u32::try_from(value).ok()),
        height: height.and_then(|value| u32::try_from(value).ok()),
        duration_ms: duration.and_then(|value| u64::try_from(value).ok()),
    })
}

fn encode_cursor(cursor: &Cursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

fn decode_cursor(value: &str) -> Result<Cursor> {
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

    #[test]
    fn cursor_round_trip() {
        let cursor = Cursor {
            timestamp: 123,
            id: Uuid::new_v4().to_string(),
        };
        let encoded = encode_cursor(&cursor).unwrap();
        let decoded = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.timestamp, cursor.timestamp);
        assert_eq!(decoded.id, cursor.id);
    }
}
