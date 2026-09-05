use std::{fs, path::Path};

use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::error::{Result, VaultError};

const TRASH_VARIANTS: [&str; 4] = ["trash", "trashing", "restoring", "purging"];

/// Reconciles journaled gallery transitions before `GalleryRepository` performs its own startup
/// cleanup. This prevents an interrupted Trash/restore operation from being mistaken for an
/// orphaned active record and discarded before the Trash journal can repair it.
pub fn prepare_trash_recovery(
    db_path: &Path,
    objects_dir: &Path,
    thumbnails_dir: &Path,
) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(objects_dir)?;
    fs::create_dir_all(thumbnails_dir)?;

    let connection = open_connection(db_path)?;
    initialize_trash_schema(&connection)?;
    if !table_exists(&connection, "media_items")? {
        return Ok(());
    }

    let mut statement =
        connection.prepare("SELECT id FROM media_trash ORDER BY deleted_at DESC, id DESC")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let ids = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);

    for id in ids {
        let Some(parsed) = canonical_uuid(&id) else {
            continue;
        };
        let active_exists: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM media_items WHERE id = ?1)",
            params![&id],
            |row| row.get(0),
        )?;
        if active_exists == 0 {
            continue;
        }

        if !reconcile_to_active(objects_dir, parsed, true)? {
            // Preserve the journal evidence. GalleryRepository will treat the missing active object
            // as invalid, after which GalleryTrash can still surface the authenticated Trash row.
            continue;
        }
        let _ = reconcile_to_active(thumbnails_dir, parsed, false)?;
        connection.execute("DELETE FROM media_trash WHERE id = ?1", params![&id])?;
    }
    Ok(())
}

fn reconcile_to_active(directory: &Path, id: Uuid, required: bool) -> Result<bool> {
    let active = directory.join(format!("{id}.enc"));
    let transition = find_transition_variant(directory, id)?;
    match (active.is_file(), transition) {
        (true, None) => Ok(true),
        (false, Some(source)) => {
            fs::rename(source, active)?;
            Ok(true)
        }
        (false, None) => Ok(!required),
        (true, Some(_)) => Err(VaultError::AuthenticationFailed),
    }
}

fn find_transition_variant(directory: &Path, id: Uuid) -> Result<Option<std::path::PathBuf>> {
    let mut found = None;
    for extension in TRASH_VARIANTS {
        let path = directory.join(format!("{id}.{extension}"));
        if !path.is_file() {
            continue;
        }
        if found.is_some() {
            return Err(VaultError::AuthenticationFailed);
        }
        found = Some(path);
    }
    Ok(found)
}

fn table_exists(connection: &Connection, name: &str) -> Result<bool> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![name],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

fn initialize_trash_schema(connection: &Connection) -> Result<()> {
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

fn open_connection(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(connection)
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gallery::GalleryRepository;
    use image::{DynamicImage, ImageFormat};
    use std::io::Cursor;

    #[test]
    fn prepares_new_gallery_database_without_active_schema() {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("gallery.sqlite3");
        let objects = directory.path().join("objects");
        let thumbnails = directory.path().join("thumbnails");

        prepare_trash_recovery(&db, &objects, &thumbnails).unwrap();

        let connection = Connection::open(db).unwrap();
        assert!(table_exists(&connection, "media_trash").unwrap());
        assert!(!table_exists(&connection, "media_items").unwrap());
    }

    #[test]
    fn restores_journaled_active_object_before_gallery_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("gallery.sqlite3");
        let objects = directory.path().join("objects");
        let thumbnails = directory.path().join("thumbnails");
        let repository =
            GalleryRepository::new(db.clone(), objects.clone(), thumbnails.clone()).unwrap();
        prepare_trash_recovery(&db, &objects, &thumbnails).unwrap();

        let key = [97_u8; 32];
        let id = import_png(&repository, &key);
        let connection = Connection::open(&db).unwrap();
        connection
            .execute(
                "INSERT INTO media_trash (id, nonce, ciphertext, deleted_at, format_version)
                 VALUES (?1, ?2, ?3, 1, 1)",
                params![id.to_string(), [7_u8; 12].as_slice(), vec![9_u8; 32]],
            )
            .unwrap();
        drop(connection);

        let active = objects.join(format!("{id}.enc"));
        let interrupted = objects.join(format!("{id}.trashing"));
        fs::rename(&active, &interrupted).unwrap();
        drop(repository);

        prepare_trash_recovery(&db, &objects, &thumbnails).unwrap();
        let recovered =
            GalleryRepository::new(db.clone(), objects.clone(), thumbnails.clone()).unwrap();
        assert_eq!(recovered.get(id).unwrap().id, id.to_string());
        assert!(recovered.thumbnail_object(id).is_ok());
        let connection = Connection::open(db).unwrap();
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM media_trash WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    fn import_png(repository: &GalleryRepository, key: &[u8; 32]) -> Uuid {
        let image = DynamicImage::new_rgb8(64, 40);
        let mut encoded = Cursor::new(Vec::new());
        image.write_to(&mut encoded, ImageFormat::Png).unwrap();
        let bytes = encoded.into_inner();
        let mut source = Cursor::new(bytes.as_slice());
        let id = repository
            .import_reader(key, &mut source, bytes.len() as u64)
            .unwrap();
        Uuid::parse_str(&id).unwrap()
    }
}
