use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::{derive_object_key, random_array},
    error::{Result, VaultError},
};

use super::{
    env::{
        ensure_gitignore, inspect_project_root, validate_environments, validate_project_name,
        write_project_manifest,
    },
    ProjectInspection, ProjectRegistration, FORMAT_VERSION, MAX_ENVIRONMENTS, MAX_KEYS,
    REGISTRY_AAD_PREFIX, REGISTRY_CONTEXT,
};

struct EncryptedProjectRow {
    id: Uuid,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    format_version: i64,
    revision: i64,
    created_at: i64,
    updated_at: i64,
}

pub struct ProjectRepository {
    db_path: PathBuf,
    writer: Mutex<()>,
}

impl ProjectRepository {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let repository = Self { db_path, writer: Mutex::new(()) };
        repository.initialize_schema()?;
        Ok(repository)
    }

    pub fn inspect(&self, root: &str) -> Result<ProjectInspection> {
        inspect_project_root(root)
    }

    pub fn register(
        &self,
        root_key: &[u8; 32],
        root: String,
        name: String,
        environments: Vec<String>,
    ) -> Result<ProjectRegistration> {
        let inspection = inspect_project_root(&root)?;
        let name = validate_project_name(&name)?;
        let environments = validate_environments(environments)?;
        let now = unix_timestamp()?;
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let existing = self.find_by_root_with_connection(root_key, &connection, &inspection.root)?;
        let (id, created_at, revision) = match existing {
            Some((registration, row_revision)) => (
                parse_uuid(&registration.id)?,
                registration.created_at,
                row_revision.saturating_add(1),
            ),
            None => (Uuid::new_v4(), now, 1),
        };
        let registration = ProjectRegistration {
            id: id.to_string(),
            name,
            root: inspection.root,
            environments,
            required_keys: inspection.required_keys,
            created_at,
            updated_at: now,
        };
        self.write_registration(&connection, root_key, &registration, revision)?;
        write_project_manifest(&registration)?;
        ensure_gitignore(&registration.root)?;
        Ok(registration)
    }

    pub fn list(&self, root_key: &[u8; 32]) -> Result<Vec<ProjectRegistration>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, record_salt, nonce, ciphertext, format_version, revision, created_at, updated_at
             FROM project_registrations ORDER BY updated_at DESC, id DESC",
        )?;
        let rows = statement.query_map([], map_project_row)?;
        let mut registrations = Vec::new();
        for row in rows {
            registrations.push(decrypt_project_row(root_key, &row?)?);
        }
        Ok(registrations)
    }

    pub fn detail(&self, root_key: &[u8; 32], id: Uuid) -> Result<ProjectRegistration> {
        let connection = self.connection()?;
        let row = encrypted_project_row(&connection, id)?;
        decrypt_project_row(root_key, &row)
    }

    pub fn sync(&self, root_key: &[u8; 32], id: Uuid) -> Result<ProjectRegistration> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let row = encrypted_project_row(&connection, id)?;
        let mut registration = decrypt_project_row(root_key, &row)?;
        let inspection = inspect_project_root(&registration.root)?;
        registration.root = inspection.root;
        registration.required_keys = inspection.required_keys;
        registration.updated_at = unix_timestamp()?;
        self.write_registration(&connection, root_key, &registration, row.revision.saturating_add(1))?;
        write_project_manifest(&registration)?;
        ensure_gitignore(&registration.root)?;
        Ok(registration)
    }

    pub fn delete(&self, id: Uuid) -> Result<()> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let changed = connection.execute(
            "DELETE FROM project_registrations WHERE id = ?1",
            params![id.to_string()],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    fn write_registration(
        &self,
        connection: &Connection,
        root_key: &[u8; 32],
        registration: &ProjectRegistration,
        revision: i64,
    ) -> Result<()> {
        let id = parse_uuid(&registration.id)?;
        let salt = random_array::<16>();
        let nonce = random_array::<12>();
        let key = project_record_key(root_key, &salt, id)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(registration)?);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &project_record_aad(id, revision),
                },
            )
            .map_err(|_| VaultError::Crypto)?;
        connection.execute(
            "INSERT INTO project_registrations (
                id, record_salt, nonce, ciphertext, format_version, revision, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                record_salt = excluded.record_salt,
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext,
                format_version = excluded.format_version,
                revision = excluded.revision,
                updated_at = excluded.updated_at",
            params![
                registration.id.as_str(),
                salt.as_slice(),
                nonce.as_slice(),
                ciphertext,
                FORMAT_VERSION,
                revision,
                registration.created_at,
                registration.updated_at,
            ],
        )?;
        Ok(())
    }

    fn find_by_root_with_connection(
        &self,
        root_key: &[u8; 32],
        connection: &Connection,
        root: &str,
    ) -> Result<Option<(ProjectRegistration, i64)>> {
        let mut statement = connection.prepare(
            "SELECT id, record_salt, nonce, ciphertext, format_version, revision, created_at, updated_at
             FROM project_registrations",
        )?;
        let rows = statement.query_map([], map_project_row)?;
        for row in rows {
            let row = row?;
            let registration = decrypt_project_row(root_key, &row)?;
            if registration.root == root {
                return Ok(Some((registration, row.revision)));
            }
        }
        Ok(None)
    }

    fn initialize_schema(&self) -> Result<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS project_registrations (
                id TEXT PRIMARY KEY NOT NULL,
                record_salt BLOB NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                format_version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_project_registrations_updated
             ON project_registrations(updated_at DESC, id DESC);",
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

fn encrypted_project_row(connection: &Connection, id: Uuid) -> Result<EncryptedProjectRow> {
    connection
        .query_row(
            "SELECT id, record_salt, nonce, ciphertext, format_version, revision, created_at, updated_at
             FROM project_registrations WHERE id = ?1",
            params![id.to_string()],
            map_project_row,
        )
        .optional()?
        .ok_or(VaultError::NotFound)
}

fn map_project_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedProjectRow> {
    let id_string: String = row.get(0)?;
    let id = Uuid::parse_str(&id_string).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let salt: Vec<u8> = row.get(1)?;
    let nonce: Vec<u8> = row.get(2)?;
    Ok(EncryptedProjectRow {
        id,
        salt: salt.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        nonce: nonce.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        ciphertext: row.get(3)?,
        format_version: row.get(4)?,
        revision: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn decrypt_project_row(root_key: &[u8; 32], row: &EncryptedProjectRow) -> Result<ProjectRegistration> {
    if row.format_version != FORMAT_VERSION || row.revision <= 0 {
        return Err(VaultError::AuthenticationFailed);
    }
    let key = project_record_key(root_key, &row.salt, row.id)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&row.nonce),
            Payload {
                msg: &row.ciphertext,
                aad: &project_record_aad(row.id, row.revision),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    let registration: ProjectRegistration =
        serde_json::from_slice(plaintext.as_slice()).map_err(|_| VaultError::AuthenticationFailed)?;
    if registration.id != row.id.to_string()
        || registration.created_at != row.created_at
        || registration.updated_at != row.updated_at
        || registration.required_keys.len() > MAX_KEYS
        || registration.environments.len() > MAX_ENVIRONMENTS
    {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(registration)
}

fn project_record_key(root_key: &[u8; 32], salt: &[u8; 16], id: Uuid) -> Result<Zeroizing<[u8; 32]>> {
    let mut context = Vec::with_capacity(REGISTRY_CONTEXT.len() + 16);
    context.extend_from_slice(REGISTRY_CONTEXT);
    context.extend_from_slice(id.as_bytes());
    derive_object_key(root_key, salt, &context)
}

fn project_record_aad(id: Uuid, revision: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(REGISTRY_AAD_PREFIX.len() + 24);
    aad.extend_from_slice(REGISTRY_AAD_PREFIX);
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

fn parse_uuid(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| VaultError::InvalidInput("invalid UUID".into()))?;
    if id.to_string() != value.to_lowercase() {
        return Err(VaultError::InvalidInput("UUID is not canonical".into()));
    }
    Ok(id)
}

fn unix_timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Platform("system clock is before UNIX epoch".into()))?;
    i64::try_from(duration.as_secs()).map_err(|_| VaultError::Platform("system clock overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_registry_encrypts_local_path() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("todo-project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join(".env.example"), "DATABASE_URL=\nAPI_TOKEN=\n").unwrap();
        let repository = ProjectRepository::new(directory.path().join("projects.sqlite3")).unwrap();
        let key = [41_u8; 32];
        let saved = repository
            .register(
                &key,
                project.to_string_lossy().into_owned(),
                "todo".into(),
                vec!["dev".into(), "prod".into()],
            )
            .unwrap();
        assert_eq!(saved.required_keys, vec!["API_TOKEN", "DATABASE_URL"]);
        let bytes = fs::read(directory.path().join("projects.sqlite3")).unwrap();
        assert!(!bytes.windows(b"todo-project".len()).any(|window| window == b"todo-project"));
        assert!(matches!(
            repository.detail(&[42_u8; 32], Uuid::parse_str(&saved.id).unwrap()),
            Err(VaultError::AuthenticationFailed)
        ));
    }
}
