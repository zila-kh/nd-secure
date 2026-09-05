use std::{
    collections::HashSet,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::Connection;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    credentials::CredentialRepository,
    error::{Result, VaultError},
    gallery::{ContainerReader, GalleryRepository, GalleryTrash},
    paths::VaultPaths,
};

const PAGE_SIZE: u32 = 200;
const MAX_REPORTED_ISSUES: usize = 50;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultHealthIssue {
    pub area: String,
    pub id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultHealthReport {
    pub healthy: bool,
    pub checked_at: i64,
    pub gallery_items: u64,
    pub gallery_trash_items: u64,
    pub credential_items: u64,
    pub credential_trash_items: u64,
    pub verified_media_bytes: u64,
    pub total_issues: u64,
    pub issues: Vec<VaultHealthIssue>,
}

struct HealthAccumulator {
    gallery_items: u64,
    gallery_trash_items: u64,
    credential_items: u64,
    credential_trash_items: u64,
    verified_media_bytes: u64,
    total_issues: u64,
    issues: Vec<VaultHealthIssue>,
}

impl HealthAccumulator {
    fn new() -> Self {
        Self {
            gallery_items: 0,
            gallery_trash_items: 0,
            credential_items: 0,
            credential_trash_items: 0,
            verified_media_bytes: 0,
            total_issues: 0,
            issues: Vec::new(),
        }
    }

    fn issue(&mut self, area: &str, id: Option<String>, message: &str) {
        self.total_issues = self.total_issues.saturating_add(1);
        if self.issues.len() < MAX_REPORTED_ISSUES {
            self.issues.push(VaultHealthIssue {
                area: area.to_owned(),
                id,
                message: message.to_owned(),
            });
        }
    }

    fn report(self) -> Result<VaultHealthReport> {
        let checked_at = unix_timestamp()?;
        Ok(VaultHealthReport {
            healthy: self.total_issues == 0,
            checked_at,
            gallery_items: self.gallery_items,
            gallery_trash_items: self.gallery_trash_items,
            credential_items: self.credential_items,
            credential_trash_items: self.credential_trash_items,
            verified_media_bytes: self.verified_media_bytes,
            total_issues: self.total_issues,
            issues: self.issues,
        })
    }
}

pub fn check_vault(
    paths: &VaultPaths,
    gallery: &GalleryRepository,
    gallery_trash: &GalleryTrash,
    credentials: &CredentialRepository,
    gallery_key: &[u8; 32],
    credential_key: &[u8; 32],
) -> Result<VaultHealthReport> {
    let mut health = HealthAccumulator::new();

    check_sqlite(&paths.gallery_db, "gallery database", &mut health);
    check_sqlite(&paths.credentials_db, "credential database", &mut health);
    check_gallery(gallery, gallery_key, &mut health);
    check_gallery_trash(gallery_trash, gallery_key, &mut health);
    check_credentials(credentials, credential_key, false, &mut health);
    check_credentials(credentials, credential_key, true, &mut health);

    health.report()
}

fn check_sqlite(path: &Path, area: &str, health: &mut HealthAccumulator) {
    let result = (|| -> Result<bool> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        Ok(quick_check == "ok")
    })();

    match result {
        Ok(true) => {}
        Ok(false) => health.issue(area, None, "SQLite structural integrity check failed"),
        Err(_) => health.issue(area, None, "Unable to complete SQLite structural integrity check"),
    }
}

fn check_gallery(gallery: &GalleryRepository, gallery_key: &[u8; 32], health: &mut HealthAccumulator) {
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();

    loop {
        let page = match gallery.page(cursor.as_deref(), PAGE_SIZE) {
            Ok(page) => page,
            Err(_) => {
                health.issue("gallery", None, "Unable to enumerate the encrypted gallery index");
                break;
            }
        };

        for item in page.items {
            health.gallery_items = health.gallery_items.saturating_add(1);
            let id = match canonical_uuid(&item.id) {
                Ok(id) => id,
                Err(_) => {
                    health.issue("gallery", Some(item.id), "Gallery index contains an invalid item identifier");
                    continue;
                }
            };
            match gallery.media_object(id).and_then(|object| {
                let mut reader = ContainerReader::open(gallery_key, object.container_id, &object.path)?;
                reader.verify_all()?;
                if reader.metadata().mime_type != object.mime_type
                    || reader.metadata().total_size != object.total_size
                {
                    return Err(VaultError::AuthenticationFailed);
                }
                Ok(object.total_size)
            }) {
                Ok(bytes) => {
                    health.verified_media_bytes = health.verified_media_bytes.saturating_add(bytes);
                }
                Err(_) => health.issue(
                    "gallery media",
                    Some(item.id.clone()),
                    "Encrypted media container failed authentication or could not be read",
                ),
            }

            if item.thumbnail_available {
                match gallery.thumbnail_object(id).and_then(|object| {
                    let mut reader = ContainerReader::open(gallery_key, object.container_id, &object.path)?;
                    reader.verify_all()?;
                    if reader.metadata().mime_type != object.mime_type
                        || reader.metadata().total_size != object.total_size
                    {
                        return Err(VaultError::AuthenticationFailed);
                    }
                    Ok(object.total_size)
                }) {
                    Ok(bytes) => {
                        health.verified_media_bytes = health.verified_media_bytes.saturating_add(bytes);
                    }
                    Err(_) => health.issue(
                        "gallery thumbnail",
                        Some(item.id),
                        "Encrypted thumbnail failed authentication or could not be read",
                    ),
                }
            }
        }

        let Some(next) = page.next_cursor else {
            break;
        };
        if !seen_cursors.insert(next.clone()) {
            health.issue("gallery", None, "Gallery pagination cursor repeated unexpectedly");
            break;
        }
        cursor = Some(next);
    }
}

fn check_gallery_trash(
    gallery_trash: &GalleryTrash,
    gallery_key: &[u8; 32],
    health: &mut HealthAccumulator,
) {
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();

    loop {
        let page = match gallery_trash.page(gallery_key, cursor.as_deref(), PAGE_SIZE) {
            Ok(page) => page,
            Err(_) => {
                health.issue("gallery trash", None, "Unable to authenticate the encrypted media Trash index");
                break;
            }
        };

        for item in page.items {
            health.gallery_trash_items = health.gallery_trash_items.saturating_add(1);
            let id = match canonical_uuid(&item.id) {
                Ok(id) => id,
                Err(_) => {
                    health.issue(
                        "gallery trash",
                        Some(item.id),
                        "Media Trash contains an invalid item identifier",
                    );
                    continue;
                }
            };
            match gallery_trash.verify_item(gallery_key, id) {
                Ok(bytes) => {
                    health.verified_media_bytes = health.verified_media_bytes.saturating_add(bytes);
                }
                Err(_) => health.issue(
                    "gallery trash",
                    Some(item.id),
                    "Trashed encrypted media failed authentication or could not be read",
                ),
            }
        }

        let Some(next) = page.next_cursor else {
            break;
        };
        if !seen_cursors.insert(next.clone()) {
            health.issue("gallery trash", None, "Media Trash pagination cursor repeated unexpectedly");
            break;
        }
        cursor = Some(next);
    }
}

fn check_credentials(
    credentials: &CredentialRepository,
    credential_key: &[u8; 32],
    trash: bool,
    health: &mut HealthAccumulator,
) {
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();
    let area = if trash { "credential trash" } else { "credentials" };

    loop {
        let page = if trash {
            credentials.trash_page(credential_key, cursor.as_deref(), PAGE_SIZE)
        } else {
            credentials.page(credential_key, cursor.as_deref(), PAGE_SIZE, "", None, None)
        };
        let page = match page {
            Ok(page) => page,
            Err(_) => {
                health.issue(area, None, "Encrypted credential records failed authentication or could not be read");
                break;
            }
        };

        let count = u64::try_from(page.items.len()).unwrap_or(u64::MAX);
        if trash {
            health.credential_trash_items = health.credential_trash_items.saturating_add(count);
        } else {
            health.credential_items = health.credential_items.saturating_add(count);
        }

        let Some(next) = page.next_cursor else {
            break;
        };
        if !seen_cursors.insert(next.clone()) {
            health.issue(area, None, "Credential pagination cursor repeated unexpectedly");
            break;
        }
        cursor = Some(next);
    }
}

fn canonical_uuid(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| VaultError::AuthenticationFailed)?;
    if id.to_string() != value {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(id)
}

fn unix_timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Platform("system clock is before UNIX epoch".into()))?;
    i64::try_from(duration.as_secs()).map_err(|_| VaultError::Platform("system clock overflow".into()))
}
