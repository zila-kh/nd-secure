use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub header: PathBuf,
    pub gallery_objects: PathBuf,
    pub gallery_thumbnails: PathBuf,
    pub gallery_db: PathBuf,
    pub credentials_root: PathBuf,
    pub credentials_db: PathBuf,
    pub projects_root: PathBuf,
    pub projects_db: PathBuf,
}

impl VaultPaths {
    pub fn new(app_local_data: &Path) -> Self {
        let root = app_local_data.join("vault");
        let gallery_root = root.join("gallery");
        let credentials_root = root.join("credentials");
        let projects_root = root.join("projects");
        Self {
            header: root.join("vault-header.json"),
            gallery_objects: gallery_root.join("objects"),
            gallery_thumbnails: gallery_root.join("thumbnails"),
            gallery_db: gallery_root.join("gallery.sqlite3"),
            credentials_db: credentials_root.join("credentials.sqlite3"),
            projects_db: projects_root.join("projects.sqlite3"),
            credentials_root,
            projects_root,
        }
    }

    pub fn create_all(&self) -> Result<()> {
        fs::create_dir_all(&self.gallery_objects)?;
        fs::create_dir_all(&self.gallery_thumbnails)?;
        fs::create_dir_all(&self.credentials_root)?;
        fs::create_dir_all(&self.projects_root)?;

        if let Some(root) = self.header.parent() {
            restrict_directory(root)?;
        }
        if let Some(gallery_root) = self.gallery_objects.parent() {
            restrict_directory(gallery_root)?;
        }
        restrict_directory(&self.gallery_objects)?;
        restrict_directory(&self.gallery_thumbnails)?;
        restrict_directory(&self.credentials_root)?;
        restrict_directory(&self.projects_root)?;
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}
