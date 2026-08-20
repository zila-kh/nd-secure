use std::{fs::File, io::Read};

#[cfg(not(target_os = "android"))]
use std::{
    fs::{self, Metadata},
    path::{Path, PathBuf},
    time::SystemTime,
};

#[cfg(not(target_os = "android"))]
use same_file::Handle;
#[cfg(not(target_os = "android"))]
use uuid::Uuid;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Runtime};
use zeroize::Zeroizing;

use crate::{
    error::{Result, VaultError},
    gallery::GalleryRepository,
};

const VERIFY_BUFFER_BYTES: usize = 64 * 1024;
const RETAINED_WARNING: &str =
    "The encrypted item was saved, but the original source was retained because it could not be verified for safe removal.";

pub struct SourceImportOutcome {
    pub id: String,
    pub source_removed: bool,
    pub warning: Option<String>,
}

struct DigestingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> DigestingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, hasher: Sha256::new() }
    }

    fn digest(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }
}

impl<R: Read> Read for DigestingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(not(target_os = "android"))]
pub fn import_source<R: Runtime>(
    _app: &AppHandle<R>,
    repository: &GalleryRepository,
    root_key: &[u8; 32],
    source: &str,
    remove_source_after_import: bool,
) -> Result<SourceImportOutcome> {
    let path = desktop_source_path(source)?;
    let link_metadata = fs::symlink_metadata(&path)?;
    let source_is_symlink = link_metadata.file_type().is_symlink();
    let mut source_handle = Handle::from_file(File::open(&path)?)?;
    let metadata = source_handle.as_file().metadata()?;
    if !metadata.is_file() {
        return Err(VaultError::InvalidInput("media source must be a file".into()));
    }
    if metadata.len() == 0 {
        return Err(VaultError::InvalidInput("empty media files are not supported".into()));
    }

    let fingerprint = DesktopFingerprint::new(&metadata);
    let mut reader = DigestingReader::new(source_handle.as_file_mut());
    let id = repository.import_reader(root_key, &mut reader, metadata.len())?;
    let imported_digest = reader.digest();

    if !remove_source_after_import {
        return Ok(SourceImportOutcome { id, source_removed: false, warning: None });
    }

    let removed = !source_is_symlink
        && verify_and_remove_desktop_source(
            &path,
            source_handle,
            &fingerprint,
            metadata.len(),
            &imported_digest,
        )
        .is_ok();
    Ok(SourceImportOutcome {
        id,
        source_removed: removed,
        warning: (!removed).then(|| RETAINED_WARNING.to_owned()),
    })
}

#[cfg(not(target_os = "android"))]
fn desktop_source_path(source: &str) -> Result<PathBuf> {
    if source.starts_with("file://") {
        let url = url::Url::parse(source).map_err(|_| VaultError::InvalidInput("invalid file URL".into()))?;
        return url.to_file_path().map_err(|_| VaultError::InvalidInput("invalid local file URL".into()));
    }
    let path = PathBuf::from(source);
    if path.as_os_str().is_empty() {
        return Err(VaultError::InvalidInput("empty media source".into()));
    }
    Ok(path)
}

#[cfg(not(target_os = "android"))]
#[derive(Clone)]
struct DesktopFingerprint {
    len: u64,
    modified: Option<SystemTime>,
}

#[cfg(not(target_os = "android"))]
impl DesktopFingerprint {
    fn new(metadata: &Metadata) -> Self {
        Self { len: metadata.len(), modified: metadata.modified().ok() }
    }

    fn matches(&self, metadata: &Metadata) -> bool {
        metadata.is_file() && metadata.len() == self.len && metadata.modified().ok() == self.modified
    }
}

#[cfg(not(target_os = "android"))]
fn verify_and_remove_desktop_source(
    path: &Path,
    imported_handle: Handle,
    fingerprint: &DesktopFingerprint,
    expected_size: u64,
    expected_digest: &[u8; 32],
) -> Result<()> {
    reject_symlink(path)?;

    let mut verification = Handle::from_path(path)?;
    if imported_handle != verification || !fingerprint.matches(&verification.as_file().metadata()?) {
        return Err(VaultError::InvalidInput("media source changed after import".into()));
    }
    let actual_digest = hash_reader(verification.as_file_mut(), expected_size)?;
    if !bool::from(actual_digest[..].ct_eq(&expected_digest[..])) {
        return Err(VaultError::InvalidInput("media source changed after import".into()));
    }

    reject_symlink(path)?;
    let final_handle = Handle::from_path(path)?;
    if imported_handle != final_handle || !fingerprint.matches(&final_handle.as_file().metadata()?) {
        return Err(VaultError::InvalidInput("media source changed before removal".into()));
    }
    drop(final_handle);
    drop(verification);

    quarantine_and_remove(path, imported_handle, fingerprint)
}

#[cfg(not(target_os = "android"))]
fn quarantine_and_remove(
    path: &Path,
    imported_handle: Handle,
    fingerprint: &DesktopFingerprint,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::InvalidInput("media source has no parent directory".into()))?;
    let quarantine_dir = parent.join(format!(".nd-secure-remove-{}", Uuid::new_v4()));
    fs::create_dir(&quarantine_dir)?;
    let quarantined = quarantine_dir.join("source");

    if let Err(error) = fs::rename(path, &quarantined) {
        let _ = fs::remove_dir(&quarantine_dir);
        return Err(error.into());
    }

    let quarantine_matches = Handle::from_path(&quarantined)
        .and_then(|handle| {
            let metadata = handle.as_file().metadata()?;
            Ok(handle == imported_handle && fingerprint.matches(&metadata))
        })
        .unwrap_or(false);
    if !quarantine_matches {
        restore_quarantined_source(path, &quarantined, &quarantine_dir);
        return Err(VaultError::InvalidInput("media source changed during removal".into()));
    }

    drop(imported_handle);
    if let Err(error) = fs::remove_file(&quarantined) {
        restore_quarantined_source(path, &quarantined, &quarantine_dir);
        return Err(error.into());
    }
    let _ = fs::remove_dir(&quarantine_dir);
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn restore_quarantined_source(path: &Path, quarantined: &Path, quarantine_dir: &Path) {
    if !path.exists() {
        let _ = fs::rename(quarantined, path);
    }
    let _ = fs::remove_dir(quarantine_dir);
}

#[cfg(not(target_os = "android"))]
fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(VaultError::InvalidInput("refusing to remove a symbolic-link source".into()));
    }
    Ok(())
}

#[cfg(target_os = "android")]
pub fn import_source<R: Runtime>(
    app: &AppHandle<R>,
    repository: &GalleryRepository,
    root_key: &[u8; 32],
    source: &str,
    remove_source_after_import: bool,
) -> Result<SourceImportOutcome> {
    use std::os::fd::FromRawFd;
    use tauri_plugin_vault_source::VaultSourceExt;

    if !source.starts_with("content://") {
        return Err(VaultError::InvalidInput("Android imports require a content URI".into()));
    }
    let opened = app
        .vault_source()
        .open_source(source.to_owned())
        .map_err(|_| VaultError::Platform("unable to open the selected Android document".into()))?;
    if opened.fd < 0 {
        return Err(VaultError::Platform("Android provider returned an invalid file descriptor".into()));
    }
    if opened.size == 0 {
        unsafe { libc::close(opened.fd) };
        return Err(VaultError::InvalidInput("empty media files are not supported".into()));
    }

    let file = unsafe { File::from_raw_fd(opened.fd) };
    let mut reader = DigestingReader::new(file);
    let id = repository.import_reader(root_key, &mut reader, opened.size)?;
    let imported_digest = reader.digest();

    if !remove_source_after_import {
        return Ok(SourceImportOutcome { id, source_removed: false, warning: None });
    }

    let removed = verify_android_source(app, source, opened.size, &imported_digest)
        .and_then(|_| {
            app.vault_source()
                .delete_source(source.to_owned())
                .map_err(|_| VaultError::Platform("unable to remove Android source".into()))
        })
        .unwrap_or(false);
    Ok(SourceImportOutcome {
        id,
        source_removed: removed,
        warning: (!removed).then(|| RETAINED_WARNING.to_owned()),
    })
}

#[cfg(target_os = "android")]
fn verify_android_source<R: Runtime>(
    app: &AppHandle<R>,
    source: &str,
    expected_size: u64,
    expected_digest: &[u8; 32],
) -> Result<()> {
    use std::os::fd::FromRawFd;
    use tauri_plugin_vault_source::VaultSourceExt;

    let opened = app
        .vault_source()
        .open_source(source.to_owned())
        .map_err(|_| VaultError::Platform("unable to reopen Android source".into()))?;
    if opened.fd < 0 {
        return Err(VaultError::Platform("Android provider returned an invalid file descriptor".into()));
    }
    if opened.size != expected_size {
        unsafe { libc::close(opened.fd) };
        return Err(VaultError::InvalidInput("media source changed after import".into()));
    }
    let mut verification = unsafe { File::from_raw_fd(opened.fd) };
    let actual_digest = hash_reader(&mut verification, expected_size)?;
    if !bool::from(actual_digest[..].ct_eq(&expected_digest[..])) {
        return Err(VaultError::InvalidInput("media source changed after import".into()));
    }
    Ok(())
}

fn hash_reader<R: Read>(reader: &mut R, expected_size: u64) -> Result<[u8; 32]> {
    let mut buffer = Zeroizing::new(vec![0_u8; VERIFY_BUFFER_BYTES]);
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    loop {
        let read = reader.read(buffer.as_mut_slice())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| VaultError::InvalidInput("media source size overflow".into()))?;
        if total > expected_size {
            return Err(VaultError::InvalidInput("media source changed after import".into()));
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(VaultError::InvalidInput("media source changed after import".into()));
    }
    Ok(hasher.finalize().into())
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn verified_removal_deletes_only_the_imported_file_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.bin");
        fs::write(&path, b"verified source").unwrap();

        let imported_handle = Handle::from_file(File::open(&path).unwrap()).unwrap();
        let metadata = imported_handle.as_file().metadata().unwrap();
        let fingerprint = DesktopFingerprint::new(&metadata);
        let digest = hash_reader(&mut Cursor::new(b"verified source".as_slice()), metadata.len()).unwrap();

        verify_and_remove_desktop_source(&path, imported_handle, &fingerprint, metadata.len(), &digest)
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn verified_removal_retains_a_replacement_at_the_same_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.bin");
        let original = directory.path().join("original.bin");
        fs::write(&path, b"same bytes").unwrap();

        let imported_handle = Handle::from_file(File::open(&path).unwrap()).unwrap();
        let metadata = imported_handle.as_file().metadata().unwrap();
        let fingerprint = DesktopFingerprint::new(&metadata);
        let digest = hash_reader(&mut Cursor::new(b"same bytes".as_slice()), metadata.len()).unwrap();

        fs::rename(&path, &original).unwrap();
        fs::write(&path, b"same bytes").unwrap();
        assert!(verify_and_remove_desktop_source(
            &path,
            imported_handle,
            &fingerprint,
            metadata.len(),
            &digest,
        )
        .is_err());
        assert!(path.exists());
    }
}
