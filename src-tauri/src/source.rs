use std::fs::File;

#[cfg(not(target_os = "android"))]
use std::path::PathBuf;

use tauri::{AppHandle, Runtime};

use crate::{
    error::{Result, VaultError},
    gallery::GalleryRepository,
};

#[cfg(not(target_os = "android"))]
pub fn import_source<R: Runtime>(
    _app: &AppHandle<R>,
    repository: &GalleryRepository,
    root_key: &[u8; 32],
    source: &str,
) -> Result<String> {
    let path = desktop_source_path(source)?;
    let metadata = std::fs::metadata(&path)?;
    if !metadata.is_file() {
        return Err(VaultError::InvalidInput("media source must be a file".into()));
    }
    if metadata.len() == 0 {
        return Err(VaultError::InvalidInput("empty media files are not supported".into()));
    }
    let mut file = File::open(path)?;
    repository.import_reader(root_key, &mut file, metadata.len())
}

#[cfg(not(target_os = "android"))]
fn desktop_source_path(source: &str) -> Result<PathBuf> {
    if source.starts_with("file://") {
        let url = url::Url::parse(source)
            .map_err(|_| VaultError::InvalidInput("invalid file URL".into()))?;
        return url
            .to_file_path()
            .map_err(|_| VaultError::InvalidInput("invalid local file URL".into()));
    }
    let path = PathBuf::from(source);
    if path.as_os_str().is_empty() {
        return Err(VaultError::InvalidInput("empty media source".into()));
    }
    Ok(path)
}

#[cfg(target_os = "android")]
pub fn import_source<R: Runtime>(
    app: &AppHandle<R>,
    repository: &GalleryRepository,
    root_key: &[u8; 32],
    source: &str,
) -> Result<String> {
    use std::os::fd::FromRawFd;
    use tauri_plugin_vault_source::VaultSourceExt;

    if !source.starts_with("content://") {
        return Err(VaultError::InvalidInput(
            "Android imports require a content URI".into(),
        ));
    }
    let opened = app
        .vault_source()
        .open_source(source.to_owned())
        .map_err(|_| VaultError::Platform("unable to open the selected Android document".into()))?;
    if opened.size == 0 {
        unsafe { libc::close(opened.fd) };
        return Err(VaultError::InvalidInput("empty media files are not supported".into()));
    }
    let mut file = unsafe { File::from_raw_fd(opened.fd) };
    repository.import_reader(root_key, &mut file, opened.size)
}
