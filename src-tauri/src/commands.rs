use std::{sync::Arc, time::Duration};

use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    credentials::{
        generate_password as create_password, generate_totp, CredentialDetail, CredentialInput,
        CredentialPage, GeneratedPassword, TotpCode,
    },
    crypto::{CREDENTIALS_DOMAIN, GALLERY_DOMAIN},
    error::{Result, VaultError},
    gallery::GalleryPage,
    session::SessionStatus,
    source,
    state::AppState,
};

type CommandResult<T> = std::result::Result<T, String>;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportMediaItemResult {
    source_index: usize,
    id: Option<String>,
    source_removed: bool,
    warning: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportMediaResult {
    items: Vec<ImportMediaItemResult>,
    source_removal_enabled: bool,
}

fn public_error(error: VaultError) -> String {
    match error {
        VaultError::Storage(_) => "unable to access secure local storage".into(),
        VaultError::Database(_) => "unable to access the encrypted vault index".into(),
        VaultError::Platform(_) => "the requested platform operation failed".into(),
        other => other.to_string(),
    }
}

async fn blocking<T, F>(operation: F) -> CommandResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|_| "secure background operation failed".to_owned())?
        .map_err(public_error)
}

#[tauri::command]
pub fn session_status(state: State<'_, AppState>) -> SessionStatus {
    state.session.status()
}

#[tauri::command]
pub async fn initialize_vault(
    state: State<'_, AppState>,
    password: String,
    auto_lock_seconds: u64,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    let password = Zeroizing::new(password);
    blocking(move || session.initialize(password, auto_lock_seconds)).await
}

#[tauri::command]
pub async fn unlock_vault(state: State<'_, AppState>, password: String) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    let password = Zeroizing::new(password);
    blocking(move || session.unlock(password)).await
}

#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> SessionStatus {
    state.session.lock()
}

#[tauri::command]
pub async fn set_auto_lock(
    state: State<'_, AppState>,
    auto_lock_seconds: u64,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    blocking(move || session.set_auto_lock(auto_lock_seconds)).await
}

#[tauri::command]
pub async fn set_delete_source_after_import(
    state: State<'_, AppState>,
    enabled: bool,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    blocking(move || session.set_delete_source_after_import(enabled)).await
}

#[tauri::command]
pub async fn gallery_page(
    state: State<'_, AppState>,
    cursor: Option<String>,
    limit: u32,
) -> CommandResult<GalleryPage> {
    state.session.touch().map_err(public_error)?;
    let repository = Arc::clone(&state.gallery);
    blocking(move || repository.page(cursor.as_deref(), limit)).await
}

#[tauri::command]
pub async fn import_media(
    app: AppHandle,
    state: State<'_, AppState>,
    sources: Vec<String>,
) -> CommandResult<ImportMediaResult> {
    if sources.is_empty() || sources.len() > 100 {
        return Err("select between 1 and 100 media files".into());
    }
    if sources.iter().any(|source| source.len() > 16 * 1024) {
        return Err("a selected media source identifier is too long".into());
    }

    let source_removal_enabled = state.session.delete_source_after_import().map_err(public_error)?;
    let key = state.session.domain_key(GALLERY_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.gallery);
    blocking(move || {
        let mut items = Vec::with_capacity(sources.len());
        for (source_index, selected) in sources.into_iter().enumerate() {
            match source::import_source(&app, repository.as_ref(), &key, &selected, source_removal_enabled) {
                Ok(outcome) => items.push(ImportMediaItemResult {
                    source_index,
                    id: Some(outcome.id),
                    source_removed: outcome.source_removed,
                    warning: outcome.warning,
                    error: None,
                }),
                Err(error) => items.push(ImportMediaItemResult {
                    source_index,
                    id: None,
                    source_removed: false,
                    warning: None,
                    error: Some(public_error(error)),
                }),
            }
        }
        Ok(ImportMediaResult { items, source_removal_enabled })
    })
    .await
}

#[tauri::command]
pub async fn delete_media(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    state.session.touch().map_err(public_error)?;
    let id = canonical_uuid(&id).map_err(public_error)?;
    let repository = Arc::clone(&state.gallery);
    blocking(move || repository.delete(id)).await
}

#[tauri::command]
pub async fn credential_page(
    state: State<'_, AppState>,
    cursor: Option<String>,
    limit: u32,
    search: String,
) -> CommandResult<CredentialPage> {
    if search.len() > 4096 {
        return Err("credential search text is too long".into());
    }
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.page(&key, cursor.as_deref(), limit, &search)).await
}

#[tauri::command]
pub async fn credential_detail(state: State<'_, AppState>, id: String) -> CommandResult<CredentialDetail> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.detail(&key, id)).await
}

#[tauri::command]
pub async fn save_credential(
    state: State<'_, AppState>,
    input: CredentialInput,
) -> CommandResult<CredentialDetail> {
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.save(&key, input)).await
}

#[tauri::command]
pub async fn delete_credential(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    state.session.touch().map_err(public_error)?;
    let id = canonical_uuid(&id).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.delete(id)).await
}

#[tauri::command]
pub async fn copy_credential_field(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    field: String,
) -> CommandResult<()> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    let secret = blocking(move || repository.field(&key, id, &field)).await?;

    app.clipboard()
        .write_text(secret.as_str())
        .map_err(|_| "unable to write to the system clipboard".to_owned())?;
    let digest = Sha256::digest(secret.as_bytes());
    let mut expected_digest = Zeroizing::new([0_u8; 32]);
    expected_digest.copy_from_slice(&digest);
    drop(secret);

    let delayed_app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let Ok(current) = delayed_app.clipboard().read_text() else {
                return;
            };
            let current = Zeroizing::new(current);
            let current_digest = Sha256::digest(current.as_bytes());
            if bool::from(current_digest[..].ct_eq(&expected_digest[..])) {
                let _ = delayed_app.clipboard().clear();
            }
        })
        .await;
    });
    Ok(())
}

#[tauri::command]
pub fn generate_password(length: usize, symbols: bool) -> CommandResult<GeneratedPassword> {
    create_password(length, symbols).map_err(public_error)
}

#[tauri::command]
pub async fn credential_totp(state: State<'_, AppState>, id: String) -> CommandResult<TotpCode> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || {
        let secret = repository.totp_secret(&key, id)?;
        generate_totp(&secret)
    })
    .await
}

fn canonical_uuid(value: &str) -> Result<Uuid> {
    let parsed = Uuid::parse_str(value).map_err(|_| VaultError::InvalidInput("invalid UUID".into()))?;
    if parsed.to_string() != value {
        return Err(VaultError::InvalidInput("UUID is not canonical".into()));
    }
    Ok(parsed)
}
