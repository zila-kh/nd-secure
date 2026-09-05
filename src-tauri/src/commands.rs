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
        generate_password as create_password, generate_password_with_options, generate_totp,
        CredentialDetail, CredentialInput, CredentialPage, GeneratedPassword,
        PasswordGeneratorOptions, TotpCode,
    },
    crypto::{CREDENTIALS_DOMAIN, GALLERY_DOMAIN},
    error::{Result, VaultError},
    gallery::{GalleryPage, GalleryTrashPage},
    session::{RecoveryKey, SessionStatus},
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaStreamHandle {
    url: String,
    token: String,
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

fn clear_clipboard_if_digest(app: &AppHandle, expected_digest: &[u8]) {
    let Ok(current) = app.clipboard().read_text() else {
        return;
    };
    let current = Zeroizing::new(current);
    let current_digest = Sha256::digest(current.as_bytes());
    if bool::from(current_digest[..].ct_eq(expected_digest)) {
        let _ = app.clipboard().clear();
    }
}

pub fn clear_tracked_clipboard(app: &AppHandle, state: &AppState) {
    state.clipboard.with_operation(|| {
        let Some((generation, expected_digest)) = state.clipboard.current() else {
            return;
        };
        clear_clipboard_if_digest(app, &expected_digest);
        state.clipboard.clear_if_generation(generation);
    });
}

#[tauri::command]
pub fn session_status(app: AppHandle, state: State<'_, AppState>) -> SessionStatus {
    let status = state.session.status();
    if status.locked {
        clear_tracked_clipboard(&app, state.inner());
    }
    status
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
pub async fn unlock_vault(
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    let password = Zeroizing::new(password);
    blocking(move || session.unlock(password)).await
}

#[tauri::command]
pub async fn reauthenticate_vault(
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    let password = Zeroizing::new(password);
    blocking(move || session.reauthenticate(password)).await
}

#[tauri::command]
pub async fn change_master_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);
    blocking(move || session.change_master_password(current_password, new_password)).await
}

#[tauri::command]
pub async fn create_recovery_key(
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<RecoveryKey> {
    let session = Arc::clone(&state.session);
    let password = Zeroizing::new(password);
    blocking(move || session.create_recovery_key(password)).await
}

#[tauri::command]
pub async fn disable_recovery(
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    let password = Zeroizing::new(password);
    blocking(move || session.disable_recovery(password)).await
}

#[tauri::command]
pub async fn recover_vault(
    state: State<'_, AppState>,
    recovery_key: String,
    new_password: String,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    let recovery_key = Zeroizing::new(recovery_key);
    let new_password = Zeroizing::new(new_password);
    blocking(move || session.recover_with_key(recovery_key, new_password)).await
}

#[tauri::command]
pub fn lock_vault(app: AppHandle, state: State<'_, AppState>) -> SessionStatus {
    state.media_server.revoke_all();
    clear_tracked_clipboard(&app, state.inner());
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
pub async fn set_security_preferences(
    state: State<'_, AppState>,
    lock_on_blur: bool,
    lock_on_suspend: bool,
    clipboard_timeout_seconds: u64,
) -> CommandResult<SessionStatus> {
    let session = Arc::clone(&state.session);
    blocking(move || {
        session.set_security_preferences(lock_on_blur, lock_on_suspend, clipboard_timeout_seconds)
    })
    .await
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
pub async fn gallery_trash_page(
    state: State<'_, AppState>,
    cursor: Option<String>,
    limit: u32,
) -> CommandResult<GalleryTrashPage> {
    let key = state.session.domain_key(GALLERY_DOMAIN).map_err(public_error)?;
    let trash = Arc::clone(&state.gallery_trash);
    blocking(move || trash.page(&key, cursor.as_deref(), limit)).await
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
            match source::import_source(
                &app,
                repository.as_ref(),
                &key,
                &selected,
                source_removal_enabled,
            ) {
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
    let key = state.session.domain_key(GALLERY_DOMAIN).map_err(public_error)?;
    state.media_server.revoke_media(id);
    let trash = Arc::clone(&state.gallery_trash);
    blocking(move || trash.delete(&key, id)).await
}

#[tauri::command]
pub async fn restore_media(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    let key = state.session.domain_key(GALLERY_DOMAIN).map_err(public_error)?;
    let trash = Arc::clone(&state.gallery_trash);
    blocking(move || trash.restore(&key, id)).await
}

#[tauri::command]
pub async fn purge_media(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    state.session.require_recent_reauthentication().map_err(public_error)?;
    let id = canonical_uuid(&id).map_err(public_error)?;
    let trash = Arc::clone(&state.gallery_trash);
    blocking(move || trash.purge(id)).await
}

#[tauri::command]
pub async fn empty_media_trash(state: State<'_, AppState>) -> CommandResult<usize> {
    state.session.require_recent_reauthentication().map_err(public_error)?;
    let trash = Arc::clone(&state.gallery_trash);
    blocking(move || trash.empty()).await
}

#[tauri::command]
pub fn open_media_stream(
    state: State<'_, AppState>,
    id: String,
) -> CommandResult<MediaStreamHandle> {
    state.session.touch().map_err(public_error)?;
    let id = canonical_uuid(&id).map_err(public_error)?;
    let item = state.gallery.get(id).map_err(public_error)?;
    if !item.mime_type.starts_with("video/") {
        return Err("media item is not a video".into());
    }
    let (url, token) = state.media_server.issue(id).map_err(public_error)?;
    Ok(MediaStreamHandle { url, token })
}

#[tauri::command]
pub fn close_media_stream(state: State<'_, AppState>, token: String) {
    state.media_server.revoke(&token);
}

#[tauri::command]
pub async fn credential_page(
    state: State<'_, AppState>,
    cursor: Option<String>,
    limit: u32,
    search: String,
    project: Option<String>,
    environment: Option<String>,
) -> CommandResult<CredentialPage> {
    if search.len() > 4096
        || project.as_ref().map(String::len).unwrap_or(0) > 256
        || environment.as_ref().map(String::len).unwrap_or(0) > 64
    {
        return Err("credential filter text is too long".into());
    }
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || {
        repository.page(
            &key,
            cursor.as_deref(),
            limit,
            &search,
            project.as_deref(),
            environment.as_deref(),
        )
    })
    .await
}

#[tauri::command]
pub async fn credential_trash_page(
    state: State<'_, AppState>,
    cursor: Option<String>,
    limit: u32,
) -> CommandResult<CredentialPage> {
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.trash_page(&key, cursor.as_deref(), limit)).await
}

#[tauri::command]
pub async fn credential_detail(
    state: State<'_, AppState>,
    id: String,
) -> CommandResult<CredentialDetail> {
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
    let id = canonical_uuid(&id).map_err(public_error)?;
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.delete(&key, id)).await
}

#[tauri::command]
pub async fn restore_credential(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    let key = state.session.domain_key(CREDENTIALS_DOMAIN).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.restore(&key, id)).await
}

#[tauri::command]
pub async fn purge_credential(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    state.session.require_recent_reauthentication().map_err(public_error)?;
    let id = canonical_uuid(&id).map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.purge(id)).await
}

#[tauri::command]
pub async fn empty_credential_trash(state: State<'_, AppState>) -> CommandResult<usize> {
    state.session.require_recent_reauthentication().map_err(public_error)?;
    let repository = Arc::clone(&state.credentials);
    blocking(move || repository.empty_trash()).await
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
    let clipboard_timeout_seconds = state.session.clipboard_timeout_seconds();
    let repository = Arc::clone(&state.credentials);
    let secret = blocking(move || repository.field(&key, id, &field)).await?;

    let digest = Sha256::digest(secret.as_bytes());
    let mut expected_digest = Zeroizing::new([0_u8; 32]);
    expected_digest.copy_from_slice(&digest);
    let generation = state.clipboard.with_operation(|| -> CommandResult<u64> {
        app.clipboard()
            .write_text(secret.as_str())
            .map_err(|_| "unable to write to the system clipboard".to_owned())?;
        let generation = state.clipboard.track(*expected_digest);
        if state.session.status().locked {
            clear_clipboard_if_digest(&app, expected_digest.as_ref());
            state.clipboard.clear_if_generation(generation);
            return Err("vault is locked".into());
        }
        Ok(generation)
    })?;
    let clipboard_tracker = Arc::clone(&state.clipboard);
    drop(secret);

    let delayed_app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(clipboard_timeout_seconds)).await;
        let _ = tauri::async_runtime::spawn_blocking(move || {
            clipboard_tracker.with_operation(|| {
                if !clipboard_tracker.is_current(generation) {
                    return;
                }
                clear_clipboard_if_digest(&delayed_app, expected_digest.as_ref());
                clipboard_tracker.clear_if_generation(generation);
            });
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
pub fn generate_password_advanced(
    options: PasswordGeneratorOptions,
) -> CommandResult<GeneratedPassword> {
    generate_password_with_options(options).map_err(public_error)
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
