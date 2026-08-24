mod commands;
mod credentials;
mod crypto;
mod error;
mod gallery;
mod media_server;
mod paths;
mod protocol;
mod session;
mod source;
mod state;

use std::sync::{Arc, OnceLock};

use tauri::{
    http::{Response, StatusCode},
    Manager,
};

use crate::{
    credentials::CredentialRepository, gallery::GalleryRepository, media_server::MediaServer,
    paths::VaultPaths, session::SessionState, state::AppState,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let protocol_state = Arc::new(OnceLock::<AppState>::new());
    let protocol_handler_state = Arc::clone(&protocol_state);
    let protocol_setup_state = Arc::clone(&protocol_state);

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init());

    #[cfg(target_os = "android")]
    let builder = builder.plugin(tauri_plugin_vault_source::init());

    builder
        .register_asynchronous_uri_scheme_protocol("vault", move |_context, request, responder| {
            let state = protocol_handler_state.get().cloned();
            tauri::async_runtime::spawn_blocking(move || {
                let response = match state {
                    Some(state) => protocol::response(&state, request),
                    None => Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header("Cache-Control", "no-store")
                        .header("Content-Length", "0")
                        .body(Vec::new())
                        .unwrap_or_else(|_| Response::new(Vec::new())),
                };
                responder.respond(response);
            });
        })
        .on_window_event(|window, event| {
            if let Some(state) = window.try_state::<AppState>() {
                let should_lock = matches!(
                    event,
                    tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
                ) || (matches!(event, tauri::WindowEvent::Focused(false))
                    && state.session.lock_on_blur());
                #[cfg(mobile)]
                let should_lock = should_lock
                    || (matches!(event, tauri::WindowEvent::Suspended) && state.session.lock_on_suspend());

                if should_lock {
                    state.media_server.revoke_all();
                    state.session.lock();
                }
            }
        })
        .setup(move |app| {
            #[cfg(desktop)]
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_content_protected(true);
            }

            let local_data = app.path().app_local_data_dir()?;
            let paths = VaultPaths::new(&local_data);
            paths.create_all()?;

            let session = Arc::new(SessionState::new(paths.header.clone()));
            let gallery = Arc::new(GalleryRepository::new(
                paths.gallery_db.clone(),
                paths.gallery_objects.clone(),
                paths.gallery_thumbnails.clone(),
            )?);
            let credentials = Arc::new(CredentialRepository::new(paths.credentials_db.clone())?);
            let media_server = Arc::new(MediaServer::start(Arc::clone(&session), Arc::clone(&gallery))?);
            let state = AppState::new(session, gallery, credentials, media_server);

            if protocol_setup_state.set(state.clone()).is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "protocol state was initialized more than once",
                )
                .into());
            }
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::session_status,
            commands::initialize_vault,
            commands::unlock_vault,
            commands::reauthenticate_vault,
            commands::change_master_password,
            commands::create_recovery_key,
            commands::disable_recovery,
            commands::recover_vault,
            commands::lock_vault,
            commands::set_auto_lock,
            commands::set_delete_source_after_import,
            commands::set_security_preferences,
            commands::gallery_page,
            commands::import_media,
            commands::delete_media,
            commands::open_media_stream,
            commands::close_media_stream,
            commands::credential_page,
            commands::credential_trash_page,
            commands::credential_detail,
            commands::save_credential,
            commands::delete_credential,
            commands::restore_credential,
            commands::purge_credential,
            commands::empty_credential_trash,
            commands::copy_credential_field,
            commands::generate_password,
            commands::generate_password_advanced,
            commands::credential_totp,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run ND Secure");
}
