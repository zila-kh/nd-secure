use std::sync::Arc;

use tauri::State;
use uuid::Uuid;

use crate::{
    crypto::{CREDENTIALS_DOMAIN, PROJECTS_DOMAIN},
    error::{Result, VaultError},
    projects::{
        ProjectCommandResult, ProjectEnvImportResult, ProjectEnvironmentStatus, ProjectInspection,
        ProjectRegistration,
    },
    state::AppState,
};

type CommandResult<T> = std::result::Result<T, String>;

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
pub async fn inspect_project(
    state: State<'_, AppState>,
    root: String,
) -> CommandResult<ProjectInspection> {
    state.session.touch().map_err(public_error)?;
    if root.len() > 32 * 1024 {
        return Err("project path is too long".into());
    }
    let repository = Arc::clone(&state.projects);
    blocking(move || repository.inspect(&root)).await
}

#[tauri::command]
pub async fn project_list(
    state: State<'_, AppState>,
) -> CommandResult<Vec<ProjectRegistration>> {
    let key = state
        .session
        .domain_key(PROJECTS_DOMAIN)
        .map_err(public_error)?;
    let repository = Arc::clone(&state.projects);
    blocking(move || repository.list(&key)).await
}

#[tauri::command]
pub async fn register_project(
    state: State<'_, AppState>,
    root: String,
    name: String,
    environments: Vec<String>,
) -> CommandResult<ProjectRegistration> {
    if root.len() > 32 * 1024 || name.len() > 256 || environments.len() > 32 {
        return Err("project registration input is too large".into());
    }
    let key = state
        .session
        .domain_key(PROJECTS_DOMAIN)
        .map_err(public_error)?;
    let repository = Arc::clone(&state.projects);
    blocking(move || repository.register(&key, root, name, environments)).await
}

#[tauri::command]
pub async fn sync_project(
    state: State<'_, AppState>,
    id: String,
) -> CommandResult<ProjectRegistration> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    let key = state
        .session
        .domain_key(PROJECTS_DOMAIN)
        .map_err(public_error)?;
    let repository = Arc::clone(&state.projects);
    blocking(move || repository.sync(&key, id)).await
}

#[tauri::command]
pub async fn delete_project(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    state.session.touch().map_err(public_error)?;
    let id = canonical_uuid(&id).map_err(public_error)?;
    let repository = Arc::clone(&state.projects);
    blocking(move || repository.delete(id)).await
}

#[tauri::command]
pub async fn project_environment_status(
    state: State<'_, AppState>,
    id: String,
    environment: String,
) -> CommandResult<ProjectEnvironmentStatus> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    if environment.len() > 64 {
        return Err("project environment name is too long".into());
    }
    let project_key = state
        .session
        .domain_key(PROJECTS_DOMAIN)
        .map_err(public_error)?;
    let credential_key = state
        .session
        .domain_key(CREDENTIALS_DOMAIN)
        .map_err(public_error)?;
    let projects = Arc::clone(&state.projects);
    let credentials = Arc::clone(&state.credentials);
    blocking(move || {
        projects.environment_status(
            &project_key,
            credentials.as_ref(),
            &credential_key,
            id,
            &environment,
        )
    })
    .await
}

#[tauri::command]
pub async fn import_project_env(
    state: State<'_, AppState>,
    id: String,
    environment: String,
    file_name: String,
) -> CommandResult<ProjectEnvImportResult> {
    let id = canonical_uuid(&id).map_err(public_error)?;
    if environment.len() > 64 || file_name.len() > 512 {
        return Err("project environment import input is too large".into());
    }
    let project_key = state
        .session
        .domain_key(PROJECTS_DOMAIN)
        .map_err(public_error)?;
    let credential_key = state
        .session
        .domain_key(CREDENTIALS_DOMAIN)
        .map_err(public_error)?;
    let projects = Arc::clone(&state.projects);
    let credentials = Arc::clone(&state.credentials);
    blocking(move || {
        projects.import_plaintext_env(
            &project_key,
            credentials.as_ref(),
            &credential_key,
            id,
            &environment,
            &file_name,
        )
    })
    .await
}

#[tauri::command]
pub async fn run_project_command(
    state: State<'_, AppState>,
    id: String,
    environment: String,
    program: String,
    args: Vec<String>,
) -> CommandResult<ProjectCommandResult> {
    state
        .session
        .require_recent_reauthentication()
        .map_err(public_error)?;
    let id = canonical_uuid(&id).map_err(public_error)?;
    if environment.len() > 64 || program.len() > 4096 || args.len() > 256 {
        return Err("project command input is too large".into());
    }
    let project_key = state
        .session
        .domain_key(PROJECTS_DOMAIN)
        .map_err(public_error)?;
    let credential_key = state
        .session
        .domain_key(CREDENTIALS_DOMAIN)
        .map_err(public_error)?;
    let projects = Arc::clone(&state.projects);
    let credentials = Arc::clone(&state.credentials);
    blocking(move || {
        projects.run_command(
            &project_key,
            credentials.as_ref(),
            &credential_key,
            id,
            &environment,
            &program,
            args,
        )
    })
    .await
}

fn canonical_uuid(value: &str) -> Result<Uuid> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| VaultError::InvalidInput("invalid UUID".into()))?;
    if parsed.to_string() != value {
        return Err(VaultError::InvalidInput("UUID is not canonical".into()));
    }
    Ok(parsed)
}
