use tauri::State;

use crate::state::AppState;

#[tauri::command]
pub fn record_user_activity(state: State<'_, AppState>) -> Result<(), String> {
    state.session.touch().map_err(|_| "vault is locked".to_owned())
}
