use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, PluginApi, PluginHandle, TauriPlugin},
    AppHandle, Manager, Runtime,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceRequest {
    uri: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenSourceResponse {
    pub fd: i32,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteSourceResponse {
    deleted: bool,
}

const PLUGIN_IDENTIFIER: &str = "kh.zila.ndsecure.vaultsource";

pub struct VaultSource<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> VaultSource<R> {
    pub fn open_source(&self, uri: String) -> Result<OpenSourceResponse> {
        self.0.run_mobile_plugin("openSource", SourceRequest { uri }).map_err(Into::into)
    }

    pub fn delete_source(&self, uri: String) -> Result<bool> {
        let response: DeleteSourceResponse =
            self.0.run_mobile_plugin("deleteSource", SourceRequest { uri })?;
        Ok(response.deleted)
    }
}

pub trait VaultSourceExt<R: Runtime> {
    fn vault_source(&self) -> &VaultSource<R>;
}

impl<R: Runtime, T: Manager<R>> VaultSourceExt<R> for T {
    fn vault_source(&self) -> &VaultSource<R> {
        self.state::<VaultSource<R>>().inner()
    }
}

fn setup<R: Runtime, C: serde::de::DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> Result<VaultSource<R>> {
    let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "VaultSourcePlugin")?;
    Ok(VaultSource(handle))
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("vault-source")
        .setup(|app, api| {
            let source = setup(app, api)?;
            app.manage(source);
            Ok(())
        })
        .build()
}
