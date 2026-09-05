mod env;
mod repository;
mod runtime;

use serde::{Deserialize, Serialize};

pub use repository::ProjectRepository;

const FORMAT_VERSION: i64 = 1;
const MANIFEST_VERSION: u32 = 1;
const MANIFEST_FILE: &str = ".ndsecure.json";
const MAX_NAME_BYTES: usize = 256;
const MAX_ENVIRONMENTS: usize = 32;
const MAX_ENVIRONMENT_BYTES: usize = 64;
const MAX_KEYS: usize = 2048;
const MAX_KEY_BYTES: usize = 256;
const MAX_ENV_FILE_BYTES: u64 = 1024 * 1024;
const REGISTRY_CONTEXT: &[u8] = b"nd-secure/project-registration/v1";
const REGISTRY_AAD_PREFIX: &[u8] = b"nd-secure/project-registration-aad/v1";
const GITIGNORE_BEGIN: &str = "# >>> ND Secure plaintext environment files >>>";
const GITIGNORE_END: &str = "# <<< ND Secure plaintext environment files <<<";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRegistration {
    pub id: String,
    pub name: String,
    pub root: String,
    pub environments: Vec<String>,
    pub required_keys: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInspection {
    pub root: String,
    pub suggested_name: String,
    pub example_exists: bool,
    pub required_keys: Vec<String>,
    pub plaintext_env_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectEnvironmentStatus {
    pub project_id: String,
    pub environment: String,
    pub present_keys: Vec<String>,
    pub missing_keys: Vec<String>,
    pub plaintext_env_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectEnvImportResult {
    pub imported_keys: Vec<String>,
    pub existing_keys: Vec<String>,
    pub source_removed: bool,
    pub rotation_recommended: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectCommandResult {
    pub pid: u32,
    pub injected_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectManifest<'a> {
    version: u32,
    project_id: &'a str,
    project: &'a str,
    environments: &'a [String],
    required_keys: &'a [String],
    managed_by: &'static str,
}
