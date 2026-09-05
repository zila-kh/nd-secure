use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    process::{Command, Stdio},
};

use uuid::Uuid;

use crate::{
    credentials::{CredentialInput, CredentialRepository, CredentialScope, CredentialType},
    error::{Result, VaultError},
};

use super::{
    env::{
        detect_plaintext_env_files, merge_env_example, parse_env_file_values,
        resolve_plaintext_env_file, validate_registered_environment,
    },
    ProjectCommandResult, ProjectEnvImportResult, ProjectEnvironmentStatus, ProjectRepository,
};

const MAX_PROGRAM_BYTES: usize = 4096;
const MAX_ARGS: usize = 256;
const MAX_ARG_BYTES: usize = 16 * 1024;

impl ProjectRepository {
    pub fn environment_status(
        &self,
        project_root_key: &[u8; 32],
        credential_repository: &CredentialRepository,
        credential_root_key: &[u8; 32],
        id: Uuid,
        environment: &str,
    ) -> Result<ProjectEnvironmentStatus> {
        let registration = self.detail(project_root_key, id)?;
        validate_registered_environment(&registration, environment)?;
        let secrets = credential_repository.project_secret_values(
            credential_root_key,
            &registration.name,
            environment,
            &registration.required_keys,
        )?;
        let present: BTreeSet<String> = secrets.keys().cloned().collect();
        let missing_keys = registration
            .required_keys
            .iter()
            .filter(|key| !present.contains(*key))
            .cloned()
            .collect();
        let present_keys = registration
            .required_keys
            .iter()
            .filter(|key| present.contains(*key))
            .cloned()
            .collect();
        drop(secrets);
        Ok(ProjectEnvironmentStatus {
            project_id: registration.id,
            environment: environment.to_owned(),
            present_keys,
            missing_keys,
            plaintext_env_files: detect_plaintext_env_files(Path::new(&registration.root))?,
        })
    }

    pub fn import_plaintext_env(
        &self,
        project_root_key: &[u8; 32],
        credential_repository: &CredentialRepository,
        credential_root_key: &[u8; 32],
        id: Uuid,
        environment: &str,
        file_name: &str,
    ) -> Result<ProjectEnvImportResult> {
        let registration = self.detail(project_root_key, id)?;
        validate_registered_environment(&registration, environment)?;
        let source_path = resolve_plaintext_env_file(&registration.root, file_name)?;
        let parsed = parse_env_file_values(&source_path)?;
        if parsed.is_empty() {
            return Err(VaultError::InvalidInput("environment file contains no values".into()));
        }
        let keys: Vec<String> = parsed.keys().cloned().collect();
        let existing = credential_repository.project_secret_values(
            credential_root_key,
            &registration.name,
            environment,
            &keys,
        )?;

        let mut conflicts = Vec::new();
        let mut existing_keys = Vec::new();
        for (key, value) in &parsed {
            if let Some(current) = existing.get(key) {
                if current.as_str() == value.as_str() {
                    existing_keys.push(key.clone());
                } else {
                    conflicts.push(key.clone());
                }
            }
        }
        if !conflicts.is_empty() {
            return Err(VaultError::InvalidInput(format!(
                "vault already contains different values for: {}",
                conflicts.join(", ")
            )));
        }

        let mut imported_keys = Vec::new();
        for (key, value) in parsed {
            if existing.contains_key(&key) {
                continue;
            }
            credential_repository.save(
                credential_root_key,
                CredentialInput {
                    id: None,
                    record_type: CredentialType::Secret,
                    title: key.clone(),
                    scope: CredentialScope::Project,
                    project: Some(registration.name.clone()),
                    environment: Some(environment.to_owned()),
                    folder: Some("Project environments".into()),
                    username: None,
                    password: None,
                    secret_value: Some(value.as_str().to_owned()),
                    websites: Vec::new(),
                    notes: Some("Imported from a local plaintext environment file by ND Secure".into()),
                    totp_secret: None,
                    custom_fields: Vec::new(),
                    favorite: false,
                },
            )?;
            imported_keys.push(key);
        }
        drop(existing);

        merge_env_example(Path::new(&registration.root), &keys)?;
        let _ = self.sync(project_root_key, id)?;
        let source_removed = fs::remove_file(&source_path).is_ok();
        imported_keys.sort();
        existing_keys.sort();
        Ok(ProjectEnvImportResult {
            imported_keys,
            existing_keys,
            source_removed,
            rotation_recommended: true,
        })
    }

    pub fn run_command(
        &self,
        project_root_key: &[u8; 32],
        credential_repository: &CredentialRepository,
        credential_root_key: &[u8; 32],
        id: Uuid,
        environment: &str,
        program: &str,
        args: Vec<String>,
    ) -> Result<ProjectCommandResult> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let _ = (
                project_root_key,
                credential_repository,
                credential_root_key,
                id,
                environment,
                program,
                args,
            );
            return Err(VaultError::Platform(
                "project command execution is only available on desktop".into(),
            ));
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            validate_program(program, &args)?;
            let registration = self.detail(project_root_key, id)?;
            validate_registered_environment(&registration, environment)?;
            let secrets = credential_repository.project_secret_values(
                credential_root_key,
                &registration.name,
                environment,
                &registration.required_keys,
            )?;
            let missing: Vec<String> = registration
                .required_keys
                .iter()
                .filter(|key| !secrets.contains_key(*key))
                .cloned()
                .collect();
            if !missing.is_empty() {
                return Err(VaultError::InvalidInput(format!(
                    "missing project secrets: {}",
                    missing.join(", ")
                )));
            }

            let mut command = Command::new(program);
            command.current_dir(&registration.root).args(args).env_clear();
            copy_safe_parent_environment(&mut command);
            command
                .env("ND_SECURE_PROJECT", &registration.name)
                .env("ND_SECURE_ENVIRONMENT", environment)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            for (key, value) in &secrets {
                command.env(key, value.as_str());
            }
            let mut child =
                command.spawn().map_err(|error| VaultError::Platform(error.to_string()))?;
            let pid = child.id();
            let injected_keys = registration.required_keys.clone();
            drop(secrets);
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            Ok(ProjectCommandResult { pid, injected_keys })
        }
    }
}

fn validate_program(program: &str, args: &[String]) -> Result<()> {
    if program.trim().is_empty() || program.len() > MAX_PROGRAM_BYTES || program.contains('\0') {
        return Err(VaultError::InvalidInput("invalid executable".into()));
    }
    if args.len() > MAX_ARGS
        || args.iter().any(|argument| argument.len() > MAX_ARG_BYTES || argument.contains('\0'))
    {
        return Err(VaultError::InvalidInput("invalid command arguments".into()));
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn copy_safe_parent_environment(command: &mut Command) {
    const ALLOW: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "APPDATA",
        "LOCALAPPDATA",
        "USERPROFILE",
    ];
    for key in ALLOW {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}
