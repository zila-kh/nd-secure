use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

use super::{
    ProjectInspection, ProjectManifest, ProjectRegistration, GITIGNORE_BEGIN, GITIGNORE_END,
    MANIFEST_FILE, MANIFEST_VERSION, MAX_ENVIRONMENTS, MAX_ENVIRONMENT_BYTES, MAX_ENV_FILE_BYTES,
    MAX_KEYS, MAX_KEY_BYTES, MAX_NAME_BYTES,
};

pub(super) fn inspect_project_root(root: &str) -> Result<ProjectInspection> {
    let canonical = fs::canonicalize(root)?;
    if !canonical.is_dir() {
        return Err(VaultError::InvalidInput(
            "project root must be a directory".into(),
        ));
    }
    let canonical_string = canonical
        .to_str()
        .ok_or_else(|| VaultError::InvalidInput("project path must be valid UTF-8".into()))?
        .to_owned();
    let suggested_name = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("project")
        .to_owned();
    let example_path = canonical.join(".env.example");
    let required_keys = if example_path.is_file() {
        parse_env_example_keys(&example_path)?
    } else {
        Vec::new()
    };
    Ok(ProjectInspection {
        root: canonical_string,
        suggested_name,
        example_exists: example_path.is_file(),
        required_keys,
        plaintext_env_files: detect_plaintext_env_files(&canonical)?,
    })
}

pub(super) fn write_project_manifest(registration: &ProjectRegistration) -> Result<()> {
    let path = Path::new(&registration.root).join(MANIFEST_FILE);
    let manifest = ProjectManifest {
        version: MANIFEST_VERSION,
        project_id: &registration.id,
        project: &registration.name,
        environments: &registration.environments,
        required_keys: &registration.required_keys,
        managed_by: "ND Secure",
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn sanitize_env_example(root: &Path, keys: &[String]) -> Result<()> {
    write_value_free_env_example(&root.join(".env.example"), keys)
}

pub(super) fn ensure_gitignore(root: &str) -> Result<()> {
    let path = Path::new(root).join(".gitignore");
    let existing = match fs::read_to_string(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let managed = format!(
        "{GITIGNORE_BEGIN}\n.env\n.env.*\n!.env.example\n{GITIGNORE_END}\n"
    );
    let begin = existing.find(GITIGNORE_BEGIN);
    let end = existing.find(GITIGNORE_END);
    let updated = match (begin, end) {
        (Some(begin), Some(end)) if begin < end => {
            let suffix_start = end + GITIGNORE_END.len();
            let mut output = String::with_capacity(existing.len().saturating_add(managed.len()));
            output.push_str(&existing[..begin]);
            output.push_str(&managed);
            let suffix = existing[suffix_start..].trim_start_matches(&['\r', '\n'][..]);
            if !suffix.is_empty() {
                output.push_str(suffix);
                if !output.ends_with('\n') {
                    output.push('\n');
                }
            }
            output
        }
        (None, None) => {
            let mut output = existing.clone();
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&managed);
            output
        }
        _ => {
            return Err(VaultError::InvalidInput(
                "existing ND Secure .gitignore block is malformed".into(),
            ));
        }
    };
    if updated != existing {
        fs::write(path, updated)?;
    }
    Ok(())
}

pub(super) fn detect_plaintext_env_files(root: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_plaintext_env_name(&name) {
            files.push(name);
        }
    }
    files.sort();
    Ok(files)
}

pub(super) fn resolve_plaintext_env_file(root: &str, file_name: &str) -> Result<PathBuf> {
    let relative = Path::new(file_name);
    if relative.components().count() != 1
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !is_plaintext_env_name(file_name)
    {
        return Err(VaultError::InvalidInput(
            "invalid plaintext environment file name".into(),
        ));
    }
    let root_path = fs::canonicalize(root)?;
    let path = root_path.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ENV_FILE_BYTES
    {
        return Err(VaultError::InvalidInput(
            "environment file is not a safe regular file".into(),
        ));
    }
    let canonical = fs::canonicalize(&path)?;
    if canonical.parent() != Some(root_path.as_path()) {
        return Err(VaultError::InvalidInput(
            "environment file escapes the project root".into(),
        ));
    }
    Ok(canonical)
}

pub(super) fn validate_env_file_environment(
    registration: &ProjectRegistration,
    file_name: &str,
    environment: &str,
) -> Result<()> {
    if file_name == ".env" {
        return Ok(());
    }
    let Some(suffix) = file_name.strip_prefix(".env.") else {
        return Ok(());
    };
    let matched = registration.environments.iter().find(|candidate| {
        suffix == candidate.as_str() || suffix.starts_with(&format!("{candidate}."))
    });
    if let Some(matched) = matched {
        if matched != environment {
            return Err(VaultError::InvalidInput(format!(
                "{file_name} appears to belong to environment {matched}, not {environment}"
            )));
        }
    }
    Ok(())
}

pub(super) fn parse_env_file_values(
    path: &Path,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_ENV_FILE_BYTES {
        return Err(VaultError::InvalidInput(
            "environment file is too large".into(),
        ));
    }
    let content = Zeroizing::new(fs::read_to_string(path)?);
    let mut values = BTreeMap::new();
    for line in content.lines() {
        let Some((key, raw_value)) = parse_env_assignment(line)? else {
            continue;
        };
        if values.contains_key(&key) {
            return Err(VaultError::InvalidInput(format!(
                "duplicate environment key: {key}"
            )));
        }
        let value = parse_env_value(raw_value)?;
        if value.is_empty() {
            return Err(VaultError::InvalidInput(format!(
                "environment key has an empty value: {key}"
            )));
        }
        if value.len() > 64 * 1024 {
            return Err(VaultError::InvalidInput(format!(
                "environment value is too large: {key}"
            )));
        }
        values.insert(key, Zeroizing::new(value));
    }
    if values.len() > MAX_KEYS {
        return Err(VaultError::InvalidInput(
            "too many environment keys".into(),
        ));
    }
    Ok(values)
}

pub(super) fn merge_env_example(root: &Path, keys: &[String]) -> Result<()> {
    let path = root.join(".env.example");
    let mut all_keys: BTreeSet<String> = if path.is_file() {
        parse_env_example_keys(&path)?.into_iter().collect()
    } else {
        BTreeSet::new()
    };
    for key in keys {
        validate_env_key(key)?;
        all_keys.insert(key.clone());
    }
    let all_keys: Vec<String> = all_keys.into_iter().collect();
    write_value_free_env_example(&path, &all_keys)
}

pub(super) fn validate_project_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(VaultError::InvalidInput("invalid project name".into()));
    }
    Ok(name.to_owned())
}

pub(super) fn validate_environments(environments: Vec<String>) -> Result<Vec<String>> {
    if environments.is_empty() || environments.len() > MAX_ENVIRONMENTS {
        return Err(VaultError::InvalidInput(
            "project must define 1 to 32 environments".into(),
        ));
    }
    let mut unique = BTreeSet::new();
    for environment in environments {
        let environment = environment.trim().to_owned();
        validate_environment_name(&environment)?;
        unique.insert(environment);
    }
    Ok(unique.into_iter().collect())
}

pub(super) fn validate_registered_environment(
    registration: &ProjectRegistration,
    environment: &str,
) -> Result<()> {
    validate_environment_name(environment)?;
    if !registration
        .environments
        .iter()
        .any(|value| value == environment)
    {
        return Err(VaultError::InvalidInput(
            "environment is not registered for this project".into(),
        ));
    }
    Ok(())
}

fn is_plaintext_env_name(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env.")) && name != ".env.example"
}

fn parse_env_example_keys(path: &Path) -> Result<Vec<String>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_ENV_FILE_BYTES {
        return Err(VaultError::InvalidInput(".env.example is too large".into()));
    }
    let content = fs::read_to_string(path)?;
    let mut keys = BTreeSet::new();
    for line in content.lines() {
        if let Some((key, _)) = parse_env_assignment(line)? {
            keys.insert(key);
        }
    }
    if keys.len() > MAX_KEYS {
        return Err(VaultError::InvalidInput(
            "too many environment keys".into(),
        ));
    }
    Ok(keys.into_iter().collect())
}

fn write_value_free_env_example(path: &Path, keys: &[String]) -> Result<()> {
    if keys.len() > MAX_KEYS {
        return Err(VaultError::InvalidInput(
            "too many environment keys".into(),
        ));
    }
    let mut unique = BTreeSet::new();
    for key in keys {
        validate_env_key(key)?;
        unique.insert(key.as_str());
    }
    let mut output = String::from(
        "# Managed by ND Secure. This file intentionally contains key names only.\n# Real values live in the encrypted vault and are injected only when authorized.\n",
    );
    for key in unique {
        output.push_str(key);
        output.push_str("=\n");
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(output.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn parse_env_assignment(line: &str) -> Result<Option<(String, &str)>> {
    let line = line.trim_start_matches('\u{feff}').trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    let Some((key, value)) = line.split_once('=') else {
        return Err(VaultError::InvalidInput(
            "environment line is missing '='".into(),
        ));
    };
    let key = key.trim();
    validate_env_key(key)?;
    Ok(Some((key.to_owned(), value)))
}

fn parse_env_value(raw: &str) -> Result<String> {
    let value = raw.trim();
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        return Ok(value[1..value.len() - 1].to_owned());
    }
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        let mut output = String::with_capacity(inner.len());
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                match character {
                    'n' => output.push('\n'),
                    'r' => output.push('\r'),
                    't' => output.push('\t'),
                    '\\' => output.push('\\'),
                    '"' => output.push('"'),
                    other => {
                        output.push('\\');
                        output.push(other);
                    }
                }
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else {
                output.push(character);
            }
        }
        if escaped {
            output.push('\\');
        }
        return Ok(output);
    }
    let unquoted = value
        .char_indices()
        .find(|(index, character)| {
            *character == '#'
                && *index > 0
                && value[..*index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace)
        })
        .map(|(index, _)| value[..index].trim_end())
        .unwrap_or(value);
    Ok(unquoted.to_owned())
}

fn validate_environment_name(environment: &str) -> Result<()> {
    if environment.is_empty()
        || environment.len() > MAX_ENVIRONMENT_BYTES
        || environment
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')))
    {
        return Err(VaultError::InvalidInput(
            "invalid project environment name".into(),
        ));
    }
    Ok(())
}

fn validate_env_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(VaultError::InvalidInput("invalid environment key".into()));
    }
    let mut characters = key.chars();
    let Some(first) = characters.next() else {
        return Err(VaultError::InvalidInput("invalid environment key".into()));
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || characters.any(|character| !(character == '_' || character.is_ascii_alphanumeric()))
    {
        return Err(VaultError::InvalidInput(format!(
            "invalid environment key: {key}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_example_parser_only_returns_key_names() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env.example");
        fs::write(
            &path,
            "# safe schema\nDATABASE_URL=postgres://example.invalid\nexport API_TOKEN=placeholder\nEMPTY=\n",
        )
        .unwrap();
        let keys = parse_env_example_keys(&path).unwrap();
        assert_eq!(keys, vec!["API_TOKEN", "DATABASE_URL", "EMPTY"]);
    }

    #[test]
    fn plaintext_env_detection_only_trusts_the_main_example_file() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(".env"), "SECRET=value").unwrap();
        fs::write(directory.path().join(".env.prod"), "SECRET=value").unwrap();
        fs::write(directory.path().join(".env.example"), "SECRET=").unwrap();
        fs::write(
            directory.path().join(".env.prod.example"),
            "SECRET=value",
        )
        .unwrap();
        fs::write(directory.path().join(".env.sample"), "SECRET=value").unwrap();
        assert_eq!(
            detect_plaintext_env_files(directory.path()).unwrap(),
            vec![".env", ".env.prod", ".env.prod.example", ".env.sample"]
        );
    }

    #[test]
    fn sanitize_env_example_removes_all_values_and_untrusted_comments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env.example");
        fs::write(
            &path,
            "# password=leaked-in-comment\nDATABASE_URL=postgres://secret\nAPI_TOKEN=secret-token\n",
        )
        .unwrap();
        let keys = parse_env_example_keys(&path).unwrap();
        sanitize_env_example(directory.path(), &keys).unwrap();
        let sanitized = fs::read_to_string(&path).unwrap();
        assert!(sanitized.contains("API_TOKEN=\n"));
        assert!(sanitized.contains("DATABASE_URL=\n"));
        assert!(!sanitized.contains("postgres://secret"));
        assert!(!sanitized.contains("secret-token"));
        assert!(!sanitized.contains("leaked-in-comment"));
    }

    #[test]
    fn environment_specific_file_cannot_be_imported_into_another_environment() {
        let registration = ProjectRegistration {
            id: uuid::Uuid::nil().to_string(),
            name: "todo".into(),
            root: "/tmp/todo".into(),
            environments: vec!["dev".into(), "prod".into()],
            required_keys: Vec::new(),
            created_at: 1,
            updated_at: 1,
        };
        assert!(validate_env_file_environment(&registration, ".env.prod", "prod").is_ok());
        assert!(
            validate_env_file_environment(&registration, ".env.prod.local", "prod").is_ok()
        );
        assert!(validate_env_file_environment(&registration, ".env.prod", "dev").is_err());
        assert!(validate_env_file_environment(&registration, ".env", "dev").is_ok());
    }

    #[test]
    fn unquoted_inline_comments_are_not_migrated_as_secret_data() {
        assert_eq!(
            parse_env_value("secret-value # developer note").unwrap(),
            "secret-value"
        );
        assert_eq!(parse_env_value("value#part").unwrap(), "value#part");
    }
}
