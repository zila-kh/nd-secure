impl CredentialRepository {
    pub fn project_secret_values(
        &self,
        root_key: &[u8; 32],
        project: &str,
        environment: &str,
        required_keys: &[String],
    ) -> Result<std::collections::BTreeMap<String, Zeroizing<String>>> {
        if required_keys.len() > 2048 {
            return Err(VaultError::InvalidInput("too many project secret keys".into()));
        }
        let required: std::collections::BTreeSet<&str> =
            required_keys.iter().map(String::as_str).collect();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, record_type, record_salt, nonce, ciphertext, format_version,
                    revision, created_at, updated_at
             FROM credential_records WHERE state = 1 AND record_type = 4",
        )?;
        let rows = statement.query_map([], map_encrypted_row)?;
        let mut values = std::collections::BTreeMap::new();
        for row in rows {
            let detail = decrypt_row(root_key, &row?)?;
            if detail.record_type != CredentialType::Secret
                || detail.scope != CredentialScope::Project
                || detail.project.as_deref() != Some(project)
                || detail.environment.as_deref() != Some(environment)
                || !required.contains(detail.title.as_str())
            {
                continue;
            }
            let value = detail
                .secret_value
                .filter(|value| !value.is_empty())
                .ok_or(VaultError::AuthenticationFailed)?;
            if values
                .insert(detail.title.clone(), Zeroizing::new(value))
                .is_some()
            {
                return Err(VaultError::InvalidInput(format!(
                    "multiple project secrets are configured for {}",
                    detail.title
                )));
            }
        }
        Ok(values)
    }
}

#[cfg(test)]
mod project_secret_tests {
    use super::*;

    #[test]
    fn project_secret_resolution_is_exact_and_does_not_fall_back_across_environments() {
        let directory = tempfile::tempdir().unwrap();
        let repository =
            CredentialRepository::new(directory.path().join("credentials.sqlite3")).unwrap();
        let key = [61_u8; 32];
        for (environment, value) in [("dev", "dev-secret"), ("prod", "prod-secret")] {
            repository
                .save(
                    &key,
                    CredentialInput {
                        id: None,
                        record_type: CredentialType::Secret,
                        title: "API_TOKEN".into(),
                        scope: CredentialScope::Project,
                        project: Some("todo".into()),
                        environment: Some(environment.into()),
                        folder: None,
                        username: None,
                        password: None,
                        secret_value: Some(value.into()),
                        websites: Vec::new(),
                        notes: None,
                        totp_secret: None,
                        custom_fields: Vec::new(),
                        favorite: false,
                    },
                )
                .unwrap();
        }
        let required = vec!["API_TOKEN".to_owned()];
        let dev = repository
            .project_secret_values(&key, "todo", "dev", &required)
            .unwrap();
        assert_eq!(dev["API_TOKEN"].as_str(), "dev-secret");
        let prod = repository
            .project_secret_values(&key, "todo", "prod", &required)
            .unwrap();
        assert_eq!(prod["API_TOKEN"].as_str(), "prod-secret");
        assert!(repository
            .project_secret_values(&key, "todo", "test", &required)
            .unwrap()
            .is_empty());
    }
}
