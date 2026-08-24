fn summary_from_detail(detail: CredentialDetail) -> CredentialSummary {
    CredentialSummary {
        id: detail.id,
        record_type: detail.record_type,
        title: detail.title,
        scope: detail.scope,
        project: detail.project,
        environment: detail.environment,
        folder: detail.folder,
        username: detail.username,
        favorite: detail.favorite,
        updated_at: detail.updated_at,
    }
}

fn page_from_summaries(summaries: Vec<CredentialSummary>, has_more: bool) -> Result<CredentialPage> {
    let next_cursor = if has_more {
        summaries
            .last()
            .map(|item| {
                encode_cursor(&Cursor {
                    updated_at: item.updated_at,
                    id: item.id.clone(),
                })
            })
            .transpose()?
    } else {
        None
    };
    Ok(CredentialPage { items: summaries, next_cursor })
}

fn encrypted_row(connection: &Connection, id: Uuid) -> Result<EncryptedRow> {
    connection
        .query_row(
            "SELECT id, record_type, record_salt, nonce, ciphertext, format_version,
                    revision, created_at, updated_at
             FROM credential_records WHERE id = ?1 AND state = 1",
            params![id.to_string()],
            map_encrypted_row,
        )
        .optional()?
        .ok_or(VaultError::NotFound)
}

fn map_encrypted_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedRow> {
    let id_string: String = row.get(0)?;
    let record_type_number: i64 = row.get(1)?;
    let salt: Vec<u8> = row.get(2)?;
    let nonce: Vec<u8> = row.get(3)?;
    let id = Uuid::parse_str(&id_string).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let record_type = CredentialType::from_i64(record_type_number)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let salt: [u8; 16] = salt.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(EncryptedRow {
        id,
        record_type,
        salt,
        nonce,
        ciphertext: row.get(4)?,
        format_version: row.get(5)?,
        revision: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn decrypt_row(root_key: &[u8; 32], row: &EncryptedRow) -> Result<CredentialDetail> {
    if row.format_version != FORMAT_VERSION || row.revision <= 0 {
        return Err(VaultError::AuthenticationFailed);
    }
    let key = record_key(root_key, &row.salt, row.id)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&row.nonce),
            Payload {
                msg: &row.ciphertext,
                aad: &record_aad(row.id, row.record_type, row.revision),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    let detail: CredentialDetail = serde_json::from_slice(plaintext.as_slice())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    if detail.id != row.id.to_string()
        || detail.record_type != row.record_type
        || detail.created_at != row.created_at
        || detail.updated_at != row.updated_at
        || (detail.scope == CredentialScope::Central && detail.project.is_some())
        || detail.password_history.len() > MAX_PASSWORD_HISTORY
        || detail.custom_fields.len() > MAX_CUSTOM_FIELDS
    {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(detail)
}

fn record_key(root_key: &[u8; 32], salt: &[u8; 16], id: Uuid) -> Result<Zeroizing<[u8; 32]>> {
    let mut context = Vec::with_capacity(52);
    context.extend_from_slice(b"nd-secure/credential-record/v1");
    context.extend_from_slice(id.as_bytes());
    derive_object_key(root_key, salt, &context)
}

fn record_aad(id: Uuid, record_type: CredentialType, revision: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(b"nd-secure/credential-aad/v1");
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&record_type.as_i64().to_be_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

fn validate_input(input: &CredentialInput) -> Result<()> {
    let title = input.title.trim();
    if title.is_empty() || title.len() > MAX_TITLE_BYTES {
        return Err(VaultError::InvalidInput(
            "credential title must contain 1 to 512 bytes".into(),
        ));
    }
    if input.username.as_ref().map(String::len).unwrap_or(0) > MAX_USERNAME_BYTES
        || input.password.as_ref().map(String::len).unwrap_or(0) > MAX_PASSWORD_BYTES
        || input.secret_value.as_ref().map(String::len).unwrap_or(0) > MAX_SECRET_BYTES
        || input.notes.as_ref().map(String::len).unwrap_or(0) > MAX_NOTES_BYTES
        || input.project.as_ref().map(String::len).unwrap_or(0) > MAX_PROJECT_BYTES
        || input.environment.as_ref().map(String::len).unwrap_or(0) > MAX_ENVIRONMENT_BYTES
        || input.folder.as_ref().map(String::len).unwrap_or(0) > MAX_FOLDER_BYTES
        || input.websites.len() > MAX_WEBSITES
        || input.websites.iter().any(|value| value.len() > MAX_WEBSITE_BYTES)
        || input.custom_fields.len() > MAX_CUSTOM_FIELDS
        || input.custom_fields.iter().any(|field| {
            field.name.len() > MAX_CUSTOM_FIELD_NAME_BYTES
                || field.value.len() > MAX_CUSTOM_FIELD_VALUE_BYTES
        })
    {
        return Err(VaultError::InvalidInput("credential field exceeds its size limit".into()));
    }

    match input.scope {
        CredentialScope::Central => {
            if input.project.as_deref().is_some_and(|value| !value.trim().is_empty()) {
                return Err(VaultError::InvalidInput(
                    "central credentials cannot be assigned to a project".into(),
                ));
            }
        }
        CredentialScope::Project => {
            let project = input.project.as_deref().unwrap_or_default().trim();
            if project.is_empty() {
                return Err(VaultError::InvalidInput(
                    "project-scoped credentials require a project name".into(),
                ));
            }
        }
    }

    if let Some(environment) = input.environment.as_deref() {
        let environment = environment.trim();
        if environment.is_empty() || environment.chars().any(char::is_control) {
            return Err(VaultError::InvalidInput("invalid environment".into()));
        }
    }
    if let Some(folder) = input.folder.as_deref() {
        if folder.trim().is_empty() || folder.chars().any(char::is_control) {
            return Err(VaultError::InvalidInput("invalid folder".into()));
        }
    }
    if input.custom_fields.iter().any(|field| field.name.chars().any(char::is_control)) {
        return Err(VaultError::InvalidInput("custom field name contains unsupported characters".into()));
    }

    if input.record_type == CredentialType::Totp {
        let secret = input
            .totp_secret
            .as_deref()
            .ok_or_else(|| VaultError::InvalidInput("TOTP secret is required".into()))?;
        validate_totp_secret(secret)?;
    }
    if input.record_type == CredentialType::Secret
        && input.secret_value.as_deref().map(str::is_empty).unwrap_or(true)
    {
        return Err(VaultError::InvalidInput("secret value is required".into()));
    }
    Ok(())
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
}

fn parse_uuid(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| VaultError::InvalidInput("invalid UUID".into()))?;
    if id.to_string() != value.to_lowercase() {
        return Err(VaultError::InvalidInput("UUID is not canonical".into()));
    }
    Ok(id)
}

fn encode_cursor(cursor: &Cursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

fn decode_cursor(value: &str) -> Result<Cursor> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| VaultError::InvalidInput("invalid credential cursor".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidInput("invalid credential cursor".into()))
}

fn unix_timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Platform("system clock is before UNIX epoch".into()))?;
    i64::try_from(duration.as_secs()).map_err(|_| VaultError::Platform("system clock overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_input(password: &str) -> CredentialInput {
        CredentialInput {
            id: None,
            record_type: CredentialType::Login,
            title: "Example".into(),
            scope: CredentialScope::Project,
            project: Some("todo".into()),
            environment: Some("prod".into()),
            folder: Some("Infrastructure".into()),
            username: Some("person@example.com".into()),
            password: Some(password.into()),
            secret_value: None,
            websites: vec!["https://example.com".into()],
            notes: Some("recovery note".into()),
            totp_secret: None,
            custom_fields: vec![CredentialField {
                name: "tenant".into(),
                value: "north".into(),
                hidden: false,
            }],
            favorite: true,
        }
    }

    #[test]
    fn credential_records_keep_encrypted_history_and_custom_fields() {
        let directory = tempfile::tempdir().unwrap();
        let repository = CredentialRepository::new(directory.path().join("credentials.sqlite3")).unwrap();
        let key = [11_u8; 32];
        let saved = repository.save(&key, login_input("first-password")).unwrap();
        let id = Uuid::parse_str(&saved.id).unwrap();
        let detail = repository.detail(&key, id).unwrap();
        assert_eq!(detail.folder.as_deref(), Some("Infrastructure"));
        assert_eq!(detail.custom_fields[0].value, "north");

        let mut update = login_input("second-password");
        update.id = Some(saved.id.clone());
        let updated = repository.save(&key, update).unwrap();
        assert_eq!(updated.password_history.len(), 1);
        assert_eq!(updated.password_history[0].password, "first-password");

        let stored = fs::read(directory.path().join("credentials.sqlite3")).unwrap();
        assert!(!stored.windows(b"first-password".len()).any(|w| w == b"first-password"));
        assert!(!stored.windows(b"north".len()).any(|w| w == b"north"));
        assert!(matches!(
            repository.detail(&[12_u8; 32], id),
            Err(VaultError::AuthenticationFailed)
        ));
    }
}
