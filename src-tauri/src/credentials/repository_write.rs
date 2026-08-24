impl CredentialRepository {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let repository = Self { db_path, writer: Mutex::new(()) };
        repository.initialize_schema()?;
        Ok(repository)
    }

    pub fn save(&self, root_key: &[u8; 32], input: CredentialInput) -> Result<CredentialDetail> {
        validate_input(&input)?;
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let now = unix_timestamp()?;
        let (id, created_at, revision, previous) = if let Some(id) = input.id.as_deref() {
            let id = parse_uuid(id)?;
            let row = encrypted_row(&connection, id)?;
            let previous = decrypt_row(root_key, &row)?;
            (id, row.created_at, row.revision.saturating_add(1), Some(previous))
        } else {
            (Uuid::new_v4(), now, 1, None)
        };

        let record_type = input.record_type;
        let scope = input.scope;
        let project = match scope {
            CredentialScope::Central => None,
            CredentialScope::Project => clean_optional(input.project),
        };
        let environment = clean_optional(input.environment);
        let folder = clean_optional(input.folder);
        let username = clean_optional(input.username);
        let password = input.password.filter(|value| !value.is_empty());
        let secret_value = input.secret_value.filter(|value| !value.is_empty());
        let websites: Vec<String> = input
            .websites
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect();
        let notes = input.notes.filter(|value| !value.is_empty());
        let totp_secret = clean_optional(input.totp_secret);
        let custom_fields: Vec<CredentialField> = input
            .custom_fields
            .into_iter()
            .map(|field| CredentialField {
                name: field.name.trim().to_owned(),
                value: field.value,
                hidden: field.hidden,
            })
            .filter(|field| !field.name.is_empty() || !field.value.is_empty())
            .collect();
        let (username, password, secret_value, websites, totp_secret) = match record_type {
            CredentialType::Login => (username, password, None, websites, None),
            CredentialType::SecureNote => (None, None, None, Vec::new(), None),
            CredentialType::Totp => (username, None, None, Vec::new(), totp_secret),
            CredentialType::Secret => (None, None, secret_value, Vec::new(), None),
        };

        let mut password_history = previous
            .as_ref()
            .map(|item| item.password_history.clone())
            .unwrap_or_default();
        if record_type == CredentialType::Login {
            if let Some(previous) = previous.as_ref() {
                if previous.record_type == CredentialType::Login && previous.password != password {
                    if let Some(old_password) = previous.password.as_ref().filter(|value| !value.is_empty()) {
                        password_history.insert(
                            0,
                            PasswordHistoryEntry { password: old_password.clone(), changed_at: now },
                        );
                    }
                }
            }
            password_history.truncate(MAX_PASSWORD_HISTORY);
        } else {
            password_history.clear();
        }

        let detail = CredentialDetail {
            id: id.to_string(),
            record_type,
            title: input.title.trim().to_owned(),
            scope,
            project,
            environment,
            folder,
            username,
            password,
            secret_value,
            websites,
            notes,
            totp_secret,
            custom_fields,
            password_history,
            favorite: input.favorite,
            created_at,
            updated_at: now,
        };
        let salt = random_array::<16>();
        let nonce = random_array::<12>();
        let key = record_key(root_key, &salt, id)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&detail)?);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &record_aad(id, detail.record_type, revision),
                },
            )
            .map_err(|_| VaultError::Crypto)?;

        connection.execute(
            "INSERT INTO credential_records (
                id, record_type, record_salt, nonce, ciphertext, format_version,
                revision, state, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                record_type = excluded.record_type,
                record_salt = excluded.record_salt,
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext,
                format_version = excluded.format_version,
                revision = excluded.revision,
                state = 1,
                updated_at = excluded.updated_at",
            params![
                id.to_string(),
                detail.record_type.as_i64(),
                salt.as_slice(),
                nonce.as_slice(),
                ciphertext,
                FORMAT_VERSION,
                revision,
                created_at,
                now,
            ],
        )?;
        Ok(detail)
    }
}
