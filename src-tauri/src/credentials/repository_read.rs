impl CredentialRepository {
    pub fn detail(&self, root_key: &[u8; 32], id: Uuid) -> Result<CredentialDetail> {
        let connection = self.connection()?;
        let row = encrypted_row(&connection, id)?;
        decrypt_row(root_key, &row)
    }

    pub fn page(
        &self,
        root_key: &[u8; 32],
        cursor: Option<&str>,
        limit: u32,
        search: &str,
        project_filter: Option<&str>,
        environment_filter: Option<&str>,
    ) -> Result<CredentialPage> {
        let limit = limit.clamp(1, 500) as usize;
        let cursor = cursor.map(decode_cursor).transpose()?;
        let query = search.trim().to_lowercase();
        let project_filter = project_filter.map(str::trim).filter(|value| !value.is_empty());
        let environment_filter = environment_filter.map(str::trim).filter(|value| !value.is_empty());
        let connection = self.connection()?;

        if query.is_empty() && project_filter.is_none() && environment_filter.is_none() {
            let requested = limit.saturating_add(1);
            let mut summaries = Vec::with_capacity(requested);
            if let Some(cursor) = cursor.as_ref() {
                let mut statement = connection.prepare_cached(
                    "SELECT id, record_type, record_salt, nonce, ciphertext, format_version,
                            revision, created_at, updated_at
                     FROM credential_records
                     WHERE state = 1
                       AND (updated_at < ?1 OR (updated_at = ?1 AND id < ?2))
                     ORDER BY updated_at DESC, id DESC
                     LIMIT ?3",
                )?;
                let rows = statement.query_map(
                    params![cursor.updated_at, cursor.id.as_str(), requested as i64],
                    map_encrypted_row,
                )?;
                for row in rows {
                    summaries.push(summary_from_detail(decrypt_row(root_key, &row?)?));
                }
            } else {
                let mut statement = connection.prepare_cached(
                    "SELECT id, record_type, record_salt, nonce, ciphertext, format_version,
                            revision, created_at, updated_at
                     FROM credential_records
                     WHERE state = 1
                     ORDER BY updated_at DESC, id DESC
                     LIMIT ?1",
                )?;
                let rows = statement.query_map(params![requested as i64], map_encrypted_row)?;
                for row in rows {
                    summaries.push(summary_from_detail(decrypt_row(root_key, &row?)?));
                }
            }
            let has_more = summaries.len() > limit;
            summaries.truncate(limit);
            return page_from_summaries(summaries, has_more);
        }

        let mut statement = connection.prepare(
            "SELECT id, record_type, record_salt, nonce, ciphertext, format_version,
                    revision, created_at, updated_at
             FROM credential_records WHERE state = 1",
        )?;
        let rows = statement.query_map([], map_encrypted_row)?;
        let mut summaries = Vec::new();
        for row in rows {
            let detail = decrypt_row(root_key, &row?)?;
            let matches_search = query.is_empty()
                || detail.title.to_lowercase().contains(&query)
                || detail
                    .project
                    .as_deref()
                    .map(|value| value.to_lowercase().contains(&query))
                    .unwrap_or(false)
                || detail
                    .environment
                    .as_deref()
                    .map(|value| value.to_lowercase().contains(&query))
                    .unwrap_or(false)
                || detail
                    .username
                    .as_deref()
                    .map(|value| value.to_lowercase().contains(&query))
                    .unwrap_or(false)
                || detail.websites.iter().any(|value| value.to_lowercase().contains(&query));
            let matches_project = match project_filter {
                Some("__central__") => detail.scope == CredentialScope::Central,
                Some("__project__") => detail.scope == CredentialScope::Project,
                Some(project) => {
                    detail.scope == CredentialScope::Project
                        && detail
                            .project
                            .as_deref()
                            .map(|value| value.eq_ignore_ascii_case(project))
                            .unwrap_or(false)
                }
                None => true,
            };
            let matches_environment = environment_filter
                .map(|environment| {
                    detail
                        .environment
                        .as_deref()
                        .map(|value| value.eq_ignore_ascii_case(environment))
                        .unwrap_or(false)
                })
                .unwrap_or(true);
            if matches_search && matches_project && matches_environment {
                summaries.push(summary_from_detail(detail));
            }
        }
        summaries.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        if let Some(cursor) = cursor {
            summaries.retain(|item| {
                item.updated_at < cursor.updated_at
                    || (item.updated_at == cursor.updated_at && item.id < cursor.id)
            });
        }
        let has_more = summaries.len() > limit;
        summaries.truncate(limit);
        page_from_summaries(summaries, has_more)
    }

    pub fn delete(&self, id: Uuid) -> Result<()> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let changed = connection.execute(
            "DELETE FROM credential_records WHERE id = ?1",
            params![id.to_string()],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    pub fn field(
        &self,
        root_key: &[u8; 32],
        id: Uuid,
        field: &str,
    ) -> Result<Zeroizing<String>> {
        let detail = self.detail(root_key, id)?;
        let value = match field {
            "username" => detail.username.unwrap_or_default(),
            "password" => detail.password.unwrap_or_default(),
            "secret" => detail.secret_value.unwrap_or_default(),
            "notes" => detail.notes.unwrap_or_default(),
            _ => return Err(VaultError::InvalidInput("unsupported credential field".into())),
        };
        if value.is_empty() {
            return Err(VaultError::InvalidInput("credential field is empty".into()));
        }
        Ok(Zeroizing::new(value))
    }

    pub fn totp_secret(&self, root_key: &[u8; 32], id: Uuid) -> Result<Zeroizing<String>> {
        let detail = self.detail(root_key, id)?;
        if detail.record_type != CredentialType::Totp {
            return Err(VaultError::InvalidInput("credential is not a TOTP record".into()));
        }
        let secret = detail
            .totp_secret
            .filter(|value| !value.is_empty())
            .ok_or_else(|| VaultError::InvalidInput("TOTP record has no secret".into()))?;
        Ok(Zeroizing::new(secret))
    }

    fn initialize_schema(&self) -> Result<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS credential_records (
                id TEXT PRIMARY KEY NOT NULL,
                record_type INTEGER NOT NULL,
                record_salt BLOB NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                format_version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                state INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_credentials_updated_id
             ON credential_records(updated_at DESC, id DESC);",
        )?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.db_path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(connection)
    }
}
