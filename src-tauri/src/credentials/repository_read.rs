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
            return page_for_state(&connection, root_key, cursor.as_ref(), limit, 1);
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
                || detail.folder.as_deref().is_some_and(|value| value.to_lowercase().contains(&query))
                || detail.project.as_deref().is_some_and(|value| value.to_lowercase().contains(&query))
                || detail.environment.as_deref().is_some_and(|value| value.to_lowercase().contains(&query))
                || detail.username.as_deref().is_some_and(|value| value.to_lowercase().contains(&query))
                || detail.websites.iter().any(|value| value.to_lowercase().contains(&query))
                || detail.custom_fields.iter().any(|field| {
                    field.name.to_lowercase().contains(&query)
                        || (!field.hidden && field.value.to_lowercase().contains(&query))
                });
            let matches_project = match project_filter {
                Some("__central__") => detail.scope == CredentialScope::Central,
                Some("__project__") => detail.scope == CredentialScope::Project,
                Some(project) => detail.scope == CredentialScope::Project
                    && detail.project.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(project)),
                None => true,
            };
            let matches_environment = environment_filter
                .map(|environment| {
                    detail.environment.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(environment))
                })
                .unwrap_or(true);
            if matches_search && matches_project && matches_environment {
                summaries.push(summary_from_detail(detail));
            }
        }
        summaries.sort_by(|left, right| {
            right.updated_at.cmp(&left.updated_at).then_with(|| right.id.cmp(&left.id))
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

    pub fn trash_page(
        &self,
        root_key: &[u8; 32],
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<CredentialPage> {
        let limit = limit.clamp(1, 500) as usize;
        let cursor = cursor.map(decode_cursor).transpose()?;
        let connection = self.connection()?;
        page_for_state(&connection, root_key, cursor.as_ref(), limit, 0)
    }

    pub fn delete(&self, id: Uuid) -> Result<()> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let now = unix_timestamp()?;
        let changed = connection.execute(
            "UPDATE credential_records
             SET state = 0, updated_at = ?2
             WHERE id = ?1 AND state = 1",
            params![id.to_string(), now],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    pub fn restore(&self, id: Uuid) -> Result<()> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let now = unix_timestamp()?;
        let changed = connection.execute(
            "UPDATE credential_records
             SET state = 1, updated_at = ?2
             WHERE id = ?1 AND state = 0",
            params![id.to_string(), now],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    pub fn purge(&self, id: Uuid) -> Result<()> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let changed = connection.execute(
            "DELETE FROM credential_records WHERE id = ?1 AND state = 0",
            params![id.to_string()],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    pub fn empty_trash(&self) -> Result<usize> {
        let _writer = self.writer.lock();
        let connection = self.connection()?;
        let deleted = connection.execute("DELETE FROM credential_records WHERE state = 0", [])?;
        Ok(deleted)
    }

    pub fn field(&self, root_key: &[u8; 32], id: Uuid, field: &str) -> Result<Zeroizing<String>> {
        let detail = self.detail(root_key, id)?;
        let value = match field {
            "username" => detail.username.unwrap_or_default(),
            "password" => detail.password.unwrap_or_default(),
            "secret" => detail.secret_value.unwrap_or_default(),
            "notes" => detail.notes.unwrap_or_default(),
            _ if field.starts_with("custom:") => {
                let index = field[7..]
                    .parse::<usize>()
                    .map_err(|_| VaultError::InvalidInput("invalid custom field index".into()))?;
                detail
                    .custom_fields
                    .get(index)
                    .map(|item| item.value.clone())
                    .ok_or_else(|| VaultError::InvalidInput("custom field not found".into()))?
            }
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
             ON credential_records(updated_at DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_credentials_state_updated_id
             ON credential_records(state, updated_at DESC, id DESC);",
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

fn page_for_state(
    connection: &Connection,
    root_key: &[u8; 32],
    cursor: Option<&Cursor>,
    limit: usize,
    state: i64,
) -> Result<CredentialPage> {
    let requested = limit.saturating_add(1);
    let mut summaries = Vec::with_capacity(requested);
    if let Some(cursor) = cursor {
        let mut statement = connection.prepare_cached(
            "SELECT id, record_type, record_salt, nonce, ciphertext, format_version,
                    revision, created_at, updated_at
             FROM credential_records
             WHERE state = ?1
               AND (updated_at < ?2 OR (updated_at = ?2 AND id < ?3))
             ORDER BY updated_at DESC, id DESC
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![state, cursor.updated_at, cursor.id.as_str(), requested as i64],
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
             WHERE state = ?1
             ORDER BY updated_at DESC, id DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![state, requested as i64], map_encrypted_row)?;
        for row in rows {
            summaries.push(summary_from_detail(decrypt_row(root_key, &row?)?));
        }
    }
    let has_more = summaries.len() > limit;
    summaries.truncate(limit);
    page_from_summaries(summaries, has_more)
}

#[cfg(test)]
mod trash_tests {
    use super::*;

    fn input() -> CredentialInput {
        CredentialInput {
            id: None,
            record_type: CredentialType::Login,
            title: "Trash test".into(),
            scope: CredentialScope::Central,
            project: None,
            environment: None,
            folder: None,
            username: Some("person@example.com".into()),
            password: Some("correct-horse-battery-staple".into()),
            secret_value: None,
            websites: vec!["https://example.com".into()],
            notes: None,
            totp_secret: None,
            custom_fields: Vec::new(),
            favorite: false,
        }
    }

    #[test]
    fn delete_moves_record_to_encrypted_trash_and_restore_returns_it() {
        let directory = tempfile::tempdir().unwrap();
        let repository = CredentialRepository::new(directory.path().join("credentials.sqlite3")).unwrap();
        let key = [23_u8; 32];
        let saved = repository.save(&key, input()).unwrap();
        let id = Uuid::parse_str(&saved.id).unwrap();

        repository.delete(id).unwrap();
        assert!(matches!(repository.detail(&key, id), Err(VaultError::NotFound)));
        let trash = repository.trash_page(&key, None, 10).unwrap();
        assert_eq!(trash.items.len(), 1);
        assert_eq!(trash.items[0].id, saved.id);

        repository.restore(id).unwrap();
        assert_eq!(repository.detail(&key, id).unwrap().title, "Trash test");
        assert!(repository.trash_page(&key, None, 10).unwrap().items.is_empty());
    }

    #[test]
    fn purge_only_removes_records_already_in_trash() {
        let directory = tempfile::tempdir().unwrap();
        let repository = CredentialRepository::new(directory.path().join("credentials.sqlite3")).unwrap();
        let key = [29_u8; 32];
        let saved = repository.save(&key, input()).unwrap();
        let id = Uuid::parse_str(&saved.id).unwrap();

        assert!(matches!(repository.purge(id), Err(VaultError::NotFound)));
        repository.delete(id).unwrap();
        repository.purge(id).unwrap();
        assert!(repository.trash_page(&key, None, 10).unwrap().items.is_empty());
    }
}
