use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    crypto::{derive_domain_key, random_array},
    error::{Result, VaultError},
};

const HEADER_VERSION: u16 = 3;
const PREVIOUS_HEADER_VERSION: u16 = 2;
const LEGACY_HEADER_VERSION: u16 = 1;
const LEGACY_VERIFIER_PLAINTEXT: &[u8] = b"ND_SECURE_MASTER_KEY_VERIFIER_V1";
const ROOT_VERIFIER_PLAINTEXT: &[u8] = b"ND_SECURE_VAULT_ROOT_VERIFIER_V1";
const LEGACY_VERIFIER_AAD: &[u8] = b"kh.zila.ndsecure/header/verifier/v1";
const V2_VERIFIER_AAD_DOMAIN: &[u8] = b"kh.zila.ndsecure/header/verifier/v2";
const V3_VERIFIER_AAD_DOMAIN: &[u8] = b"kh.zila.ndsecure/header/verifier/v3";
const ROOT_WRAP_AAD_DOMAIN: &[u8] = b"kh.zila.ndsecure/header/root-wrap/v1";
const PASSWORD_WRAP_KEY_DOMAIN: &[u8] = b"nd-secure/password-wrap-key/v1";
const RECOVERY_WRAP_KEY_DOMAIN: &[u8] = b"nd-secure/recovery-wrap-key/v1";
const RECOVERY_WRAP_AAD_DOMAIN: &[u8] = b"kh.zila.ndsecure/header/recovery-wrap/v1";
const RECOVERY_PREFIX: &str = "NDSECURE-R1-";
const MIN_PASSWORD_CHARS: usize = 12;
const DEFAULT_AUTO_LOCK_SECONDS: u64 = 300;
const MIN_AUTO_LOCK_SECONDS: u64 = 60;
const MAX_AUTO_LOCK_SECONDS: u64 = 86_400;
const DEFAULT_CLIPBOARD_TIMEOUT_SECONDS: u64 = 30;
const MIN_CLIPBOARD_TIMEOUT_SECONDS: u64 = 5;
const MAX_CLIPBOARD_TIMEOUT_SECONDS: u64 = 300;
const REAUTH_WINDOW_SECONDS: u64 = 120;
const DEFAULT_ARGON_MEMORY_KIB: u32 = 65_536;
const DEFAULT_ARGON_ITERATIONS: u32 = 3;
const DEFAULT_ARGON_PARALLELISM: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultHeader {
    version: u16,
    salt: String,
    argon_memory_kib: u32,
    argon_iterations: u32,
    argon_parallelism: u32,
    verifier_nonce: String,
    verifier_ciphertext: String,
    auto_lock_seconds: u64,
    #[serde(default)]
    delete_source_after_import: bool,
    #[serde(default)]
    vault_id: String,
    #[serde(default)]
    wrapped_root_nonce: String,
    #[serde(default)]
    wrapped_root_ciphertext: String,
    #[serde(default)]
    recovery_nonce: String,
    #[serde(default)]
    recovery_ciphertext: String,
    #[serde(default)]
    lock_on_blur: bool,
    #[serde(default = "default_true")]
    lock_on_suspend: bool,
    #[serde(default = "default_clipboard_timeout")]
    clipboard_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatus {
    pub initialized: bool,
    pub locked: bool,
    pub auto_lock_seconds: u64,
    pub delete_source_after_import: bool,
    pub lock_on_blur: bool,
    pub lock_on_suspend: bool,
    pub clipboard_timeout_seconds: u64,
    pub recovery_configured: bool,
    pub recently_reauthenticated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKey {
    pub recovery_key: String,
}

struct UnlockedSession {
    root_key: Zeroizing<[u8; 32]>,
    last_activity: Instant,
    reauthenticated_at: Option<Instant>,
}

struct SessionInner {
    unlocked: Option<UnlockedSession>,
    auto_lock_seconds: u64,
    delete_source_after_import: bool,
    lock_on_blur: bool,
    lock_on_suspend: bool,
    clipboard_timeout_seconds: u64,
    recovery_configured: bool,
}

struct AttemptState {
    failed: u32,
    blocked_until: Option<Instant>,
}

pub struct SessionState {
    header_path: PathBuf,
    lifecycle: Mutex<()>,
    inner: Mutex<SessionInner>,
    attempts: Mutex<AttemptState>,
}

impl SessionState {
    pub fn new(header_path: PathBuf) -> Self {
        recover_header(&header_path);
        let existing = read_header(&header_path);
        let auto_lock_seconds = existing
            .as_ref()
            .map(|header| header.auto_lock_seconds)
            .unwrap_or(DEFAULT_AUTO_LOCK_SECONDS)
            .clamp(MIN_AUTO_LOCK_SECONDS, MAX_AUTO_LOCK_SECONDS);
        let delete_source_after_import = existing
            .as_ref()
            .filter(|header| header.version >= PREVIOUS_HEADER_VERSION)
            .map(|header| header.delete_source_after_import)
            .unwrap_or(false);
        let lock_on_blur = existing.as_ref().map(|header| header.lock_on_blur).unwrap_or(false);
        let lock_on_suspend = existing.as_ref().map(|header| header.lock_on_suspend).unwrap_or(true);
        let clipboard_timeout_seconds = existing
            .as_ref()
            .map(|header| header.clipboard_timeout_seconds)
            .unwrap_or(DEFAULT_CLIPBOARD_TIMEOUT_SECONDS)
            .clamp(MIN_CLIPBOARD_TIMEOUT_SECONDS, MAX_CLIPBOARD_TIMEOUT_SECONDS);
        let recovery_configured = existing.as_ref().is_some_and(recovery_is_configured);
        Self {
            header_path,
            lifecycle: Mutex::new(()),
            inner: Mutex::new(SessionInner {
                unlocked: None,
                auto_lock_seconds,
                delete_source_after_import,
                lock_on_blur,
                lock_on_suspend,
                clipboard_timeout_seconds,
                recovery_configured,
            }),
            attempts: Mutex::new(AttemptState { failed: 0, blocked_until: None }),
        }
    }

    pub fn status(&self) -> SessionStatus {
        self.expire_if_idle();
        let inner = self.inner.lock();
        let recently_reauthenticated = inner
            .unlocked
            .as_ref()
            .and_then(|session| session.reauthenticated_at)
            .is_some_and(|instant| instant.elapsed() < Duration::from_secs(REAUTH_WINDOW_SECONDS));
        SessionStatus {
            initialized: self.header_path.is_file(),
            locked: inner.unlocked.is_none(),
            auto_lock_seconds: inner.auto_lock_seconds,
            delete_source_after_import: inner.delete_source_after_import,
            lock_on_blur: inner.lock_on_blur,
            lock_on_suspend: inner.lock_on_suspend,
            clipboard_timeout_seconds: inner.clipboard_timeout_seconds,
            recovery_configured: inner.recovery_configured,
            recently_reauthenticated,
        }
    }

    pub fn initialize(&self, password: Zeroizing<String>, auto_lock_seconds: u64) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        if self.header_path.exists() {
            return Err(VaultError::AlreadyInitialized);
        }
        validate_password(&password)?;
        let auto_lock_seconds = auto_lock_seconds.clamp(MIN_AUTO_LOCK_SECONDS, MAX_AUTO_LOCK_SECONDS);
        let salt = random_array::<16>();
        let password_key = derive_password_key(
            &password,
            &salt,
            DEFAULT_ARGON_MEMORY_KIB,
            DEFAULT_ARGON_ITERATIONS,
            DEFAULT_ARGON_PARALLELISM,
        )?;
        let root_key = Zeroizing::new(random_array::<32>());
        let mut header = VaultHeader {
            version: HEADER_VERSION,
            salt: BASE64.encode(salt),
            argon_memory_kib: DEFAULT_ARGON_MEMORY_KIB,
            argon_iterations: DEFAULT_ARGON_ITERATIONS,
            argon_parallelism: DEFAULT_ARGON_PARALLELISM,
            verifier_nonce: String::new(),
            verifier_ciphertext: String::new(),
            auto_lock_seconds,
            delete_source_after_import: false,
            vault_id: URL_SAFE_NO_PAD.encode(random_array::<16>()),
            wrapped_root_nonce: String::new(),
            wrapped_root_ciphertext: String::new(),
            recovery_nonce: String::new(),
            recovery_ciphertext: String::new(),
            lock_on_blur: false,
            lock_on_suspend: true,
            clipboard_timeout_seconds: DEFAULT_CLIPBOARD_TIMEOUT_SECONDS,
        };
        wrap_root_key(&mut header, &password_key, &root_key)?;
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;

        self.apply_header_to_inner(
            &header,
            Some(UnlockedSession {
                root_key,
                last_activity: Instant::now(),
                reauthenticated_at: Some(Instant::now()),
            }),
        );
        Ok(self.status())
    }

    pub fn unlock(&self, password: Zeroizing<String>) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        self.check_attempt_limit()?;
        let mut header = read_header(&self.header_path).ok_or(VaultError::NotInitialized)?;
        validate_header(&header)?;
        let salt = decode_array::<16>(&header.salt)?;
        let password_key = derive_password_key(
            &password,
            &salt,
            header.argon_memory_kib,
            header.argon_iterations,
            header.argon_parallelism,
        )?;

        let root_key = if header.version == HEADER_VERSION {
            match unwrap_root_key(&header, &password_key) {
                Ok(root_key) => root_key,
                Err(_) => {
                    self.record_failed_attempt();
                    return Err(VaultError::InvalidPassword);
                }
            }
        } else {
            if !verify_legacy_verifier(&header, &password_key)? {
                self.record_failed_attempt();
                return Err(VaultError::InvalidPassword);
            }
            let root_key = Zeroizing::new(*password_key);
            migrate_header_to_v3(&mut header, &password_key, &root_key)?;
            write_header(&self.header_path, &header)?;
            root_key
        };

        if !verify_root_verifier(&header, &root_key)? {
            return Err(VaultError::AuthenticationFailed);
        }
        self.reset_attempts();
        self.apply_header_to_inner(
            &header,
            Some(UnlockedSession {
                root_key,
                last_activity: Instant::now(),
                reauthenticated_at: Some(Instant::now()),
            }),
        );
        Ok(self.status())
    }

    pub fn reauthenticate(&self, password: Zeroizing<String>) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        self.check_attempt_limit()?;
        let current_root = self.root_key_copy()?;
        let header = read_header(&self.header_path).ok_or(VaultError::NotInitialized)?;
        validate_header(&header)?;
        if header.version != HEADER_VERSION {
            return Err(VaultError::AuthenticationFailed);
        }
        let salt = decode_array::<16>(&header.salt)?;
        let password_key = derive_password_key(
            &password,
            &salt,
            header.argon_memory_kib,
            header.argon_iterations,
            header.argon_parallelism,
        )?;
        let candidate_root = match unwrap_root_key(&header, &password_key) {
            Ok(root_key) => root_key,
            Err(_) => {
                self.record_failed_attempt();
                return Err(VaultError::InvalidPassword);
            }
        };
        if !bool::from(candidate_root.as_ref().ct_eq(current_root.as_ref())) {
            self.record_failed_attempt();
            return Err(VaultError::InvalidPassword);
        }
        if !verify_root_verifier(&header, &candidate_root)? {
            return Err(VaultError::AuthenticationFailed);
        }
        self.reset_attempts();
        let mut inner = self.inner.lock();
        let unlocked = inner.unlocked.as_mut().ok_or(VaultError::Locked)?;
        unlocked.last_activity = Instant::now();
        unlocked.reauthenticated_at = Some(Instant::now());
        drop(inner);
        Ok(self.status())
    }

    pub fn change_master_password(
        &self,
        current_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        validate_password(&new_password)?;
        let root_key = self.root_key_copy()?;
        let mut header = self.authenticated_header(&root_key)?;
        self.authenticate_current_password(&header, &current_password, &root_key)?;

        let salt = random_array::<16>();
        header.salt = BASE64.encode(salt);
        header.argon_memory_kib = DEFAULT_ARGON_MEMORY_KIB;
        header.argon_iterations = DEFAULT_ARGON_ITERATIONS;
        header.argon_parallelism = DEFAULT_ARGON_PARALLELISM;
        let new_password_key = derive_password_key(
            &new_password,
            &salt,
            header.argon_memory_kib,
            header.argon_iterations,
            header.argon_parallelism,
        )?;
        wrap_root_key(&mut header, &new_password_key, &root_key)?;
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;
        self.reset_attempts();

        let mut inner = self.inner.lock();
        let unlocked = inner.unlocked.as_mut().ok_or(VaultError::Locked)?;
        unlocked.last_activity = Instant::now();
        unlocked.reauthenticated_at = Some(Instant::now());
        drop(inner);
        Ok(self.status())
    }

    pub fn create_recovery_key(&self, password: Zeroizing<String>) -> Result<RecoveryKey> {
        let _lifecycle = self.lifecycle.lock();
        let root_key = self.root_key_copy()?;
        let mut header = self.authenticated_header(&root_key)?;
        self.authenticate_current_password(&header, &password, &root_key)?;

        let recovery_key = Zeroizing::new(random_array::<32>());
        let nonce = random_array::<12>();
        let recovery_wrap_key = derive_domain_key(&recovery_key, RECOVERY_WRAP_KEY_DOMAIN)?;
        let cipher = Aes256Gcm::new_from_slice(recovery_wrap_key.as_ref()).map_err(|_| VaultError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: root_key.as_ref(), aad: &recovery_wrap_aad(&header)? },
            )
            .map_err(|_| VaultError::Crypto)?;
        header.recovery_nonce = BASE64.encode(nonce);
        header.recovery_ciphertext = BASE64.encode(ciphertext);
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;

        let mut inner = self.inner.lock();
        inner.recovery_configured = true;
        if let Some(unlocked) = inner.unlocked.as_mut() {
            unlocked.last_activity = Instant::now();
            unlocked.reauthenticated_at = Some(Instant::now());
        }
        drop(inner);
        Ok(RecoveryKey {
            recovery_key: format!("{RECOVERY_PREFIX}{}", URL_SAFE_NO_PAD.encode(recovery_key.as_ref())),
        })
    }

    pub fn disable_recovery(&self, password: Zeroizing<String>) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        let root_key = self.root_key_copy()?;
        let mut header = self.authenticated_header(&root_key)?;
        self.authenticate_current_password(&header, &password, &root_key)?;
        header.recovery_nonce.clear();
        header.recovery_ciphertext.clear();
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;

        let mut inner = self.inner.lock();
        inner.recovery_configured = false;
        if let Some(unlocked) = inner.unlocked.as_mut() {
            unlocked.last_activity = Instant::now();
            unlocked.reauthenticated_at = Some(Instant::now());
        }
        drop(inner);
        Ok(self.status())
    }

    pub fn recover_with_key(
        &self,
        recovery_key: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        validate_password(&new_password)?;
        let mut header = read_header(&self.header_path).ok_or(VaultError::NotInitialized)?;
        validate_header(&header)?;
        if header.version != HEADER_VERSION || !recovery_is_configured(&header) {
            return Err(VaultError::InvalidInput("vault recovery is not configured".into()));
        }
        let recovery_key = decode_recovery_key(&recovery_key)?;
        let root_key = unwrap_recovery_root(&header, &recovery_key)?;
        if !verify_root_verifier(&header, &root_key)? {
            return Err(VaultError::AuthenticationFailed);
        }

        let salt = random_array::<16>();
        header.salt = BASE64.encode(salt);
        header.argon_memory_kib = DEFAULT_ARGON_MEMORY_KIB;
        header.argon_iterations = DEFAULT_ARGON_ITERATIONS;
        header.argon_parallelism = DEFAULT_ARGON_PARALLELISM;
        let password_key = derive_password_key(
            &new_password,
            &salt,
            header.argon_memory_kib,
            header.argon_iterations,
            header.argon_parallelism,
        )?;
        wrap_root_key(&mut header, &password_key, &root_key)?;
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;
        self.reset_attempts();
        self.apply_header_to_inner(
            &header,
            Some(UnlockedSession { root_key, last_activity: Instant::now(), reauthenticated_at: None }),
        );
        Ok(self.status())
    }

    pub fn lock(&self) -> SessionStatus {
        let _lifecycle = self.lifecycle.lock();
        self.inner.lock().unlocked = None;
        self.status()
    }

    pub fn set_auto_lock(&self, seconds: u64) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        if !(MIN_AUTO_LOCK_SECONDS..=MAX_AUTO_LOCK_SECONDS).contains(&seconds) {
            return Err(VaultError::InvalidInput("auto-lock must be between 60 and 86400 seconds".into()));
        }
        let root_key = self.root_key_copy()?;
        let mut header = self.authenticated_header(&root_key)?;
        header.auto_lock_seconds = seconds;
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;
        self.inner.lock().auto_lock_seconds = seconds;
        Ok(self.status())
    }

    pub fn set_delete_source_after_import(&self, enabled: bool) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        let root_key = self.root_key_copy()?;
        let mut header = self.authenticated_header(&root_key)?;
        header.delete_source_after_import = enabled;
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;
        self.inner.lock().delete_source_after_import = enabled;
        Ok(self.status())
    }

    pub fn set_security_preferences(
        &self,
        lock_on_blur: bool,
        lock_on_suspend: bool,
        clipboard_timeout_seconds: u64,
    ) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        if !(MIN_CLIPBOARD_TIMEOUT_SECONDS..=MAX_CLIPBOARD_TIMEOUT_SECONDS)
            .contains(&clipboard_timeout_seconds)
        {
            return Err(VaultError::InvalidInput(
                "clipboard timeout must be between 5 and 300 seconds".into(),
            ));
        }
        let root_key = self.root_key_copy()?;
        let mut header = self.authenticated_header(&root_key)?;
        header.lock_on_blur = lock_on_blur;
        header.lock_on_suspend = lock_on_suspend;
        header.clipboard_timeout_seconds = clipboard_timeout_seconds;
        seal_root_verifier(&mut header, &root_key)?;
        write_header(&self.header_path, &header)?;

        let mut inner = self.inner.lock();
        inner.lock_on_blur = lock_on_blur;
        inner.lock_on_suspend = lock_on_suspend;
        inner.clipboard_timeout_seconds = clipboard_timeout_seconds;
        drop(inner);
        Ok(self.status())
    }

    pub fn delete_source_after_import(&self) -> Result<bool> {
        self.touch()?;
        Ok(self.inner.lock().delete_source_after_import)
    }

    pub fn lock_on_blur(&self) -> bool {
        self.inner.lock().lock_on_blur
    }

    #[cfg(mobile)]
    pub fn lock_on_suspend(&self) -> bool {
        self.inner.lock().lock_on_suspend
    }

    pub fn clipboard_timeout_seconds(&self) -> u64 {
        self.inner.lock().clipboard_timeout_seconds
    }

    pub fn require_recent_reauthentication(&self) -> Result<()> {
        self.expire_if_idle();
        let mut inner = self.inner.lock();
        let unlocked = inner.unlocked.as_mut().ok_or(VaultError::Locked)?;
        let valid = unlocked
            .reauthenticated_at
            .is_some_and(|instant| instant.elapsed() < Duration::from_secs(REAUTH_WINDOW_SECONDS));
        if !valid {
            return Err(VaultError::InvalidInput(
                "master-password confirmation is required for this action".into(),
            ));
        }
        unlocked.last_activity = Instant::now();
        Ok(())
    }

    pub fn touch(&self) -> Result<()> {
        self.expire_if_idle();
        let mut inner = self.inner.lock();
        let unlocked = inner.unlocked.as_mut().ok_or(VaultError::Locked)?;
        unlocked.last_activity = Instant::now();
        Ok(())
    }

    pub fn domain_key(&self, domain: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.expire_if_idle();
        let mut inner = self.inner.lock();
        let unlocked = inner.unlocked.as_mut().ok_or(VaultError::Locked)?;
        let key = derive_domain_key(&unlocked.root_key, domain)?;
        unlocked.last_activity = Instant::now();
        Ok(key)
    }

    fn root_key_copy(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.expire_if_idle();
        let mut inner = self.inner.lock();
        let unlocked = inner.unlocked.as_mut().ok_or(VaultError::Locked)?;
        unlocked.last_activity = Instant::now();
        Ok(Zeroizing::new(*unlocked.root_key))
    }

    fn authenticate_current_password(
        &self,
        header: &VaultHeader,
        password: &str,
        expected_root: &[u8; 32],
    ) -> Result<()> {
        self.check_attempt_limit()?;
        match authenticate_password(header, password, expected_root) {
            Ok(()) => {
                self.reset_attempts();
                Ok(())
            }
            Err(VaultError::InvalidPassword) => {
                self.record_failed_attempt();
                Err(VaultError::InvalidPassword)
            }
            Err(error) => Err(error),
        }
    }

    fn authenticated_header(&self, root_key: &[u8; 32]) -> Result<VaultHeader> {
        let header = read_header(&self.header_path).ok_or(VaultError::NotInitialized)?;
        validate_header(&header)?;
        if header.version != HEADER_VERSION || !verify_root_verifier(&header, root_key)? {
            return Err(VaultError::AuthenticationFailed);
        }
        Ok(header)
    }

    fn apply_header_to_inner(&self, header: &VaultHeader, unlocked: Option<UnlockedSession>) {
        let mut inner = self.inner.lock();
        inner.auto_lock_seconds = header.auto_lock_seconds;
        inner.delete_source_after_import = header.delete_source_after_import;
        inner.lock_on_blur = header.lock_on_blur;
        inner.lock_on_suspend = header.lock_on_suspend;
        inner.clipboard_timeout_seconds = header.clipboard_timeout_seconds;
        inner.recovery_configured = recovery_is_configured(header);
        inner.unlocked = unlocked;
    }

    fn expire_if_idle(&self) {
        let mut inner = self.inner.lock();
        let should_expire = inner
            .unlocked
            .as_ref()
            .map(|session| {
                session.last_activity.elapsed()
                    >= Duration::from_secs(inner.auto_lock_seconds.max(MIN_AUTO_LOCK_SECONDS))
            })
            .unwrap_or(false);
        if should_expire {
            inner.unlocked = None;
        }
    }

    fn check_attempt_limit(&self) -> Result<()> {
        let attempts = self.attempts.lock();
        if attempts.blocked_until.is_some_and(|deadline| deadline > Instant::now()) {
            return Err(VaultError::RateLimited);
        }
        Ok(())
    }

    fn record_failed_attempt(&self) {
        let mut attempts = self.attempts.lock();
        attempts.failed = attempts.failed.saturating_add(1);
        let shift = attempts.failed.saturating_sub(1).min(5);
        let seconds = (1_u64 << shift).min(30);
        attempts.blocked_until = Some(Instant::now() + Duration::from_secs(seconds));
    }

    fn reset_attempts(&self) {
        let mut attempts = self.attempts.lock();
        attempts.failed = 0;
        attempts.blocked_until = None;
    }
}

fn default_true() -> bool {
    true
}

fn default_clipboard_timeout() -> u64 {
    DEFAULT_CLIPBOARD_TIMEOUT_SECONDS
}

fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword);
    }
    Ok(())
}

fn validate_header(header: &VaultHeader) -> Result<()> {
    if !matches!(header.version, LEGACY_HEADER_VERSION | PREVIOUS_HEADER_VERSION | HEADER_VERSION)
        || !(32_768..=1_048_576).contains(&header.argon_memory_kib)
        || !(1..=10).contains(&header.argon_iterations)
        || !(1..=16).contains(&header.argon_parallelism)
        || !(MIN_AUTO_LOCK_SECONDS..=MAX_AUTO_LOCK_SECONDS).contains(&header.auto_lock_seconds)
    {
        return Err(VaultError::InvalidInput("invalid vault header parameters".into()));
    }
    if header.version == HEADER_VERSION
        && (header.vault_id.is_empty()
            || header.wrapped_root_nonce.is_empty()
            || header.wrapped_root_ciphertext.is_empty()
            || !(MIN_CLIPBOARD_TIMEOUT_SECONDS..=MAX_CLIPBOARD_TIMEOUT_SECONDS)
                .contains(&header.clipboard_timeout_seconds))
    {
        return Err(VaultError::InvalidInput("invalid vault envelope parameters".into()));
    }
    Ok(())
}

fn migrate_header_to_v3(
    header: &mut VaultHeader,
    password_key: &[u8; 32],
    root_key: &[u8; 32],
) -> Result<()> {
    if header.version == LEGACY_HEADER_VERSION {
        header.delete_source_after_import = false;
    }
    header.version = HEADER_VERSION;
    header.vault_id = URL_SAFE_NO_PAD.encode(random_array::<16>());
    header.wrapped_root_nonce.clear();
    header.wrapped_root_ciphertext.clear();
    header.recovery_nonce.clear();
    header.recovery_ciphertext.clear();
    header.lock_on_blur = false;
    header.lock_on_suspend = true;
    header.clipboard_timeout_seconds = DEFAULT_CLIPBOARD_TIMEOUT_SECONDS;
    wrap_root_key(header, password_key, root_key)?;
    seal_root_verifier(header, root_key)
}

fn authenticate_password(header: &VaultHeader, password: &str, expected_root: &[u8; 32]) -> Result<()> {
    let salt = decode_array::<16>(&header.salt)?;
    let password_key = derive_password_key(
        password,
        &salt,
        header.argon_memory_kib,
        header.argon_iterations,
        header.argon_parallelism,
    )?;
    let root_key = unwrap_root_key(header, &password_key).map_err(|_| VaultError::InvalidPassword)?;
    if !bool::from(root_key.as_ref().ct_eq(expected_root)) {
        return Err(VaultError::InvalidPassword);
    }
    if !verify_root_verifier(header, &root_key)? {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(())
}

fn wrap_root_key(header: &mut VaultHeader, password_key: &[u8; 32], root_key: &[u8; 32]) -> Result<()> {
    let nonce = random_array::<12>();
    let wrap_key = derive_domain_key(password_key, PASSWORD_WRAP_KEY_DOMAIN)?;
    let cipher = Aes256Gcm::new_from_slice(wrap_key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: root_key, aad: &root_wrap_aad(header)? })
        .map_err(|_| VaultError::Crypto)?;
    header.wrapped_root_nonce = BASE64.encode(nonce);
    header.wrapped_root_ciphertext = BASE64.encode(ciphertext);
    Ok(())
}

fn unwrap_root_key(header: &VaultHeader, password_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let nonce = decode_array::<12>(&header.wrapped_root_nonce)?;
    let ciphertext = BASE64
        .decode(header.wrapped_root_ciphertext.as_bytes())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let wrap_key = derive_domain_key(password_key, PASSWORD_WRAP_KEY_DOMAIN)?;
    let cipher = Aes256Gcm::new_from_slice(wrap_key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &root_wrap_aad(header)? })
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );
    let root: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(Zeroizing::new(root))
}

fn unwrap_recovery_root(header: &VaultHeader, recovery_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let nonce = decode_array::<12>(&header.recovery_nonce)?;
    let ciphertext = BASE64
        .decode(header.recovery_ciphertext.as_bytes())
        .map_err(|_| VaultError::InvalidInput("invalid recovery envelope".into()))?;
    let recovery_wrap_key = derive_domain_key(recovery_key, RECOVERY_WRAP_KEY_DOMAIN)?;
    let cipher = Aes256Gcm::new_from_slice(recovery_wrap_key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: &ciphertext, aad: &recovery_wrap_aad(header)? },
            )
            .map_err(|_| VaultError::InvalidPassword)?,
    );
    let root: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(Zeroizing::new(root))
}

fn seal_root_verifier(header: &mut VaultHeader, root_key: &[u8; 32]) -> Result<()> {
    let nonce = random_array::<12>();
    header.verifier_nonce = BASE64.encode(nonce);
    let aad = root_verifier_aad(header)?;
    let cipher = Aes256Gcm::new_from_slice(root_key).map_err(|_| VaultError::Crypto)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: ROOT_VERIFIER_PLAINTEXT, aad: &aad })
        .map_err(|_| VaultError::Crypto)?;
    header.verifier_ciphertext = BASE64.encode(ciphertext);
    Ok(())
}

fn verify_root_verifier(header: &VaultHeader, root_key: &[u8; 32]) -> Result<bool> {
    let nonce = decode_array::<12>(&header.verifier_nonce)?;
    let ciphertext =
        BASE64.decode(header.verifier_ciphertext.as_bytes()).map_err(|_| VaultError::AuthenticationFailed)?;
    let aad = root_verifier_aad(header)?;
    let cipher = Aes256Gcm::new_from_slice(root_key).map_err(|_| VaultError::Crypto)?;
    let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &aad });
    let valid = plaintext
        .as_ref()
        .map(|value| bool::from(value.as_slice().ct_eq(ROOT_VERIFIER_PLAINTEXT)))
        .unwrap_or(false);
    let mut plaintext = Zeroizing::new(plaintext.unwrap_or_default());
    plaintext.clear();
    Ok(valid)
}

fn verify_legacy_verifier(header: &VaultHeader, password_key: &[u8; 32]) -> Result<bool> {
    let nonce = decode_array::<12>(&header.verifier_nonce)?;
    let ciphertext =
        BASE64.decode(header.verifier_ciphertext.as_bytes()).map_err(|_| VaultError::InvalidPassword)?;
    let aad = legacy_verifier_aad(header)?;
    let cipher = Aes256Gcm::new_from_slice(password_key).map_err(|_| VaultError::Crypto)?;
    let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &aad });
    let valid = plaintext
        .as_ref()
        .map(|value| bool::from(value.as_slice().ct_eq(LEGACY_VERIFIER_PLAINTEXT)))
        .unwrap_or(false);
    let mut plaintext = Zeroizing::new(plaintext.unwrap_or_default());
    plaintext.clear();
    Ok(valid)
}

fn legacy_verifier_aad(header: &VaultHeader) -> Result<Vec<u8>> {
    match header.version {
        LEGACY_HEADER_VERSION => Ok(LEGACY_VERIFIER_AAD.to_vec()),
        PREVIOUS_HEADER_VERSION => {
            let mut aad = Vec::with_capacity(V2_VERIFIER_AAD_DOMAIN.len() + 64);
            aad.extend_from_slice(V2_VERIFIER_AAD_DOMAIN);
            aad.extend_from_slice(&header.version.to_be_bytes());
            append_aad_field(&mut aad, header.salt.as_bytes())?;
            aad.extend_from_slice(&header.argon_memory_kib.to_be_bytes());
            aad.extend_from_slice(&header.argon_iterations.to_be_bytes());
            aad.extend_from_slice(&header.argon_parallelism.to_be_bytes());
            aad.extend_from_slice(&header.auto_lock_seconds.to_be_bytes());
            aad.push(u8::from(header.delete_source_after_import));
            Ok(aad)
        }
        _ => Err(VaultError::InvalidInput("unsupported legacy vault header version".into())),
    }
}

fn root_wrap_aad(header: &VaultHeader) -> Result<Vec<u8>> {
    let mut aad = Vec::with_capacity(ROOT_WRAP_AAD_DOMAIN.len() + 96);
    aad.extend_from_slice(ROOT_WRAP_AAD_DOMAIN);
    aad.extend_from_slice(&header.version.to_be_bytes());
    append_aad_field(&mut aad, header.vault_id.as_bytes())?;
    append_aad_field(&mut aad, header.salt.as_bytes())?;
    aad.extend_from_slice(&header.argon_memory_kib.to_be_bytes());
    aad.extend_from_slice(&header.argon_iterations.to_be_bytes());
    aad.extend_from_slice(&header.argon_parallelism.to_be_bytes());
    Ok(aad)
}

fn recovery_wrap_aad(header: &VaultHeader) -> Result<Vec<u8>> {
    let mut aad = Vec::with_capacity(RECOVERY_WRAP_AAD_DOMAIN.len() + 48);
    aad.extend_from_slice(RECOVERY_WRAP_AAD_DOMAIN);
    aad.extend_from_slice(&header.version.to_be_bytes());
    append_aad_field(&mut aad, header.vault_id.as_bytes())?;
    Ok(aad)
}

fn root_verifier_aad(header: &VaultHeader) -> Result<Vec<u8>> {
    let mut aad = Vec::with_capacity(V3_VERIFIER_AAD_DOMAIN.len() + 256);
    aad.extend_from_slice(V3_VERIFIER_AAD_DOMAIN);
    aad.extend_from_slice(&header.version.to_be_bytes());
    append_aad_field(&mut aad, header.vault_id.as_bytes())?;
    append_aad_field(&mut aad, header.salt.as_bytes())?;
    aad.extend_from_slice(&header.argon_memory_kib.to_be_bytes());
    aad.extend_from_slice(&header.argon_iterations.to_be_bytes());
    aad.extend_from_slice(&header.argon_parallelism.to_be_bytes());
    append_aad_field(&mut aad, header.wrapped_root_nonce.as_bytes())?;
    append_aad_field(&mut aad, header.wrapped_root_ciphertext.as_bytes())?;
    aad.extend_from_slice(&header.auto_lock_seconds.to_be_bytes());
    aad.push(u8::from(header.delete_source_after_import));
    aad.push(u8::from(header.lock_on_blur));
    aad.push(u8::from(header.lock_on_suspend));
    aad.extend_from_slice(&header.clipboard_timeout_seconds.to_be_bytes());
    append_aad_field(&mut aad, header.recovery_nonce.as_bytes())?;
    append_aad_field(&mut aad, header.recovery_ciphertext.as_bytes())?;
    Ok(aad)
}

fn append_aad_field(destination: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| VaultError::InvalidInput("vault header field is too long".into()))?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
    Ok(())
}

fn derive_password_key(
    password: &str,
    salt: &[u8; 16],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params =
        Params::new(memory_kib, iterations, parallelism, Some(32)).map_err(|_| VaultError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon.hash_password_into(password.as_bytes(), salt, output.as_mut()).map_err(|_| VaultError::Crypto)?;
    Ok(output)
}

fn decode_recovery_key(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = value
        .trim()
        .strip_prefix(RECOVERY_PREFIX)
        .ok_or_else(|| VaultError::InvalidInput("invalid recovery-key format".into()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| VaultError::InvalidInput("invalid recovery-key encoding".into()))?;
    let key: [u8; 32] =
        decoded.try_into().map_err(|_| VaultError::InvalidInput("invalid recovery-key length".into()))?;
    Ok(Zeroizing::new(key))
}

fn recovery_is_configured(header: &VaultHeader) -> bool {
    !header.recovery_nonce.is_empty() && !header.recovery_ciphertext.is_empty()
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let decoded = BASE64
        .decode(value.as_bytes())
        .map_err(|_| VaultError::InvalidInput("invalid vault header encoding".into()))?;
    decoded.try_into().map_err(|_| VaultError::InvalidInput("invalid vault header length".into()))
}

fn read_header(path: &Path) -> Option<VaultHeader> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn recover_header(path: &Path) {
    let backup = path.with_extension("backup");
    if !path.exists() && backup.is_file() {
        let _ = fs::rename(&backup, path);
    } else if path.is_file() && backup.is_file() {
        let _ = fs::remove_file(backup);
    }
}

fn write_header(path: &Path, header: &VaultHeader) -> Result<()> {
    let parent =
        path.parent().ok_or_else(|| VaultError::Storage("vault header has no parent directory".into()))?;
    fs::create_dir_all(parent)?;
    let partial = path.with_extension("partial");
    let backup = path.with_extension("backup");
    let bytes = serde_json::to_vec_pretty(header)?;
    fs::write(&partial, bytes)?;
    let file = fs::OpenOptions::new().read(true).write(true).open(&partial)?;
    file.sync_all()?;

    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    if path.exists() {
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&partial, path) {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        let _ = fs::remove_file(&partial);
        return Err(error.into());
    }
    if backup.exists() {
        let _ = fs::remove_file(&backup);
    }
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_keys_are_distinct() {
        let root = [7_u8; 32];
        let gallery = derive_domain_key(&root, b"gallery").unwrap();
        let credentials = derive_domain_key(&root, b"credentials").unwrap();
        assert_ne!(gallery.as_ref(), credentials.as_ref());
    }

    #[test]
    fn legacy_header_without_source_removal_field_defaults_to_false() {
        let header: VaultHeader = serde_json::from_value(serde_json::json!({
            "version": LEGACY_HEADER_VERSION,
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "argonMemoryKib": 65_536,
            "argonIterations": 3,
            "argonParallelism": 1,
            "verifierNonce": "AAAAAAAAAAAAAAAA",
            "verifierCiphertext": "AA==",
            "autoLockSeconds": 300
        }))
        .unwrap();
        assert!(!header.delete_source_after_import);
        assert!(header.lock_on_suspend);
    }

    #[test]
    fn legacy_header_migrates_to_envelope_without_changing_domain_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault-header.json");
        let password = "correct horse battery staple";
        write_legacy_test_header(&path, password, PREVIOUS_HEADER_VERSION, true);
        let legacy_header = read_header(&path).unwrap();
        let salt = decode_array::<16>(&legacy_header.salt).unwrap();
        let legacy_root = derive_password_key(
            password,
            &salt,
            legacy_header.argon_memory_kib,
            legacy_header.argon_iterations,
            legacy_header.argon_parallelism,
        )
        .unwrap();
        let expected_gallery = derive_domain_key(&legacy_root, crate::crypto::GALLERY_DOMAIN).unwrap();

        let state = SessionState::new(path.clone());
        let unlocked = state.unlock(Zeroizing::new(password.to_owned())).unwrap();
        assert!(!unlocked.locked);
        assert!(unlocked.delete_source_after_import);
        assert_eq!(
            state.domain_key(crate::crypto::GALLERY_DOMAIN).unwrap().as_ref(),
            expected_gallery.as_ref()
        );

        let migrated = read_header(&path).unwrap();
        assert_eq!(migrated.version, HEADER_VERSION);
        assert!(!migrated.wrapped_root_ciphertext.is_empty());
        assert!(verify_root_verifier(&migrated, &legacy_root).unwrap());
    }

    #[test]
    fn v1_migration_forces_source_removal_off() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault-header.json");
        let password = "correct horse battery staple";
        write_legacy_test_header(&path, password, LEGACY_HEADER_VERSION, true);
        let state = SessionState::new(path.clone());
        let unlocked = state.unlock(Zeroizing::new(password.to_owned())).unwrap();
        assert!(!unlocked.delete_source_after_import);
        assert!(!read_header(&path).unwrap().delete_source_after_import);
    }

    #[test]
    fn authenticated_setting_tampering_is_detected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault-header.json");
        let state = SessionState::new(path.clone());
        let password = "correct horse battery staple";
        state.initialize(Zeroizing::new(password.to_owned()), 300).unwrap();
        state.lock();

        let mut header = read_header(&path).unwrap();
        header.delete_source_after_import = true;
        write_header(&path, &header).unwrap();

        assert!(matches!(
            state.unlock(Zeroizing::new(password.to_owned())),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn master_password_change_preserves_encrypted_domain_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault-header.json");
        let state = SessionState::new(path.clone());
        let old_password = "correct horse battery staple";
        let new_password = "another correct horse battery staple";
        state.initialize(Zeroizing::new(old_password.to_owned()), 300).unwrap();
        let before = state.domain_key(crate::crypto::CREDENTIALS_DOMAIN).unwrap();
        state
            .change_master_password(
                Zeroizing::new(old_password.to_owned()),
                Zeroizing::new(new_password.to_owned()),
            )
            .unwrap();
        state.lock();

        let old_attempt = SessionState::new(path.clone());
        assert!(old_attempt.unlock(Zeroizing::new(old_password.to_owned())).is_err());

        let reopened = SessionState::new(path);
        reopened.unlock(Zeroizing::new(new_password.to_owned())).unwrap();
        let after = reopened.domain_key(crate::crypto::CREDENTIALS_DOMAIN).unwrap();
        assert_eq!(before.as_ref(), after.as_ref());
    }

    #[test]
    fn recovery_key_can_reset_password_without_rotating_root_key() {
        let directory = tempfile::tempdir().unwrap();
        let state = SessionState::new(directory.path().join("vault-header.json"));
        let old_password = "correct horse battery staple";
        let new_password = "recovered horse battery staple";
        state.initialize(Zeroizing::new(old_password.to_owned()), 300).unwrap();
        let before = state.domain_key(crate::crypto::GALLERY_DOMAIN).unwrap();
        let recovery = state.create_recovery_key(Zeroizing::new(old_password.to_owned())).unwrap();
        state.lock();
        state
            .recover_with_key(Zeroizing::new(recovery.recovery_key), Zeroizing::new(new_password.to_owned()))
            .unwrap();
        let after = state.domain_key(crate::crypto::GALLERY_DOMAIN).unwrap();
        assert_eq!(before.as_ref(), after.as_ref());
        state.lock();
        state.unlock(Zeroizing::new(new_password.to_owned())).unwrap();
    }

    #[test]
    fn session_initializes_with_secure_lifecycle_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let state = SessionState::new(directory.path().join("vault-header.json"));
        let initialized =
            state.initialize(Zeroizing::new("correct horse battery staple".to_owned()), 300).unwrap();
        assert!(initialized.initialized);
        assert!(!initialized.locked);
        assert!(!initialized.delete_source_after_import);
        assert!(!initialized.lock_on_blur);
        assert!(initialized.lock_on_suspend);
        assert_eq!(initialized.clipboard_timeout_seconds, DEFAULT_CLIPBOARD_TIMEOUT_SECONDS);
        assert!(!initialized.recovery_configured);
        assert!(initialized.recently_reauthenticated);
        assert_ne!(
            state.domain_key(crate::crypto::GALLERY_DOMAIN).unwrap().as_ref(),
            state.domain_key(crate::crypto::CREDENTIALS_DOMAIN).unwrap().as_ref()
        );
    }

    fn write_legacy_test_header(path: &Path, password: &str, version: u16, delete_source_after_import: bool) {
        let salt = [7_u8; 16];
        let nonce = [9_u8; 12];
        let key = derive_password_key(password, &salt, 65_536, 3, 1).unwrap();
        let mut header = VaultHeader {
            version,
            salt: BASE64.encode(salt),
            argon_memory_kib: 65_536,
            argon_iterations: 3,
            argon_parallelism: 1,
            verifier_nonce: BASE64.encode(nonce),
            verifier_ciphertext: String::new(),
            auto_lock_seconds: 300,
            delete_source_after_import,
            vault_id: String::new(),
            wrapped_root_nonce: String::new(),
            wrapped_root_ciphertext: String::new(),
            recovery_nonce: String::new(),
            recovery_ciphertext: String::new(),
            lock_on_blur: false,
            lock_on_suspend: true,
            clipboard_timeout_seconds: DEFAULT_CLIPBOARD_TIMEOUT_SECONDS,
        };
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        let aad = legacy_verifier_aad(&header).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: LEGACY_VERIFIER_PLAINTEXT, aad: &aad })
            .unwrap();
        header.verifier_ciphertext = BASE64.encode(ciphertext);
        write_header(path, &header).unwrap();
    }
}
