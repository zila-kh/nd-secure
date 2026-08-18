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
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    crypto::{derive_domain_key, random_array},
    error::{Result, VaultError},
};

const HEADER_VERSION: u16 = 1;
const VERIFIER_PLAINTEXT: &[u8] = b"ND_SECURE_MASTER_KEY_VERIFIER_V1";
const VERIFIER_AAD: &[u8] = b"kh.zila.ndsecure/header/verifier/v1";
const MIN_PASSWORD_CHARS: usize = 12;
const DEFAULT_AUTO_LOCK_SECONDS: u64 = 300;
const MIN_AUTO_LOCK_SECONDS: u64 = 60;
const MAX_AUTO_LOCK_SECONDS: u64 = 86_400;

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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatus {
    pub initialized: bool,
    pub locked: bool,
    pub auto_lock_seconds: u64,
}

struct UnlockedSession {
    master_key: Zeroizing<[u8; 32]>,
    last_activity: Instant,
}

struct SessionInner {
    unlocked: Option<UnlockedSession>,
    auto_lock_seconds: u64,
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
        let auto_lock_seconds = read_header(&header_path)
            .map(|header| header.auto_lock_seconds)
            .unwrap_or(DEFAULT_AUTO_LOCK_SECONDS)
            .clamp(MIN_AUTO_LOCK_SECONDS, MAX_AUTO_LOCK_SECONDS);
        Self {
            header_path,
            lifecycle: Mutex::new(()),
            inner: Mutex::new(SessionInner {
                unlocked: None,
                auto_lock_seconds,
            }),
            attempts: Mutex::new(AttemptState {
                failed: 0,
                blocked_until: None,
            }),
        }
    }

    pub fn status(&self) -> SessionStatus {
        self.expire_if_idle();
        let inner = self.inner.lock();
        SessionStatus {
            initialized: self.header_path.is_file(),
            locked: inner.unlocked.is_none(),
            auto_lock_seconds: inner.auto_lock_seconds,
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
        let master_key = derive_master_key(&password, &salt, 65_536, 3, 1)?;
        let verifier_nonce = random_array::<12>();
        let cipher = Aes256Gcm::new_from_slice(master_key.as_ref()).map_err(|_| VaultError::Crypto)?;
        let verifier_ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&verifier_nonce),
                Payload {
                    msg: VERIFIER_PLAINTEXT,
                    aad: VERIFIER_AAD,
                },
            )
            .map_err(|_| VaultError::Crypto)?;

        let header = VaultHeader {
            version: HEADER_VERSION,
            salt: BASE64.encode(salt),
            argon_memory_kib: 65_536,
            argon_iterations: 3,
            argon_parallelism: 1,
            verifier_nonce: BASE64.encode(verifier_nonce),
            verifier_ciphertext: BASE64.encode(verifier_ciphertext),
            auto_lock_seconds,
        };
        write_header(&self.header_path, &header)?;

        let mut inner = self.inner.lock();
        inner.auto_lock_seconds = auto_lock_seconds;
        inner.unlocked = Some(UnlockedSession {
            master_key,
            last_activity: Instant::now(),
        });
        drop(inner);
        Ok(self.status())
    }

    pub fn unlock(&self, password: Zeroizing<String>) -> Result<SessionStatus> {
        let _lifecycle = self.lifecycle.lock();
        self.check_attempt_limit()?;
        let header = read_header(&self.header_path).ok_or(VaultError::NotInitialized)?;
        validate_header(&header)?;
        let salt = decode_array::<16>(&header.salt)?;
        let candidate = derive_master_key(
            &password,
            &salt,
            header.argon_memory_kib,
            header.argon_iterations,
            header.argon_parallelism,
        )?;
        let nonce = decode_array::<12>(&header.verifier_nonce)?;
        let ciphertext = BASE64
            .decode(header.verifier_ciphertext.as_bytes())
            .map_err(|_| VaultError::InvalidPassword)?;
        let cipher = Aes256Gcm::new_from_slice(candidate.as_ref()).map_err(|_| VaultError::Crypto)?;
        let plaintext = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: VERIFIER_AAD,
            },
        );

        let valid = plaintext
            .as_ref()
            .map(|value| value.as_slice().ct_eq(VERIFIER_PLAINTEXT).into())
            .unwrap_or(false);
        let mut plaintext = Zeroizing::new(plaintext.unwrap_or_default());
        plaintext.clear();

        if !valid {
            self.record_failed_attempt();
            return Err(VaultError::InvalidPassword);
        }
        self.reset_attempts();

        let mut inner = self.inner.lock();
        inner.auto_lock_seconds = header.auto_lock_seconds;
        inner.unlocked = Some(UnlockedSession {
            master_key: candidate,
            last_activity: Instant::now(),
        });
        drop(inner);
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
            return Err(VaultError::InvalidInput(
                "auto-lock must be between 60 and 86400 seconds".into(),
            ));
        }
        self.touch()?;
        let mut header = read_header(&self.header_path).ok_or(VaultError::NotInitialized)?;
        header.auto_lock_seconds = seconds;
        write_header(&self.header_path, &header)?;
        self.inner.lock().auto_lock_seconds = seconds;
        Ok(self.status())
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
        let key = derive_domain_key(&*unlocked.master_key, domain)?;
        unlocked.last_activity = Instant::now();
        Ok(key)
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
        if attempts
            .blocked_until
            .map(|deadline| deadline > Instant::now())
            .unwrap_or(false)
        {
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

fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword);
    }
    Ok(())
}

fn validate_header(header: &VaultHeader) -> Result<()> {
    if header.version != HEADER_VERSION
        || !(32_768..=1_048_576).contains(&header.argon_memory_kib)
        || !(1..=10).contains(&header.argon_iterations)
        || !(1..=16).contains(&header.argon_parallelism)
        || !(MIN_AUTO_LOCK_SECONDS..=MAX_AUTO_LOCK_SECONDS).contains(&header.auto_lock_seconds)
    {
        return Err(VaultError::InvalidInput("invalid vault header parameters".into()));
    }
    Ok(())
}

fn derive_master_key(
    password: &str,
    salt: &[u8; 16],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|_| VaultError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, output.as_mut())
        .map_err(|_| VaultError::Crypto)?;
    Ok(output)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let decoded = BASE64
        .decode(value.as_bytes())
        .map_err(|_| VaultError::InvalidInput("invalid vault header encoding".into()))?;
    decoded
        .try_into()
        .map_err(|_| VaultError::InvalidInput("invalid vault header length".into()))
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
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::Storage("vault header has no parent directory".into()))?;
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
        fs::remove_file(backup)?;
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
    fn session_initializes_locks_and_unlocks() {
        let directory = tempfile::tempdir().unwrap();
        let state = SessionState::new(directory.path().join("vault-header.json"));
        let initialized = state
            .initialize(Zeroizing::new("correct horse battery staple".to_owned()), 300)
            .unwrap();
        assert!(initialized.initialized);
        assert!(!initialized.locked);
        assert_ne!(
            state.domain_key(crate::crypto::GALLERY_DOMAIN).unwrap().as_ref(),
            state.domain_key(crate::crypto::CREDENTIALS_DOMAIN).unwrap().as_ref()
        );

        assert!(state.lock().locked);
        let unlocked = state
            .unlock(Zeroizing::new("correct horse battery staple".to_owned()))
            .unwrap();
        assert!(!unlocked.locked);
    }
}
