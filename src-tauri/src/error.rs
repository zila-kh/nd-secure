use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("vault has not been initialized")]
    NotInitialized,
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("invalid master password")]
    InvalidPassword,
    #[error("too many failed unlock attempts; try again shortly")]
    RateLimited,
    #[error("master password must contain at least 12 characters")]
    WeakPassword,
    #[error("unsupported or malformed media file")]
    UnsupportedMedia,
    #[error("requested media range is invalid")]
    InvalidRange,
    #[error("requested media response exceeds the configured limit")]
    RangeTooLarge,
    #[error("encrypted data authentication failed")]
    AuthenticationFailed,
    #[error("encrypted container is malformed or truncated")]
    MalformedContainer,
    #[error("record was not found")]
    NotFound,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("platform operation failed: {0}")]
    Platform(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

impl From<std::io::Error> for VaultError {
    fn from(value: std::io::Error) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.to_string())
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(value: serde_json::Error) -> Self {
        Self::InvalidInput(value.to_string())
    }
}
