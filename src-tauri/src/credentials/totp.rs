use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

const PERIOD: u64 = 30;
const DIGITS: u32 = 6;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub remaining_seconds: u64,
}

pub fn validate_totp_secret(secret: &str) -> Result<()> {
    let decoded = decode_secret(secret)?;
    if decoded.len() < 10 || decoded.len() > 128 {
        return Err(VaultError::InvalidInput("TOTP secret must decode to between 10 and 128 bytes".into()));
    }
    Ok(())
}

pub fn generate_totp(secret: &str) -> Result<TotpCode> {
    let secret = decode_secret(secret)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Platform("system clock is before UNIX epoch".into()))?
        .as_secs();
    let counter = now / PERIOD;
    let mut mac = HmacSha1::new_from_slice(secret.as_slice()).map_err(|_| VaultError::Crypto)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let code = binary % 10_u32.pow(DIGITS);
    Ok(TotpCode { code: format!("{code:06}"), remaining_seconds: PERIOD - (now % PERIOD) })
}

fn decode_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    if secret.len() > 1024 {
        return Err(VaultError::InvalidInput("TOTP secret is too long".into()));
    }
    let normalized = Zeroizing::new(
        secret
            .chars()
            .filter(|character| !character.is_whitespace() && *character != '-' && *character != '=')
            .flat_map(char::to_uppercase)
            .collect::<String>(),
    );
    if normalized.is_empty() {
        return Err(VaultError::InvalidInput("TOTP secret is empty".into()));
    }
    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| VaultError::InvalidInput("TOTP secret is not valid Base32".into()))?;
    Ok(Zeroizing::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_secret() {
        assert!(validate_totp_secret("JBSWY3DP").is_err());
    }
}
