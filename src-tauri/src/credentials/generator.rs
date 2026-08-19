use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use serde::Serialize;

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
    pub entropy_bits: f64,
}

pub fn generate_password(length: usize, symbols: bool) -> Result<GeneratedPassword> {
    if !(12..=128).contains(&length) {
        return Err(VaultError::InvalidInput(
            "generated password length must be between 12 and 128".into(),
        ));
    }
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const NUMBERS: &[u8] = b"23456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";

    let mut alphabet = Vec::new();
    alphabet.extend_from_slice(LOWER);
    alphabet.extend_from_slice(UPPER);
    alphabet.extend_from_slice(NUMBERS);
    if symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }

    let required: Vec<&[u8]> = if symbols {
        vec![LOWER, UPPER, NUMBERS, SYMBOLS]
    } else {
        vec![LOWER, UPPER, NUMBERS]
    };
    let mut rng = OsRng;
    let mut output = Vec::with_capacity(length);
    for group in required {
        output.push(group[rng.gen_range(0..group.len())]);
    }
    while output.len() < length {
        output.push(alphabet[rng.gen_range(0..alphabet.len())]);
    }
    output.shuffle(&mut rng);
    let password = String::from_utf8(output).map_err(|_| VaultError::Crypto)?;
    let entropy_bits = length as f64 * (alphabet.len() as f64).log2();
    Ok(GeneratedPassword {
        password,
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_respects_requested_length() {
        let generated = generate_password(24, true).unwrap();
        assert_eq!(generated.password.len(), 24);
    }
}
