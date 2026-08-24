use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

const LOWER_WITH_AMBIGUOUS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER_WITH_AMBIGUOUS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS_WITH_AMBIGUOUS: &[u8] = b"0123456789";
const LOWER_SAFE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER_SAFE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const NUMBERS_SAFE: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
    pub entropy_bits: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGeneratorOptions {
    pub length: usize,
    #[serde(default = "default_true")]
    pub lowercase: bool,
    #[serde(default = "default_true")]
    pub uppercase: bool,
    #[serde(default = "default_true")]
    pub numbers: bool,
    #[serde(default = "default_true")]
    pub symbols: bool,
    #[serde(default = "default_true")]
    pub exclude_ambiguous: bool,
    #[serde(default)]
    pub min_numbers: usize,
    #[serde(default)]
    pub min_symbols: usize,
}

pub fn generate_password(length: usize, symbols: bool) -> Result<GeneratedPassword> {
    generate_password_with_options(PasswordGeneratorOptions {
        length,
        lowercase: true,
        uppercase: true,
        numbers: true,
        symbols,
        exclude_ambiguous: true,
        min_numbers: 1,
        min_symbols: usize::from(symbols),
    })
}

pub fn generate_password_with_options(options: PasswordGeneratorOptions) -> Result<GeneratedPassword> {
    if !(12..=128).contains(&options.length) {
        return Err(VaultError::InvalidInput(
            "generated password length must be between 12 and 128".into(),
        ));
    }
    if !(options.lowercase || options.uppercase || options.numbers || options.symbols) {
        return Err(VaultError::InvalidInput(
            "enable at least one password character class".into(),
        ));
    }
    if options.min_numbers > options.length || options.min_symbols > options.length {
        return Err(VaultError::InvalidInput(
            "minimum character counts cannot exceed password length".into(),
        ));
    }
    if options.min_numbers > 0 && !options.numbers {
        return Err(VaultError::InvalidInput(
            "minimum number count requires numbers to be enabled".into(),
        ));
    }
    if options.min_symbols > 0 && !options.symbols {
        return Err(VaultError::InvalidInput(
            "minimum symbol count requires symbols to be enabled".into(),
        ));
    }

    let lower = if options.exclude_ambiguous { LOWER_SAFE } else { LOWER_WITH_AMBIGUOUS };
    let upper = if options.exclude_ambiguous { UPPER_SAFE } else { UPPER_WITH_AMBIGUOUS };
    let numbers = if options.exclude_ambiguous { NUMBERS_SAFE } else { NUMBERS_WITH_AMBIGUOUS };

    let mut groups: Vec<&[u8]> = Vec::with_capacity(4);
    if options.lowercase {
        groups.push(lower);
    }
    if options.uppercase {
        groups.push(upper);
    }
    if options.numbers {
        groups.push(numbers);
    }
    if options.symbols {
        groups.push(SYMBOLS);
    }

    let minimum_required = groups.len()
        + options.min_numbers.saturating_sub(usize::from(options.numbers))
        + options.min_symbols.saturating_sub(usize::from(options.symbols));
    if minimum_required > options.length {
        return Err(VaultError::InvalidInput(
            "requested minimum character counts exceed password length".into(),
        ));
    }

    let mut alphabet = Vec::new();
    for group in &groups {
        alphabet.extend_from_slice(group);
    }

    let mut rng = OsRng;
    let mut output = Vec::with_capacity(options.length);
    for group in &groups {
        output.push(random_from(group, &mut rng));
    }
    if options.numbers {
        for _ in 1..options.min_numbers {
            output.push(random_from(numbers, &mut rng));
        }
    }
    if options.symbols {
        for _ in 1..options.min_symbols {
            output.push(random_from(SYMBOLS, &mut rng));
        }
    }
    while output.len() < options.length {
        output.push(random_from(&alphabet, &mut rng));
    }
    output.shuffle(&mut rng);

    let password = String::from_utf8(output).map_err(|_| VaultError::Crypto)?;
    let entropy_bits = options.length as f64 * (alphabet.len() as f64).log2();
    Ok(GeneratedPassword { password, entropy_bits })
}

fn random_from<R: Rng + ?Sized>(values: &[u8], rng: &mut R) -> u8 {
    values[rng.gen_range(0..values.len())]
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_respects_requested_length() {
        let generated = generate_password(24, true).unwrap();
        assert_eq!(generated.password.len(), 24);
    }

    #[test]
    fn advanced_generator_enforces_minimum_counts() {
        let generated = generate_password_with_options(PasswordGeneratorOptions {
            length: 32,
            lowercase: true,
            uppercase: true,
            numbers: true,
            symbols: true,
            exclude_ambiguous: true,
            min_numbers: 5,
            min_symbols: 4,
        })
        .unwrap();
        assert!(generated.password.bytes().filter(u8::is_ascii_digit).count() >= 5);
        assert!(generated.password.bytes().filter(|byte| SYMBOLS.contains(byte)).count() >= 4);
    }

    #[test]
    fn generator_rejects_impossible_constraints() {
        assert!(generate_password_with_options(PasswordGeneratorOptions {
            length: 12,
            lowercase: true,
            uppercase: true,
            numbers: false,
            symbols: false,
            exclude_ambiguous: true,
            min_numbers: 2,
            min_symbols: 0,
        })
        .is_err());
    }
}
