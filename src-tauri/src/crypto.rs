use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub const GALLERY_DOMAIN: &[u8] = b"nd-secure/gallery-root/v1";
pub const CREDENTIALS_DOMAIN: &[u8] = b"nd-secure/credentials-root/v1";
pub const PROJECTS_DOMAIN: &[u8] = b"nd-secure/projects-root/v1";

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut output = [0_u8; N];
    OsRng.fill_bytes(&mut output);
    output
}

pub fn derive_domain_key(master_key: &[u8; 32], domain: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"nd-secure/root-salt/v1"), master_key);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(domain, output.as_mut()).map_err(|_| VaultError::Crypto)?;
    Ok(output)
}

pub fn derive_object_key(
    root_key: &[u8; 32],
    salt: &[u8; 16],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), root_key);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(context, output.as_mut()).map_err(|_| VaultError::Crypto)?;
    Ok(output)
}
