use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;
const APP_KEY_ENV: &str = "CONNECT_ARCHIVE_APP_KEY_HEX";
const DEV_APP_KEY: [u8; KEY_LEN] = [0x43; KEY_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSecrets {
    pub salt: [u8; SALT_LEN],
    pub outer_nonce: [u8; NONCE_LEN],
    pub inner_nonce: [u8; NONCE_LEN],
}

impl EnvelopeSecrets {
    pub fn generate() -> Self {
        let mut salt = [0u8; SALT_LEN];
        let mut outer_nonce = [0u8; NONCE_LEN];
        let mut inner_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut outer_nonce);
        OsRng.fill_bytes(&mut inner_nonce);
        Self {
            salt,
            outer_nonce,
            inner_nonce,
        }
    }
}

pub fn encrypt_bytes(
    plaintext: &[u8],
    psk: &str,
    app_key: &[u8; KEY_LEN],
    secrets: &EnvelopeSecrets,
) -> Result<Vec<u8>> {
    let inner_cipher = XChaCha20Poly1305::new(Key::from_slice(app_key));
    let inner = inner_cipher
        .encrypt(XNonce::from_slice(&secrets.inner_nonce), plaintext)
        .map_err(|_| Error::new("unable to encrypt archive"))?;

    let mut derived_key = derive_psk_key(psk, &secrets.salt)?;
    let outer_cipher = XChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let result = outer_cipher
        .encrypt(XNonce::from_slice(&secrets.outer_nonce), inner.as_ref())
        .map_err(|_| Error::new("unable to encrypt archive"));
    derived_key.zeroize();
    result
}

pub fn decrypt_bytes(
    ciphertext: &[u8],
    psk: &str,
    app_key: &[u8; KEY_LEN],
    secrets: &EnvelopeSecrets,
) -> Result<Vec<u8>> {
    let mut derived_key = derive_psk_key(psk, &secrets.salt)?;
    let outer_cipher = XChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let inner = outer_cipher
        .decrypt(XNonce::from_slice(&secrets.outer_nonce), ciphertext)
        .map_err(|_| Error::new("unable to decrypt archive"));
    derived_key.zeroize();
    let inner = inner?;

    let inner_cipher = XChaCha20Poly1305::new(Key::from_slice(app_key));
    inner_cipher
        .decrypt(XNonce::from_slice(&secrets.inner_nonce), inner.as_ref())
        .map_err(|_| Error::new("unable to decrypt archive"))
}

fn derive_psk_key(psk: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(KEY_LEN))
        .map_err(|error| Error::new(format!("invalid argon2 parameters: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; KEY_LEN];
    argon2
        .hash_password_into(psk.as_bytes(), salt, &mut output)
        .map_err(|error| Error::new(format!("unable to derive archive key: {error}")))?;
    Ok(output)
}

pub fn embedded_app_key() -> Result<[u8; KEY_LEN]> {
    if let Some(hex) = option_env!("CONNECT_ARCHIVE_APP_KEY_HEX") {
        return decode_app_key(hex);
    }

    if cfg!(debug_assertions) || cfg!(test) {
        return Ok(DEV_APP_KEY);
    }

    Err(Error::new(format!(
        "missing embedded archive application key; set {APP_KEY_ENV} at build time"
    )))
}

fn decode_app_key(hex: &str) -> Result<[u8; KEY_LEN]> {
    let trimmed = hex.trim();
    if trimmed.len() != KEY_LEN * 2 {
        return Err(Error::new(format!(
            "{APP_KEY_ENV} must be {} hex characters",
            KEY_LEN * 2
        )));
    }

    let mut key = [0u8; KEY_LEN];
    for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let value = std::str::from_utf8(chunk)
            .map_err(|_| Error::new(format!("{APP_KEY_ENV} must be valid UTF-8 hex")))?;
        key[index] = u8::from_str_radix(value, 16)
            .map_err(|_| Error::new(format!("{APP_KEY_ENV} must be valid hex")))?;
    }
    Ok(key)
}
