use serde::{de::DeserializeOwned, Serialize};

use crate::error::{Error, Result};

use super::{
    crypto::{decrypt_bytes, encrypt_bytes, EnvelopeSecrets, ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, NONCE_LEN, SALT_LEN},
    schema::ArchiveKind,
};

const MAGIC: &[u8; 8] = b"CNARCH01";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 1 + SALT_LEN + NONCE_LEN + NONCE_LEN;

pub fn encrypt_archive<T: Serialize>(
    payload: &T,
    kind: ArchiveKind,
    psk: &str,
    app_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|error| Error::new(format!("invalid archive payload: {error}")))?;
    let secrets = EnvelopeSecrets::generate();
    let ciphertext = encrypt_bytes(&plaintext, psk, app_key, &secrets)?;

    let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(FORMAT_VERSION);
    output.push(kind_to_byte(kind));
    output.extend_from_slice(&ARGON2_MEMORY_KIB.to_le_bytes());
    output.extend_from_slice(&ARGON2_ITERATIONS.to_le_bytes());
    output.push(ARGON2_PARALLELISM as u8);
    output.extend_from_slice(&secrets.salt);
    output.extend_from_slice(&secrets.outer_nonce);
    output.extend_from_slice(&secrets.inner_nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_archive<T: DeserializeOwned>(
    archive: &[u8],
    expected_kind: ArchiveKind,
    psk: &str,
    app_key: &[u8; 32],
) -> Result<T> {
    if archive.len() < HEADER_LEN {
        return Err(Error::new("archive is truncated"));
    }
    if &archive[..MAGIC.len()] != MAGIC {
        return Err(Error::new("archive header is invalid"));
    }
    if archive[8] != FORMAT_VERSION {
        return Err(Error::new("archive format version is unsupported"));
    }

    let actual_kind = byte_to_kind(archive[9])?;
    if actual_kind != expected_kind {
        return Err(Error::new("archive kind does not match requested operation"));
    }

    let memory = u32::from_le_bytes(archive[10..14].try_into().unwrap());
    let iterations = u32::from_le_bytes(archive[14..18].try_into().unwrap());
    let parallelism = archive[18];
    if memory != ARGON2_MEMORY_KIB
        || iterations != ARGON2_ITERATIONS
        || parallelism != ARGON2_PARALLELISM as u8
    {
        return Err(Error::new("archive KDF parameters are unsupported"));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&archive[19..19 + SALT_LEN]);
    let mut outer_nonce = [0u8; NONCE_LEN];
    outer_nonce.copy_from_slice(&archive[19 + SALT_LEN..19 + SALT_LEN + NONCE_LEN]);
    let mut inner_nonce = [0u8; NONCE_LEN];
    inner_nonce.copy_from_slice(
        &archive[19 + SALT_LEN + NONCE_LEN..19 + SALT_LEN + NONCE_LEN + NONCE_LEN],
    );
    let ciphertext = &archive[HEADER_LEN..];

    let plaintext = decrypt_bytes(
        ciphertext,
        psk,
        app_key,
        &EnvelopeSecrets {
            salt,
            outer_nonce,
            inner_nonce,
        },
    )?;
    serde_json::from_slice(&plaintext).map_err(|error| Error::new(format!("invalid archive payload: {error}")))
}

fn kind_to_byte(kind: ArchiveKind) -> u8 {
    match kind {
        ArchiveKind::Backup => 1,
        ArchiveKind::ProfileExport => 2,
    }
}

fn byte_to_kind(value: u8) -> Result<ArchiveKind> {
    match value {
        1 => Ok(ArchiveKind::Backup),
        2 => Ok(ArchiveKind::ProfileExport),
        _ => Err(Error::new("archive kind is unsupported")),
    }
}
