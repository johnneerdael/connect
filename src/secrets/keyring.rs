use keyring_core::{Entry, Error as KeyringError};

use crate::error::{Error, Result};

use super::SecretStore;

#[derive(Debug, Clone)]
pub struct KeyringSecretStore {
    service_name: String,
}

impl KeyringSecretStore {
    pub fn new(service_name: impl Into<String>) -> Result<Self> {
        keyring::use_native_store(false)?;
        Ok(Self {
            service_name: service_name.into(),
        })
    }

    fn entry(&self, profile_name: &str, suffix: &str) -> Result<Entry> {
        Ok(Entry::new(
            &self.service_name,
            &format!("{profile_name}:{suffix}"),
        )?)
    }

    fn set_secret(&self, profile_name: &str, suffix: &str, value: &str) -> Result<()> {
        self.entry(profile_name, suffix)?.set_password(value)?;
        Ok(())
    }

    fn get_secret(&self, profile_name: &str, suffix: &str) -> Result<Option<String>> {
        let entry = self.entry(profile_name, suffix)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(Error::from(error)),
        }
    }

    fn delete_secret(&self, profile_name: &str, suffix: &str) -> Result<()> {
        let entry = self.entry(profile_name, suffix)?;
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }
}

impl SecretStore for KeyringSecretStore {
    fn set_password(&self, profile_name: &str, password: &str) -> Result<()> {
        self.set_secret(profile_name, "password", password)
    }

    fn get_password(&self, profile_name: &str) -> Result<Option<String>> {
        self.get_secret(profile_name, "password")
    }

    fn set_private_key(&self, profile_name: &str, pem: &str) -> Result<()> {
        self.set_secret(profile_name, "private-key", pem)
    }

    fn get_private_key(&self, profile_name: &str) -> Result<Option<String>> {
        self.get_secret(profile_name, "private-key")
    }

    fn set_key_passphrase(&self, profile_name: &str, passphrase: &str) -> Result<()> {
        self.set_secret(profile_name, "key-passphrase", passphrase)
    }

    fn get_key_passphrase(&self, profile_name: &str) -> Result<Option<String>> {
        self.get_secret(profile_name, "key-passphrase")
    }

    fn delete_profile_secrets(&self, profile_name: &str) -> Result<()> {
        for suffix in ["password", "private-key", "key-passphrase"] {
            self.delete_secret(profile_name, suffix)?;
        }
        Ok(())
    }
}
