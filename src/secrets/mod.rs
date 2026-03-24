use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
};

use crate::error::{Error, Result};

pub mod keyring;

pub use keyring::KeyringSecretStore;

pub trait SecretStore: Send + Sync {
    fn set_password(&self, profile_name: &str, password: &str) -> Result<()>;
    fn get_password(&self, profile_name: &str) -> Result<Option<String>>;
    fn set_private_key(&self, profile_name: &str, pem: &str) -> Result<()>;
    fn get_private_key(&self, profile_name: &str) -> Result<Option<String>>;
    fn set_key_passphrase(&self, profile_name: &str, passphrase: &str) -> Result<()>;
    fn get_key_passphrase(&self, profile_name: &str) -> Result<Option<String>>;
    fn delete_profile_secrets(&self, profile_name: &str) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct MemorySecretStore {
    secrets: Mutex<HashMap<String, String>>,
}

impl MemorySecretStore {
    fn set_secret(&self, profile_name: &str, suffix: &str, value: &str) -> Result<()> {
        self.secrets
            .lock()
            .map_err(lock_error)?
            .insert(secret_key(profile_name, suffix), value.to_string());
        Ok(())
    }

    fn get_secret(&self, profile_name: &str, suffix: &str) -> Result<Option<String>> {
        let secret = self
            .secrets
            .lock()
            .map_err(lock_error)?
            .get(&secret_key(profile_name, suffix))
            .cloned();
        Ok(secret)
    }
}

impl SecretStore for MemorySecretStore {
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
        let mut secrets = self.secrets.lock().map_err(lock_error)?;
        for suffix in ["password", "private-key", "key-passphrase"] {
            secrets.remove(&secret_key(profile_name, suffix));
        }
        Ok(())
    }
}

fn secret_key(profile_name: &str, suffix: &str) -> String {
    format!("{profile_name}:{suffix}")
}

fn lock_error<T>(_error: PoisonError<T>) -> Error {
    Error::new("secret store lock poisoned")
}
