use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub mod keyring;

pub use keyring::KeyringSecretStore;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBundle {
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub key_passphrase: Option<String>,
}

impl SecretBundle {
    pub fn new() -> Self {
        Self {
            password: None,
            private_key: None,
            key_passphrase: None,
        }
    }

    pub fn with_password(mut self, password: Option<String>) -> Self {
        self.password = password;
        self
    }

    pub fn with_private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    pub fn with_key_passphrase(mut self, key_passphrase: Option<String>) -> Self {
        self.key_passphrase = key_passphrase;
        self
    }
}

pub trait SecretStore: Send + Sync {
    fn set_password(&self, profile_name: &str, password: &str) -> Result<()>;
    fn get_password(&self, profile_name: &str) -> Result<Option<String>>;
    fn set_private_key(&self, profile_name: &str, pem: &str) -> Result<()>;
    fn get_private_key(&self, profile_name: &str) -> Result<Option<String>>;
    fn set_key_passphrase(&self, profile_name: &str, passphrase: &str) -> Result<()>;
    fn get_key_passphrase(&self, profile_name: &str) -> Result<Option<String>>;
    fn get_profile_secrets(&self, profile_name: &str) -> Result<Option<SecretBundle>> {
        let bundle = SecretBundle::new()
            .with_password(self.get_password(profile_name)?)
            .with_private_key(self.get_private_key(profile_name)?)
            .with_key_passphrase(self.get_key_passphrase(profile_name)?);

        if bundle == SecretBundle::default() {
            Ok(None)
        } else {
            Ok(Some(bundle))
        }
    }
    fn set_profile_secrets(&self, profile_name: &str, bundle: &SecretBundle) -> Result<()> {
        self.delete_profile_secrets(profile_name)?;

        if let Some(password) = &bundle.password {
            self.set_password(profile_name, password)?;
        }
        if let Some(private_key) = &bundle.private_key {
            self.set_private_key(profile_name, private_key)?;
        }
        if let Some(key_passphrase) = &bundle.key_passphrase {
            self.set_key_passphrase(profile_name, key_passphrase)?;
        }

        Ok(())
    }
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

    fn get_profile_secrets(&self, profile_name: &str) -> Result<Option<SecretBundle>> {
        let bundle = SecretBundle::new()
            .with_password(self.get_password(profile_name)?)
            .with_private_key(self.get_private_key(profile_name)?)
            .with_key_passphrase(self.get_key_passphrase(profile_name)?);

        if bundle == SecretBundle::default() {
            Ok(None)
        } else {
            Ok(Some(bundle))
        }
    }

    fn set_profile_secrets(&self, profile_name: &str, bundle: &SecretBundle) -> Result<()> {
        let mut secrets = self.secrets.lock().map_err(lock_error)?;
        for suffix in ["password", "private-key", "key-passphrase"] {
            secrets.remove(&secret_key(profile_name, suffix));
        }

        if let Some(password) = &bundle.password {
            secrets.insert(secret_key(profile_name, "password"), password.clone());
        }
        if let Some(private_key) = &bundle.private_key {
            secrets.insert(secret_key(profile_name, "private-key"), private_key.clone());
        }
        if let Some(key_passphrase) = &bundle.key_passphrase {
            secrets.insert(secret_key(profile_name, "key-passphrase"), key_passphrase.clone());
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_secret_store_round_trips_secret_bundle() {
        let store = MemorySecretStore::default();
        let bundle = SecretBundle::new()
            .with_password(Some("pw".into()))
            .with_private_key(Some("pem".into()))
            .with_key_passphrase(Some("phrase".into()));

        store.set_profile_secrets("prod", &bundle).unwrap();

        assert_eq!(store.get_profile_secrets("prod").unwrap(), Some(bundle));
    }
}
