use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use keyring_core::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::SecretStore;

const BUNDLE_VERSION: u8 = 1;
const BUNDLE_SUFFIX: &str = "profile";
const PASSWORD_SUFFIX: &str = "password";
const PRIVATE_KEY_SUFFIX: &str = "private-key";
const KEY_PASSPHRASE_SUFFIX: &str = "key-passphrase";
const LEGACY_SUFFIXES: [&str; 3] = [PASSWORD_SUFFIX, PRIVATE_KEY_SUFFIX, KEY_PASSPHRASE_SUFFIX];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SecretBundle {
    version: u8,
    password: Option<String>,
    private_key: Option<String>,
    key_passphrase: Option<String>,
}

impl Default for SecretBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBundle {
    fn new() -> Self {
        Self {
            version: BUNDLE_VERSION,
            password: None,
            private_key: None,
            key_passphrase: None,
        }
    }

    fn with_password(mut self, password: Option<String>) -> Self {
        self.password = password;
        self
    }

    fn with_private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    fn with_key_passphrase(mut self, key_passphrase: Option<String>) -> Self {
        self.key_passphrase = key_passphrase;
        self
    }

    fn is_empty(&self) -> bool {
        self.password.is_none() && self.private_key.is_none() && self.key_passphrase.is_none()
    }
}

fn encode_bundle(bundle: &SecretBundle) -> Result<String> {
    serde_json::to_string(bundle)
        .map_err(|error| Error::new(format!("invalid secret bundle: {error}")))
}

fn decode_bundle(encoded: &str) -> Result<SecretBundle> {
    serde_json::from_str(encoded)
        .map_err(|error| Error::new(format!("invalid secret bundle: {error}")))
}

trait KeyringBackend: Send + Sync + std::fmt::Debug {
    fn set_secret(&self, account: &str, value: &str) -> Result<()>;
    fn get_secret(&self, account: &str) -> Result<Option<String>>;
    fn delete_secret(&self, account: &str) -> Result<()>;
}

#[derive(Debug)]
struct NativeKeyringBackend {
    service_name: String,
}

impl NativeKeyringBackend {
    fn entry(&self, account: &str) -> Result<Entry> {
        Ok(Entry::new(&self.service_name, account)?)
    }
}

impl KeyringBackend for NativeKeyringBackend {
    fn set_secret(&self, account: &str, value: &str) -> Result<()> {
        self.entry(account)?.set_password(value)?;
        Ok(())
    }

    fn get_secret(&self, account: &str) -> Result<Option<String>> {
        let entry = self.entry(account)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(Error::from(error)),
        }
    }

    fn delete_secret(&self, account: &str) -> Result<()> {
        let entry = self.entry(account)?;
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyringSecretStore {
    backend: Arc<dyn KeyringBackend>,
    cache: Arc<Mutex<HashMap<String, Option<SecretBundle>>>>,
}

impl KeyringSecretStore {
    pub fn new(service_name: impl Into<String>) -> Result<Self> {
        keyring::use_native_store(false)?;
        Ok(Self::with_backend(Arc::new(NativeKeyringBackend {
            service_name: service_name.into(),
        })))
    }

    fn with_backend(backend: Arc<dyn KeyringBackend>) -> Self {
        Self {
            backend,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    fn with_backend_for_tests<T>(backend: Arc<T>) -> Self
    where
        T: KeyringBackend + 'static,
    {
        Self::with_backend(backend)
    }

    fn bundle_account(profile_name: &str) -> String {
        secret_key(profile_name, BUNDLE_SUFFIX)
    }

    fn legacy_account(profile_name: &str, suffix: &str) -> String {
        secret_key(profile_name, suffix)
    }

    fn load_bundle(&self, profile_name: &str) -> Result<Option<SecretBundle>> {
        if let Some(bundle) = self
            .cache
            .lock()
            .map_err(lock_error)?
            .get(profile_name)
            .cloned()
        {
            return Ok(bundle);
        }

        let bundle = if let Some(encoded) = self
            .backend
            .get_secret(&Self::bundle_account(profile_name))?
        {
            Some(decode_bundle(&encoded)?)
        } else {
            self.migrate_legacy_bundle(profile_name)?
        };

        self.cache
            .lock()
            .map_err(lock_error)?
            .insert(profile_name.to_string(), bundle.clone());
        Ok(bundle)
    }

    fn migrate_legacy_bundle(&self, profile_name: &str) -> Result<Option<SecretBundle>> {
        let mut bundle = SecretBundle::new();
        let mut found_secret = false;

        for (suffix, assign) in [
            (PASSWORD_SUFFIX, SecretField::Password),
            (PRIVATE_KEY_SUFFIX, SecretField::PrivateKey),
            (KEY_PASSPHRASE_SUFFIX, SecretField::KeyPassphrase),
        ] {
            if let Some(secret) = self
                .backend
                .get_secret(&Self::legacy_account(profile_name, suffix))?
            {
                found_secret = true;
                bundle = match assign {
                    SecretField::Password => bundle.with_password(Some(secret)),
                    SecretField::PrivateKey => bundle.with_private_key(Some(secret)),
                    SecretField::KeyPassphrase => bundle.with_key_passphrase(Some(secret)),
                };
            }
        }

        if !found_secret {
            return Ok(None);
        }

        let encoded = encode_bundle(&bundle)?;
        self.backend
            .set_secret(&Self::bundle_account(profile_name), &encoded)?;
        for suffix in LEGACY_SUFFIXES {
            let _ = self
                .backend
                .delete_secret(&Self::legacy_account(profile_name, suffix));
        }
        Ok(Some(bundle))
    }

    fn store_bundle(&self, profile_name: &str, bundle: SecretBundle) -> Result<()> {
        if bundle.is_empty() {
            self.backend
                .delete_secret(&Self::bundle_account(profile_name))?;
            self.cache
                .lock()
                .map_err(lock_error)?
                .insert(profile_name.to_string(), None);
            return Ok(());
        }

        let encoded = encode_bundle(&bundle)?;
        self.backend
            .set_secret(&Self::bundle_account(profile_name), &encoded)?;
        self.cache
            .lock()
            .map_err(lock_error)?
            .insert(profile_name.to_string(), Some(bundle));
        Ok(())
    }

    fn update_bundle<F>(&self, profile_name: &str, update: F) -> Result<()>
    where
        F: FnOnce(SecretBundle) -> SecretBundle,
    {
        let current = self.load_bundle(profile_name)?.unwrap_or_default();
        self.store_bundle(profile_name, update(current))
    }

    fn get_field(
        &self,
        profile_name: &str,
        field: impl FnOnce(&SecretBundle) -> Option<String>,
    ) -> Result<Option<String>> {
        Ok(self.load_bundle(profile_name)?.and_then(|bundle| field(&bundle)))
    }

    fn delete_legacy_entries(&self, profile_name: &str) -> Result<()> {
        for suffix in LEGACY_SUFFIXES {
            self.backend
                .delete_secret(&Self::legacy_account(profile_name, suffix))?;
        }
        Ok(())
    }
}

impl SecretStore for KeyringSecretStore {
    fn set_password(&self, profile_name: &str, password: &str) -> Result<()> {
        self.update_bundle(profile_name, |bundle| bundle.with_password(Some(password.into())))
    }

    fn get_password(&self, profile_name: &str) -> Result<Option<String>> {
        self.get_field(profile_name, |bundle| bundle.password.clone())
    }

    fn set_private_key(&self, profile_name: &str, pem: &str) -> Result<()> {
        self.update_bundle(profile_name, |bundle| bundle.with_private_key(Some(pem.into())))
    }

    fn get_private_key(&self, profile_name: &str) -> Result<Option<String>> {
        self.get_field(profile_name, |bundle| bundle.private_key.clone())
    }

    fn set_key_passphrase(&self, profile_name: &str, passphrase: &str) -> Result<()> {
        self.update_bundle(profile_name, |bundle| {
            bundle.with_key_passphrase(Some(passphrase.into()))
        })
    }

    fn get_key_passphrase(&self, profile_name: &str) -> Result<Option<String>> {
        self.get_field(profile_name, |bundle| bundle.key_passphrase.clone())
    }

    fn delete_profile_secrets(&self, profile_name: &str) -> Result<()> {
        self.backend
            .delete_secret(&Self::bundle_account(profile_name))?;
        self.delete_legacy_entries(profile_name)?;
        self.cache.lock().map_err(lock_error)?.remove(profile_name);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum SecretField {
    Password,
    PrivateKey,
    KeyPassphrase,
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn secret_bundle_round_trips_through_json() {
        let bundle = SecretBundle {
            version: 1,
            password: Some("pw".into()),
            private_key: Some("pem".into()),
            key_passphrase: Some("phrase".into()),
        };

        let encoded = encode_bundle(&bundle).expect("bundle should encode");
        let decoded = decode_bundle(&encoded).expect("bundle should decode");

        assert_eq!(decoded, bundle);
    }

    #[test]
    fn merge_updates_only_requested_secret_field() {
        let bundle = SecretBundle {
            version: 1,
            password: Some("old".into()),
            private_key: Some("pem".into()),
            key_passphrase: None,
        };

        let merged = bundle.with_password(Some("new".into()));

        assert_eq!(merged.password.as_deref(), Some("new"));
        assert_eq!(merged.private_key.as_deref(), Some("pem"));
        assert_eq!(merged.key_passphrase, None);
    }

    #[test]
    fn legacy_field_entries_migrate_into_a_single_profile_bundle() {
        let backend = TestBackend::with_legacy_entries("prod", Some("pw"), Some("pem"), None);
        let store = KeyringSecretStore::with_backend_for_tests(backend.clone());

        assert_eq!(store.get_password("prod").unwrap().as_deref(), Some("pw"));
        assert_eq!(backend.bundle_write_count("prod"), 1);
        assert!(backend.legacy_entries_deleted("prod"));
    }

    #[test]
    fn repeated_reads_use_cached_bundle_after_first_load() {
        let backend = TestBackend::with_bundle(
            "prod",
            SecretBundle {
                version: 1,
                password: Some("pw".into()),
                private_key: None,
                key_passphrase: None,
            },
        );
        let store = KeyringSecretStore::with_backend_for_tests(backend.clone());

        assert_eq!(store.get_password("prod").unwrap().as_deref(), Some("pw"));
        assert_eq!(store.get_password("prod").unwrap().as_deref(), Some("pw"));
        assert_eq!(backend.bundle_read_count("prod"), 1);
    }

    #[test]
    fn delete_profile_secrets_removes_bundled_and_legacy_entries() {
        let backend = TestBackend::with_legacy_entries("prod", Some("pw"), Some("pem"), None);
        backend.store_bundle(
            "prod",
            SecretBundle {
                version: 1,
                password: Some("pw".into()),
                private_key: Some("pem".into()),
                key_passphrase: None,
            },
        );
        let store = KeyringSecretStore::with_backend_for_tests(backend.clone());

        store.delete_profile_secrets("prod").unwrap();

        assert!(backend.get_secret(&KeyringSecretStore::bundle_account("prod")).unwrap().is_none());
        assert!(backend.legacy_entries_deleted("prod"));
    }

    #[test]
    fn failed_migration_writes_do_not_delete_legacy_entries() {
        let backend = TestBackend::with_legacy_entries("prod", Some("pw"), Some("pem"), None);
        backend.fail_bundle_writes.store(true, Ordering::SeqCst);
        let store = KeyringSecretStore::with_backend_for_tests(backend.clone());

        assert!(store.get_password("prod").is_err());
        assert!(!backend.legacy_entries_deleted("prod"));
    }

    #[derive(Debug, Default)]
    struct TestBackend {
        secrets: Mutex<HashMap<String, String>>,
        bundle_reads: AtomicUsize,
        bundle_writes: AtomicUsize,
        fail_bundle_writes: AtomicBool,
    }

    impl TestBackend {
        fn with_legacy_entries(
            profile_name: &str,
            password: Option<&str>,
            private_key: Option<&str>,
            key_passphrase: Option<&str>,
        ) -> Arc<Self> {
            let backend = Arc::new(Self::default());
            if let Some(password) = password {
                backend
                    .secrets
                    .lock()
                    .unwrap()
                    .insert(secret_key(profile_name, PASSWORD_SUFFIX), password.to_string());
            }
            if let Some(private_key) = private_key {
                backend
                    .secrets
                    .lock()
                    .unwrap()
                    .insert(secret_key(profile_name, PRIVATE_KEY_SUFFIX), private_key.to_string());
            }
            if let Some(key_passphrase) = key_passphrase {
                backend.secrets.lock().unwrap().insert(
                    secret_key(profile_name, KEY_PASSPHRASE_SUFFIX),
                    key_passphrase.to_string(),
                );
            }
            backend
        }

        fn with_bundle(profile_name: &str, bundle: SecretBundle) -> Arc<Self> {
            let backend = Arc::new(Self::default());
            backend.store_bundle(profile_name, bundle);
            backend
        }

        fn store_bundle(&self, profile_name: &str, bundle: SecretBundle) {
            self.secrets.lock().unwrap().insert(
                KeyringSecretStore::bundle_account(profile_name),
                encode_bundle(&bundle).unwrap(),
            );
        }

        fn bundle_write_count(&self, profile_name: &str) -> usize {
            let _ = profile_name;
            self.bundle_writes.load(Ordering::SeqCst)
        }

        fn bundle_read_count(&self, profile_name: &str) -> usize {
            let _ = profile_name;
            self.bundle_reads.load(Ordering::SeqCst)
        }

        fn legacy_entries_deleted(&self, profile_name: &str) -> bool {
            let secrets = self.secrets.lock().unwrap();
            LEGACY_SUFFIXES
                .iter()
                .all(|suffix| !secrets.contains_key(&secret_key(profile_name, suffix)))
        }
    }

    impl KeyringBackend for TestBackend {
        fn set_secret(&self, account: &str, value: &str) -> Result<()> {
            if account.ends_with(&format!(":{BUNDLE_SUFFIX}")) {
                if self.fail_bundle_writes.load(Ordering::SeqCst) {
                    return Err(Error::new("simulated bundle write failure"));
                }
                self.bundle_writes.fetch_add(1, Ordering::SeqCst);
            }

            self.secrets
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_string());
            Ok(())
        }

        fn get_secret(&self, account: &str) -> Result<Option<String>> {
            if account.ends_with(&format!(":{BUNDLE_SUFFIX}")) {
                self.bundle_reads.fetch_add(1, Ordering::SeqCst);
            }

            Ok(self.secrets.lock().unwrap().get(account).cloned())
        }

        fn delete_secret(&self, account: &str) -> Result<()> {
            self.secrets.lock().unwrap().remove(account);
            Ok(())
        }
    }
}
