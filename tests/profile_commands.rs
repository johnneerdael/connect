use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use connect::{
    app::{App, AppPaths, SecretBackend},
    error::Error,
    secrets::{MemorySecretStore, SecretStore},
    store::ProfileInput,
};

struct TestHarness {
    root: PathBuf,
    app: App,
    secrets: Arc<MemorySecretStore>,
}

impl TestHarness {
    fn new() -> Self {
        let root = unique_temp_path("connect-profile-tests");
        let paths = AppPaths::from_root(&root);
        let secrets = Arc::new(MemorySecretStore::default());
        let app = App::new(paths, secrets.clone()).expect("app should initialize");

        Self { root, app, secrets }
    }

    fn app(&self) -> &App {
        &self.app
    }

    fn secrets(&self) -> Arc<MemorySecretStore> {
        Arc::clone(&self.secrets)
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn profile_insert_round_trip_preserves_metadata() {
    let harness = TestHarness::new();
    let profile = ProfileInput::new("prod", "prod.example.com", "deploy");

    harness.app().save_profile(profile).unwrap();

    let loaded = harness.app().get_profile("prod").unwrap();
    assert_eq!(loaded.host, "prod.example.com");
    assert_eq!(loaded.username, "deploy");
    assert_eq!(loaded.port, 22);
}

#[test]
fn profile_save_updates_existing_metadata() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod-2.example.com", "root").with_port(2200))
        .unwrap();

    let loaded = harness.app().get_profile("prod").unwrap();
    assert_eq!(loaded.host, "prod-2.example.com");
    assert_eq!(loaded.username, "root");
    assert_eq!(loaded.port, 2200);
}

#[test]
fn profile_delete_cleans_up_stored_secrets() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    harness
        .secrets()
        .set_password("prod", "super-secret")
        .unwrap();
    harness
        .secrets()
        .set_private_key("prod", "pem-data")
        .unwrap();
    harness
        .secrets()
        .set_key_passphrase("prod", "passphrase")
        .unwrap();

    harness.app().delete_profile("prod").unwrap();

    assert!(harness.app().get_profile("prod").is_err());
    assert_eq!(harness.secrets().get_password("prod").unwrap(), None);
    assert_eq!(harness.secrets().get_private_key("prod").unwrap(), None);
    assert_eq!(harness.secrets().get_key_passphrase("prod").unwrap(), None);
}

#[test]
fn list_profiles_returns_all_saved_profiles() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    harness
        .app()
        .save_profile(ProfileInput::new("stage", "stage.example.com", "tester"))
        .unwrap();

    let names: Vec<String> = harness
        .app()
        .list_profiles()
        .unwrap()
        .into_iter()
        .map(|profile| profile.name)
        .collect();

    assert_eq!(names, vec!["prod".to_string(), "stage".to_string()]);
}

#[test]
fn runtime_app_defaults_to_keyring_secret_store() {
    let root = unique_temp_path("connect-runtime-app");
    let paths = AppPaths::from_root(&root);

    let app = App::with_default_secret_store(paths).unwrap();

    assert_eq!(app.secret_backend(), SecretBackend::Keyring);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn profile_delete_keeps_metadata_when_secret_cleanup_fails() {
    let root = unique_temp_path("connect-delete-failure");
    let paths = AppPaths::from_root(&root);
    let secrets = Arc::new(DeleteFailsSecretStore::default());
    let app = App::new(paths, secrets).unwrap();

    app.save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();

    let error = app.delete_profile("prod").unwrap_err();
    assert_eq!(error.to_string(), "secret deletion failed");

    let loaded = app.get_profile("prod").unwrap();
    assert_eq!(loaded.name, "prod");

    let _ = std::fs::remove_dir_all(&root);
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    let temp_root = std::env::temp_dir();
    let process_id = std::process::id();

    for _ in 0..1024 {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = temp_root.join(format!("{prefix}-{process_id}-{id}"));

        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("failed to create test temp dir {}: {error}", path.display()),
        }
    }

    panic!("failed to allocate a unique temp dir for {prefix}");
}

#[allow(dead_code)]
fn _assert_path_exists(path: &Path) {
    assert!(path.exists(), "expected path to exist: {}", path.display());
}

#[derive(Debug, Default)]
struct DeleteFailsSecretStore;

impl SecretStore for DeleteFailsSecretStore {
    fn set_password(&self, _profile_name: &str, _password: &str) -> connect::error::Result<()> {
        Ok(())
    }

    fn get_password(&self, _profile_name: &str) -> connect::error::Result<Option<String>> {
        Ok(None)
    }

    fn set_private_key(&self, _profile_name: &str, _pem: &str) -> connect::error::Result<()> {
        Ok(())
    }

    fn get_private_key(&self, _profile_name: &str) -> connect::error::Result<Option<String>> {
        Ok(None)
    }

    fn set_key_passphrase(
        &self,
        _profile_name: &str,
        _passphrase: &str,
    ) -> connect::error::Result<()> {
        Ok(())
    }

    fn get_key_passphrase(&self, _profile_name: &str) -> connect::error::Result<Option<String>> {
        Ok(None)
    }

    fn delete_profile_secrets(&self, _profile_name: &str) -> connect::error::Result<()> {
        Err(Error::new("secret deletion failed"))
    }
}
