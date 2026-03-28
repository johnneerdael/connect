use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use connect::{
    app::{App, AppPaths, ProfileSecretsInput},
    archive::{BackupPayload, ProfileExportPayload},
    error::Error,
    secrets::{MemorySecretStore, SecretBundle, SecretStore},
    store::{ForwardDefinition, ForwardKind, ProfileInput},
};

struct ArchiveHarness {
    root: PathBuf,
    app: App,
}

impl ArchiveHarness {
    fn new() -> Self {
        let root = unique_temp_path("connect-archive-tests");
        let paths = AppPaths::from_root(&root);
        let app = App::new(paths, Arc::new(MemorySecretStore::default())).unwrap();
        Self { root, app }
    }
}

impl Drop for ArchiveHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn snapshot_backup_includes_profiles_forwards_host_keys_and_secret_bundles() {
    let harness = ArchiveHarness::new();
    harness
        .app
        .save_profile_with_secrets(
            ProfileInput::new("prod", "prod.example.com", "deploy"),
            ProfileSecretsInput {
                password: Some("pw".into()),
                private_key: Some("pem".into()),
                key_passphrase: None,
            },
        )
        .unwrap();
    harness
        .app
        .save_forward(ForwardDefinition {
            profile_name: "prod".into(),
            name: "db".into(),
            kind: ForwardKind::Local,
            bind_host: "127.0.0.1".into(),
            bind_port: 15432,
            target_host: Some("db.internal".into()),
            target_port: Some(5432),
            description: Some("database".into()),
        })
        .unwrap();
    harness
        .app
        .save_host_key("prod.example.com", 22, "ssh-ed25519", "fp-123", "pub-123")
        .unwrap();

    let snapshot: BackupPayload = harness.app.create_backup_snapshot().unwrap();

    assert_eq!(snapshot.profiles.len(), 1);
    assert_eq!(snapshot.forwards.len(), 1);
    assert_eq!(snapshot.host_keys.len(), 1);
    assert_eq!(snapshot.secret_bundles.len(), 1);
    assert_eq!(snapshot.secret_bundles[0].profile_name, "prod");
    assert_eq!(
        snapshot.secret_bundles[0].bundle.password.as_deref(),
        Some("pw")
    );
}

#[test]
fn snapshot_profile_export_includes_one_profile_and_excludes_host_keys() {
    let harness = ArchiveHarness::new();
    harness
        .app
        .save_profile_with_secrets(
            ProfileInput::new("prod", "prod.example.com", "deploy"),
            ProfileSecretsInput {
                password: Some("pw".into()),
                private_key: None,
                key_passphrase: None,
            },
        )
        .unwrap();
    harness
        .app
        .save_forward(ForwardDefinition {
            profile_name: "prod".into(),
            name: "proxy".into(),
            kind: ForwardKind::Socks,
            bind_host: "127.0.0.1".into(),
            bind_port: 1080,
            target_host: None,
            target_port: None,
            description: None,
        })
        .unwrap();
    harness
        .app
        .save_host_key("prod.example.com", 22, "ssh-ed25519", "fp-123", "pub-123")
        .unwrap();

    let snapshot: ProfileExportPayload = harness.app.create_profile_export_snapshot("prod").unwrap();

    assert_eq!(snapshot.profile.name, "prod");
    assert_eq!(snapshot.forwards.len(), 1);
    assert_eq!(snapshot.secret_bundle.password.as_deref(), Some("pw"));
}

#[test]
fn restore_backup_replaces_existing_profiles_forwards_host_keys_and_secrets() {
    let harness = ArchiveHarness::new();
    harness
        .app
        .save_profile_with_secrets(
            ProfileInput::new("old", "old.example.com", "deploy"),
            ProfileSecretsInput {
                password: Some("old-pw".into()),
                private_key: None,
                key_passphrase: None,
            },
        )
        .unwrap();
    harness
        .app
        .save_host_key("old.example.com", 22, "ssh-ed25519", "fp-old", "pub-old")
        .unwrap();

    let replacement = BackupPayload {
        profiles: vec![connect::archive::BackupProfileRecord {
            name: "prod".into(),
            host: "prod.example.com".into(),
            port: 22,
            username: "alice".into(),
            auth_mode: "auto".into(),
            copy_threads: 1,
            has_password: true,
            has_private_key: false,
            has_key_passphrase: false,
            created_at: "2026-03-28T00:00:00Z".into(),
            updated_at: "2026-03-28T00:00:00Z".into(),
        }],
        forwards: vec![connect::archive::BackupForwardRecord {
            profile_name: "prod".into(),
            name: "db".into(),
            kind: "local".into(),
            bind_host: "127.0.0.1".into(),
            bind_port: 15432,
            target_host: Some("db.internal".into()),
            target_port: Some(5432),
            description: None,
        }],
        host_keys: vec![connect::archive::BackupHostKeyRecord {
            host: "prod.example.com".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "fp-new".into(),
            public_key: "pub-new".into(),
            accepted_at: "2026-03-28T00:00:00Z".into(),
        }],
        secret_bundles: vec![connect::archive::ProfileSecretRecord {
            profile_name: "prod".into(),
            bundle: SecretBundle::new().with_password(Some("new-pw".into())),
        }],
    };

    harness.app.restore_backup_snapshot(replacement).unwrap();

    let profiles = harness.app.list_profiles().unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].name, "prod");
    assert_eq!(harness.app.list_forwards("prod").unwrap().len(), 1);
    assert_eq!(harness.app.list_host_keys().unwrap().len(), 1);
    assert_eq!(
        harness
            .app
            .create_profile_export_snapshot("prod")
            .unwrap()
            .secret_bundle
            .password
            .as_deref(),
        Some("new-pw")
    );
}

#[test]
fn import_profile_replaces_only_target_profile_and_its_forwards_and_secrets() {
    let harness = ArchiveHarness::new();
    harness
        .app
        .save_profile_with_secrets(
            ProfileInput::new("prod", "old.example.com", "deploy"),
            ProfileSecretsInput {
                password: Some("old-pw".into()),
                private_key: None,
                key_passphrase: None,
            },
        )
        .unwrap();
    harness
        .app
        .save_profile(ProfileInput::new("keep", "keep.example.com", "deploy"))
        .unwrap();

    let payload = ProfileExportPayload {
        profile: connect::archive::BackupProfileRecord {
            name: "prod".into(),
            host: "prod.example.com".into(),
            port: 2222,
            username: "alice".into(),
            auth_mode: "auto".into(),
            copy_threads: 3,
            has_password: true,
            has_private_key: false,
            has_key_passphrase: false,
            created_at: "2026-03-28T00:00:00Z".into(),
            updated_at: "2026-03-28T00:00:00Z".into(),
        },
        forwards: vec![connect::archive::BackupForwardRecord {
            profile_name: "prod".into(),
            name: "proxy".into(),
            kind: "socks".into(),
            bind_host: "127.0.0.1".into(),
            bind_port: 1080,
            target_host: None,
            target_port: None,
            description: None,
        }],
        secret_bundle: SecretBundle::new().with_password(Some("new-pw".into())),
    };

    harness.app.import_profile_snapshot(payload).unwrap();

    let prod = harness.app.get_profile("prod").unwrap();
    assert_eq!(prod.host, "prod.example.com");
    assert_eq!(prod.port, 2222);
    assert_eq!(harness.app.list_forwards("prod").unwrap().len(), 1);
    assert!(harness.app.get_profile("keep").is_ok());
    assert_eq!(
        harness
            .app
            .create_profile_export_snapshot("prod")
            .unwrap()
            .secret_bundle
            .password
            .as_deref(),
        Some("new-pw")
    );
}

#[test]
fn restore_backup_rolls_back_secret_changes_when_secret_write_fails() {
    let root = unique_temp_path("connect-archive-rollback-tests");
    let paths = AppPaths::from_root(&root);
    let secrets = Arc::new(FailsOnKeyPassphraseSecretStore::default());
    let app = App::new(paths, secrets.clone()).unwrap();
    app.save_profile_with_secrets(
        ProfileInput::new("prod", "prod.example.com", "deploy"),
        ProfileSecretsInput {
            password: Some("old-pw".into()),
            private_key: None,
            key_passphrase: None,
        },
    )
    .unwrap();

    let replacement = BackupPayload {
        profiles: vec![connect::archive::BackupProfileRecord {
            name: "prod".into(),
            host: "prod.example.com".into(),
            port: 22,
            username: "alice".into(),
            auth_mode: "auto".into(),
            copy_threads: 1,
            has_password: true,
            has_private_key: false,
            has_key_passphrase: true,
            created_at: "2026-03-28T00:00:00Z".into(),
            updated_at: "2026-03-28T00:00:00Z".into(),
        }],
        forwards: Vec::new(),
        host_keys: Vec::new(),
        secret_bundles: vec![connect::archive::ProfileSecretRecord {
            profile_name: "prod".into(),
            bundle: SecretBundle::new()
                .with_password(Some("new-pw".into()))
                .with_key_passphrase(Some("should-fail".into())),
        }],
    };

    let error = app.restore_backup_snapshot(replacement).unwrap_err();
    assert!(error.to_string().contains("key passphrase write failed"));
    assert_eq!(
        app.create_profile_export_snapshot("prod")
            .unwrap()
            .secret_bundle
            .password
            .as_deref(),
        Some("old-pw")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[derive(Debug, Default)]
struct FailsOnKeyPassphraseSecretStore {
    inner: MemorySecretStore,
}

impl SecretStore for FailsOnKeyPassphraseSecretStore {
    fn set_password(&self, profile_name: &str, password: &str) -> connect::error::Result<()> {
        self.inner.set_password(profile_name, password)
    }

    fn get_password(&self, profile_name: &str) -> connect::error::Result<Option<String>> {
        self.inner.get_password(profile_name)
    }

    fn set_private_key(&self, profile_name: &str, pem: &str) -> connect::error::Result<()> {
        self.inner.set_private_key(profile_name, pem)
    }

    fn get_private_key(&self, profile_name: &str) -> connect::error::Result<Option<String>> {
        self.inner.get_private_key(profile_name)
    }

    fn set_key_passphrase(
        &self,
        _profile_name: &str,
        _passphrase: &str,
    ) -> connect::error::Result<()> {
        Err(Error::new("key passphrase write failed"))
    }

    fn get_key_passphrase(&self, profile_name: &str) -> connect::error::Result<Option<String>> {
        self.inner.get_key_passphrase(profile_name)
    }

    fn delete_profile_secrets(&self, profile_name: &str) -> connect::error::Result<()> {
        self.inner.delete_profile_secrets(profile_name)
    }
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()))
}
