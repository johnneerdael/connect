use std::{
    collections::HashMap,
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use connect::{
    app::{App, AppPaths, ProfileSecretsInput, SecretBackend},
    cli::{
        commands::{add, edit, list, remove, show},
        AddArgs, EditArgs, RemoveArgs, ShowArgs,
    },
    error::Error,
    secrets::{MemorySecretStore, SecretStore},
    ssh::{
        parse_copy_spec, CopyDirection, ObservedHostKey, RemoteDirectoryEntry, RemoteFileType,
        SshClient, SshSession,
    },
    store::ProfileInput,
    terminal::prompt::Prompt,
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

    fn with_profile(name: &str) -> Self {
        let harness = Self::new();
        harness
            .app()
            .save_profile(ProfileInput::new(name, format!("{name}.example.com"), "deploy"))
            .unwrap();
        harness
    }

    fn app(&self) -> &App {
        &self.app
    }

    fn secrets(&self) -> Arc<MemorySecretStore> {
        Arc::clone(&self.secrets)
    }

    fn save_hostkey(&self, host: &str, port: u16, fingerprint: &str) {
        self.app()
            .save_host_key(
                host,
                port,
                "ssh-ed25519",
                fingerprint,
                &format!("public-key-{fingerprint}"),
            )
            .unwrap();
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
fn add_command_imports_private_key_and_persists_profile() {
    let harness = TestHarness::new();
    let temp_key = TestKey::write_temp_pem();
    let mut output = Vec::new();

    let args = AddArgs {
        name: "prod".into(),
        host: Some("prod.example.com".into()),
        user: Some("deploy".into()),
        port: None,
        password: None,
        private_key: Some(temp_key.path().into()),
        key_passphrase: None,
    };

    add::run(harness.app(), &FakePrompt::default(), &args, &mut output).unwrap();

    let profile = harness.app().get_profile("prod").unwrap();
    assert_eq!(profile.host, "prod.example.com");
    assert_eq!(profile.username, "deploy");
    assert!(profile.has_private_key);
    assert_eq!(
        harness.secrets().get_private_key("prod").unwrap(),
        Some(temp_key.contents().to_string())
    );
}

#[test]
fn add_command_prompts_for_missing_required_fields() {
    let harness = TestHarness::new();
    let prompt = FakePrompt::new()
        .with_text("host", "prod.example.com")
        .with_text("user", "deploy");
    let mut output = Vec::new();

    let args = AddArgs {
        name: "prod".into(),
        host: None,
        user: None,
        port: None,
        password: None,
        private_key: None,
        key_passphrase: None,
    };

    add::run(harness.app(), &prompt, &args, &mut output).unwrap();

    let profile = harness.app().get_profile("prod").unwrap();
    assert_eq!(profile.host, "prod.example.com");
    assert_eq!(profile.username, "deploy");
}

#[test]
fn add_command_stores_password_from_flag() {
    let harness = TestHarness::new();
    let mut output = Vec::new();

    let args = AddArgs {
        name: "prod".into(),
        host: Some("prod.example.com".into()),
        user: Some("deploy".into()),
        port: None,
        password: Some("super-secret".into()),
        private_key: None,
        key_passphrase: None,
    };

    add::run(harness.app(), &FakePrompt::default(), &args, &mut output).unwrap();

    let profile = harness.app().get_profile("prod").unwrap();
    assert!(profile.has_password);
    assert_eq!(
        harness.secrets().get_password("prod").unwrap(),
        Some("super-secret".into())
    );
}

#[test]
fn add_command_rejects_duplicate_profile_names() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    harness.secrets().set_password("prod", "old-secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("prod", true, false, false)
        .unwrap();

    let args = AddArgs {
        name: "prod".into(),
        host: Some("prod-2.example.com".into()),
        user: Some("root".into()),
        port: Some(2200),
        password: Some("new-secret".into()),
        private_key: None,
        key_passphrase: None,
    };

    let error = add::run(harness.app(), &FakePrompt::default(), &args, &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "profile 'prod' already exists");

    let profile = harness.app().get_profile("prod").unwrap();
    assert_eq!(profile.host, "prod.example.com");
    assert_eq!(profile.username, "deploy");
    assert_eq!(profile.port, 22);
    assert_eq!(
        harness.secrets().get_password("prod").unwrap(),
        Some("old-secret".into())
    );
}

#[test]
fn add_command_rejects_reserved_profile_name() {
    let harness = TestHarness::new();

    let args = AddArgs {
        name: "list".into(),
        host: Some("prod.example.com".into()),
        user: Some("deploy".into()),
        port: None,
        password: None,
        private_key: None,
        key_passphrase: None,
    };

    let error = add::run(harness.app(), &FakePrompt::default(), &args, &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "profile name 'list' is reserved");
    assert!(matches!(harness.app().get_profile("list"), Err(Error::ProfileNotFound(_))));
}

#[test]
fn add_command_rejects_single_letter_profile_name() {
    let harness = TestHarness::new();

    let args = AddArgs {
        name: "c".into(),
        host: Some("prod.example.com".into()),
        user: Some("deploy".into()),
        port: None,
        password: None,
        private_key: None,
        key_passphrase: None,
    };

    let error = add::run(harness.app(), &FakePrompt::default(), &args, &mut Vec::new()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "single-letter profile names are reserved to avoid Windows path ambiguity"
    );
    assert!(matches!(harness.app().get_profile("c"), Err(Error::ProfileNotFound(_))));
}

#[test]
fn add_command_rolls_back_secrets_when_secret_write_fails() {
    let root = unique_temp_path("connect-add-secret-failure");
    let paths = AppPaths::from_root(&root);
    let secrets = Arc::new(FailsOnKeyPassphraseSecretStore::default());
    let app = App::new(paths, secrets.clone()).unwrap();

    let args = AddArgs {
        name: "prod".into(),
        host: Some("prod.example.com".into()),
        user: Some("deploy".into()),
        port: None,
        password: Some("super-secret".into()),
        private_key: None,
        key_passphrase: Some("unlock".into()),
    };

    let error = add::run(&app, &FakePrompt::default(), &args, &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "key passphrase write failed");
    assert!(matches!(
        app.get_profile("prod"),
        Err(Error::ProfileNotFound(_))
    ));
    assert_eq!(secrets.get_password("prod").unwrap(), None);
    assert_eq!(secrets.get_key_passphrase("prod").unwrap(), None);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn add_command_preserves_primary_error_when_rollback_fails() {
    let root = unique_temp_path("connect-add-rollback-failure");
    let paths = AppPaths::from_root(&root);
    let secrets = Arc::new(FailsOnKeyPassphraseAndDeleteSecretStore::default());
    let app = App::new(paths, secrets).unwrap();

    let args = AddArgs {
        name: "prod".into(),
        host: Some("prod.example.com".into()),
        user: Some("deploy".into()),
        port: None,
        password: Some("super-secret".into()),
        private_key: None,
        key_passphrase: Some("unlock".into()),
    };

    let error = add::run(&app, &FakePrompt::default(), &args, &mut Vec::new()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("key passphrase write failed"));
    assert!(message.contains("rollback failed"));
    assert!(message.contains("secret deletion failed"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn add_command_rolls_back_new_secrets_when_metadata_save_fails() {
    let harness = TestHarness::new();
    break_database(&harness.root);

    let args = AddArgs {
        name: "prod".into(),
        host: Some("prod.example.com".into()),
        user: Some("deploy".into()),
        port: None,
        password: Some("super-secret".into()),
        private_key: None,
        key_passphrase: None,
    };

    let error = add::run(
        harness.app(),
        &FakePrompt::default(),
        &args,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("directory") || error.to_string().contains("unable"));
    assert!(matches!(
        harness.app().get_profile("prod"),
        Err(Error::ProfileNotFound(_)) | Err(Error::Io(_)) | Err(Error::Sqlite(_))
    ));
    assert_eq!(harness.secrets().get_password("prod").unwrap(), None);
}

#[test]
fn edit_command_updates_only_supplied_fields() {
    let harness = TestHarness::new();
    let temp_key = TestKey::write_temp_pem();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();

    let args = EditArgs {
        name: "prod".into(),
        host: Some("prod-2.example.com".into()),
        user: None,
        port: Some(2200),
        password: Some("new-password".into()),
        private_key: Some(temp_key.path().into()),
        key_passphrase: None,
    };

    edit::run(
        harness.app(),
        &FakePrompt::default(),
        &args,
        &mut Vec::new(),
    )
    .unwrap();

    let profile = harness.app().get_profile("prod").unwrap();
    assert_eq!(profile.host, "prod-2.example.com");
    assert_eq!(profile.username, "deploy");
    assert_eq!(profile.port, 2200);
    assert!(profile.has_password);
    assert!(profile.has_private_key);
    assert_eq!(
        harness.secrets().get_password("prod").unwrap(),
        Some("new-password".into())
    );
    assert_eq!(
        harness.secrets().get_private_key("prod").unwrap(),
        Some(temp_key.contents().into())
    );
}

#[test]
fn edit_command_rejects_reserved_profile_name() {
    let harness = TestHarness::new();
    harness
        .app()
        .save_profile(ProfileInput::new("list", "prod.example.com", "deploy"))
        .unwrap();

    let args = EditArgs {
        name: "list".into(),
        host: Some("prod-2.example.com".into()),
        user: None,
        port: None,
        password: None,
        private_key: None,
        key_passphrase: None,
    };

    let error = edit::run(harness.app(), &FakePrompt::default(), &args, &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "profile name 'list' is reserved");

    let profile = harness.app().get_profile("list").unwrap();
    assert_eq!(profile.host, "prod.example.com");
}

#[test]
fn edit_command_allows_existing_single_letter_profile_name() {
    let harness = TestHarness::new();
    harness
        .app()
        .save_profile(ProfileInput::new("c", "prod.example.com", "deploy"))
        .unwrap();

    let args = EditArgs {
        name: "c".into(),
        host: Some("prod-2.example.com".into()),
        user: None,
        port: None,
        password: None,
        private_key: None,
        key_passphrase: None,
    };

    edit::run(harness.app(), &FakePrompt::default(), &args, &mut Vec::new()).unwrap();

    let profile = harness.app().get_profile("c").unwrap();
    assert_eq!(profile.host, "prod-2.example.com");
}

#[test]
fn edit_command_rolls_back_overwritten_secrets_when_secret_write_fails() {
    let root = unique_temp_path("connect-edit-secret-failure");
    let paths = AppPaths::from_root(&root);
    let secrets = Arc::new(FailsOnKeyPassphraseSecretStore::default());
    let app = App::new(paths, secrets.clone()).unwrap();

    app.save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    app.save_profile_with_secrets(
        ProfileInput::new("prod", "prod.example.com", "deploy"),
        ProfileSecretsInput {
            password: Some("old-secret".into()),
            private_key: None,
            key_passphrase: None,
        },
    )
    .unwrap();

    let args = EditArgs {
        name: "prod".into(),
        host: Some("prod-2.example.com".into()),
        user: None,
        port: None,
        password: Some("new-secret".into()),
        private_key: None,
        key_passphrase: Some("unlock".into()),
    };

    let error = edit::run(&app, &FakePrompt::default(), &args, &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "key passphrase write failed");

    let profile = app.get_profile("prod").unwrap();
    assert_eq!(profile.host, "prod.example.com");
    assert_eq!(profile.username, "deploy");
    assert!(profile.has_password);
    assert!(!profile.has_key_passphrase);
    assert_eq!(
        secrets.get_password("prod").unwrap(),
        Some("old-secret".into())
    );
    assert_eq!(secrets.get_key_passphrase("prod").unwrap(), None);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn remove_command_requires_confirmation_without_yes_flag() {
    let harness = TestHarness::new();
    let prompt = FakePrompt::new().with_confirm("remove", false);

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();

    let args = RemoveArgs {
        name: "prod".into(),
        yes: false,
    };

    remove::run(harness.app(), &prompt, &args, &mut Vec::new()).unwrap();

    assert!(harness.app().get_profile("prod").is_ok());
}

#[test]
fn remove_command_deletes_profile_and_secrets_with_yes_flag() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    harness.secrets().set_password("prod", "secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("prod", true, false, false)
        .unwrap();

    let args = RemoveArgs {
        name: "prod".into(),
        yes: true,
    };

    remove::run(
        harness.app(),
        &FakePrompt::default(),
        &args,
        &mut Vec::new(),
    )
    .unwrap();

    assert!(matches!(
        harness.app().get_profile("prod"),
        Err(Error::ProfileNotFound(_))
    ));
    assert_eq!(harness.secrets().get_password("prod").unwrap(), None);
}

#[test]
fn list_command_prints_concise_rows() {
    let harness = TestHarness::new();
    let mut output = Vec::new();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    harness
        .app()
        .save_profile(ProfileInput::new("stage", "stage.example.com", "tester").with_port(2200))
        .unwrap();

    list::run(harness.app(), &mut output).unwrap();

    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("prod\tdeploy@prod.example.com:22"));
    assert!(stdout.contains("stage\ttester@stage.example.com:2200"));
}

#[test]
fn show_command_prints_metadata_and_redacted_secret_availability_only() {
    let harness = TestHarness::new();
    let mut output = Vec::new();

    harness
        .app()
        .save_profile(ProfileInput::new("prod", "prod.example.com", "deploy"))
        .unwrap();
    harness.secrets().set_password("prod", "secret").unwrap();
    harness.secrets().set_private_key("prod", "pem").unwrap();
    harness
        .app()
        .update_profile_secret_flags("prod", true, true, false)
        .unwrap();

    let args = ShowArgs {
        name: "prod".into(),
    };

    show::run(harness.app(), &args, &mut output).unwrap();

    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("Name: prod"));
    assert!(stdout.contains("Host: prod.example.com"));
    assert!(stdout.contains("Username: deploy"));
    assert!(stdout.contains("Password: configured"));
    assert!(stdout.contains("Private key: configured"));
    assert!(stdout.contains("Key passphrase: not configured"));
    assert!(!stdout.contains("secret"));
    assert!(!stdout.contains("pem"));
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

#[tokio::test]
async fn connect_uses_profile_and_rejects_host_key_mismatch() {
    let harness = TestHarness::with_profile("prod");
    harness.save_hostkey("prod.example.com", 22, "expected-fingerprint");

    let ssh = FakeConnectSshClient::with_hostkey("different-fingerprint");
    let result = harness
        .app()
        .connect_profile("prod", &ssh, &FakePrompt::default())
        .await;

    assert!(matches!(result, Err(Error::Message(message)) if message == "saved host key does not match the server host key"));
}

#[tokio::test]
async fn connect_tries_private_key_before_password() {
    let harness = TestHarness::with_profile("prod");
    harness.save_hostkey("prod.example.com", 22, "fp-123");
    harness
        .secrets()
        .set_private_key("prod", "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
        .unwrap();
    harness.secrets().set_password("prod", "super-secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("prod", true, true, false)
        .unwrap();

    let ssh = FakeConnectSshClient::key_rejected_then_password_succeeds();

    harness
        .app()
        .connect_profile("prod", &ssh, &FakePrompt::default())
        .await
        .unwrap();

    assert_eq!(ssh.auth_attempts(), vec!["key", "password"]);
}

#[tokio::test]
async fn connect_propagates_remote_exit_status() {
    let harness = TestHarness::with_profile("prod");
    harness.save_hostkey("prod.example.com", 22, "fp-123");
    harness.secrets().set_password("prod", "super-secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("prod", true, false, false)
        .unwrap();

    let ssh = FakeConnectSshClient::with_exit_status(23);
    let error = harness
        .app()
        .connect_profile("prod", &ssh, &FakePrompt::default())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::RemoteExitStatus(23)));
}

#[tokio::test]
async fn copy_uses_profile_and_rejects_host_key_mismatch() {
    let harness = TestHarness::with_profile("prod");
    harness.save_hostkey("prod.example.com", 22, "expected-fingerprint");
    let source = TestFile::write_temp("artifact.txt", "payload");
    let spec = parse_copy_spec(
        source.path().to_string_lossy().as_ref(),
        "prod:/tmp/artifact.txt",
        false,
    )
    .unwrap();

    let ssh = FakeCopySshClient::with_hostkey("different-fingerprint");
    let result = harness
        .app()
        .copy(&spec, &ssh, &FakePrompt::default())
        .await;

    assert!(matches!(result, Err(Error::Message(message)) if message == "saved host key does not match the server host key"));
}

#[tokio::test]
async fn copy_tries_private_key_before_password() {
    let harness = TestHarness::with_profile("prod");
    harness.save_hostkey("prod.example.com", 22, "fp-123");
    harness
        .secrets()
        .set_private_key("prod", "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
        .unwrap();
    harness.secrets().set_password("prod", "super-secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("prod", true, true, false)
        .unwrap();

    let source = TestFile::write_temp("artifact.txt", "payload");
    let spec = parse_copy_spec(
        source.path().to_string_lossy().as_ref(),
        "prod:/tmp/artifact.txt",
        false,
    )
    .unwrap();
    let ssh = FakeCopySshClient::key_rejected_then_password_succeeds();

    harness
        .app()
        .copy(&spec, &ssh, &FakePrompt::default())
        .await
        .unwrap();

    assert_eq!(ssh.auth_attempts(), vec!["key", "password"]);
    assert_eq!(
        ssh.transfers(),
        vec![(CopyDirection::Upload, source.path().to_path_buf(), "/tmp/artifact.txt".into())]
    );
}

#[tokio::test]
async fn copy_rejects_remote_directory_without_recursive_flag() {
    let harness = TestHarness::with_profile("prod");
    harness.save_hostkey("prod.example.com", 22, "fp-123");
    harness.secrets().set_password("prod", "super-secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("prod", true, false, false)
        .unwrap();

    let destination = unique_temp_path("connect-copy-download");
    let spec = parse_copy_spec("prod:/var/log", &destination.to_string_lossy(), false).unwrap();
    let ssh = FakeCopySshClient::with_remote_directory("/var/log");

    let error = harness
        .app()
        .copy(&spec, &ssh, &FakePrompt::default())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("--recursive"));

    let _ = fs::remove_dir_all(destination);
}

#[tokio::test]
async fn copy_accepts_explicit_remote_prefix_for_single_letter_profile() {
    let harness = TestHarness::new();
    harness
        .app()
        .save_profile(ProfileInput::new("p", "prod.example.com", "deploy"))
        .unwrap();
    harness.save_hostkey("prod.example.com", 22, "fp-123");
    harness.secrets().set_password("p", "super-secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("p", true, false, false)
        .unwrap();

    let destination = unique_temp_path("connect-copy-single-letter");
    let spec = parse_copy_spec("@p:/tmp/artifact.txt", &destination.to_string_lossy(), false).unwrap();
    let ssh = FakeCopySshClient::with_hostkey("fp-123");
    ssh.state
        .lock()
        .unwrap()
        .remote_paths
        .insert("/tmp/artifact.txt".into(), RemoteFileType::File);

    harness
        .app()
        .copy(&spec, &ssh, &FakePrompt::default())
        .await
        .unwrap();

    assert_eq!(
        ssh.transfers(),
        vec![(
            CopyDirection::Download,
            destination.join("artifact.txt"),
            "/tmp/artifact.txt".into()
        )]
    );

    let _ = fs::remove_dir_all(destination);
}

#[tokio::test]
async fn copy_accepts_explicit_remote_prefix_for_at_prefixed_profile() {
    let harness = TestHarness::new();
    harness
        .app()
        .save_profile(ProfileInput::new("@prod", "prod.example.com", "deploy"))
        .unwrap();
    harness.save_hostkey("prod.example.com", 22, "fp-123");
    harness.secrets().set_password("@prod", "super-secret").unwrap();
    harness
        .app()
        .update_profile_secret_flags("@prod", true, false, false)
        .unwrap();

    let destination = unique_temp_path("connect-copy-at-profile");
    let spec = parse_copy_spec("@@prod:/tmp/artifact.txt", &destination.to_string_lossy(), false)
        .unwrap();
    let ssh = FakeCopySshClient::with_hostkey("fp-123");
    ssh.state
        .lock()
        .unwrap()
        .remote_paths
        .insert("/tmp/artifact.txt".into(), RemoteFileType::File);

    harness
        .app()
        .copy(&spec, &ssh, &FakePrompt::default())
        .await
        .unwrap();

    assert_eq!(
        ssh.transfers(),
        vec![(
            CopyDirection::Download,
            destination.join("artifact.txt"),
            "/tmp/artifact.txt".into()
        )]
    );

    let _ = fs::remove_dir_all(destination);
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

fn break_database(root: &Path) {
    let database_path = AppPaths::from_root(root).database_path;
    fs::remove_file(&database_path).expect("database file should be removable");
    fs::create_dir(&database_path).expect("database path should become a directory");
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

#[derive(Debug, Default)]
struct FailsOnKeyPassphraseAndDeleteSecretStore {
    inner: MemorySecretStore,
}

impl SecretStore for FailsOnKeyPassphraseAndDeleteSecretStore {
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

    fn delete_profile_secrets(&self, _profile_name: &str) -> connect::error::Result<()> {
        Err(Error::new("secret deletion failed"))
    }
}

#[derive(Debug, Default)]
struct FakePrompt {
    text: HashMap<String, String>,
    secret: HashMap<String, String>,
    confirm: HashMap<String, bool>,
}

impl FakePrompt {
    fn new() -> Self {
        Self::default()
    }

    fn with_text(mut self, key: &str, value: &str) -> Self {
        self.text.insert(key.to_string(), value.to_string());
        self
    }

    fn with_confirm(mut self, key: &str, value: bool) -> Self {
        self.confirm.insert(key.to_string(), value);
        self
    }
}

impl Prompt for FakePrompt {
    fn prompt(
        &self,
        key: &str,
        _message: &str,
        _default: Option<&str>,
    ) -> connect::error::Result<String> {
        self.text
            .get(key)
            .cloned()
            .ok_or_else(|| Error::new(format!("missing text response for {key}")))
    }

    fn prompt_secret(&self, key: &str, _message: &str) -> connect::error::Result<Option<String>> {
        Ok(self.secret.get(key).cloned())
    }

    fn confirm(&self, key: &str, _message: &str, _default: bool) -> connect::error::Result<bool> {
        self.confirm
            .get(key)
            .copied()
            .ok_or_else(|| Error::new(format!("missing confirm response for {key}")))
    }
}

#[derive(Debug, Clone)]
struct FakeConnectSshClient {
    state: Arc<std::sync::Mutex<FakeConnectState>>,
}

#[derive(Debug, Clone)]
struct FakeCopySshClient {
    state: Arc<std::sync::Mutex<FakeCopyState>>,
}

#[derive(Debug, Clone)]
struct FakeCopyState {
    observed: ObservedHostKey,
    auth_attempts: Vec<&'static str>,
    key_result: bool,
    password_result: bool,
    remote_paths: HashMap<String, RemoteFileType>,
    remote_directories: HashMap<String, Vec<RemoteDirectoryEntry>>,
    transfers: Vec<(CopyDirection, PathBuf, String)>,
}

impl FakeCopySshClient {
    fn with_hostkey(fingerprint: &str) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(FakeCopyState {
                observed: ObservedHostKey {
                    host: "prod.example.com".into(),
                    port: 22,
                    algorithm: "ssh-ed25519".into(),
                    fingerprint: fingerprint.into(),
                    public_key: format!("public-key-{fingerprint}"),
                },
                auth_attempts: Vec::new(),
                key_result: true,
                password_result: true,
                remote_paths: HashMap::new(),
                remote_directories: HashMap::new(),
                transfers: Vec::new(),
            })),
        }
    }

    fn key_rejected_then_password_succeeds() -> Self {
        let client = Self::with_hostkey("fp-123");
        client.state.lock().unwrap().key_result = false;
        client
    }

    fn with_remote_directory(path: &str) -> Self {
        let client = Self::with_hostkey("fp-123");
        client
            .state
            .lock()
            .unwrap()
            .remote_paths
            .insert(path.into(), RemoteFileType::Directory);
        client
    }

    fn auth_attempts(&self) -> Vec<&'static str> {
        self.state.lock().unwrap().auth_attempts.clone()
    }

    fn transfers(&self) -> Vec<(CopyDirection, PathBuf, String)> {
        self.state.lock().unwrap().transfers.clone()
    }
}

impl SshClient for FakeCopySshClient {
    fn connect<'a>(
        &'a self,
        _profile: &'a connect::store::Profile,
        _expected_host_key: Option<&'a connect::store::HostKeyRecord>,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<Box<dyn SshSession + Send + 'static>>>
                + Send
                + 'a,
        >,
    > {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            Ok(Box::new(FakeCopySession { state }) as Box<dyn SshSession + Send>)
        })
    }
}

struct FakeCopySession {
    state: Arc<std::sync::Mutex<FakeCopyState>>,
}

impl SshSession for FakeCopySession {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<ObservedHostKey>> + Send + 'a>> {
        let observed = self.state.lock().unwrap().observed.clone();
        Box::pin(async move { Ok(observed) })
    }

    fn authenticate_public_key<'a>(
        &'a mut self,
        _username: &'a str,
        _private_key: &'a str,
        _passphrase: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        let result = {
            let mut state = self.state.lock().unwrap();
            state.auth_attempts.push("key");
            state.key_result
        };
        Box::pin(async move { Ok(result) })
    }

    fn authenticate_password<'a>(
        &'a mut self,
        _username: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        let result = {
            let mut state = self.state.lock().unwrap();
            state.auth_attempts.push("password");
            state.password_result
        };
        Box::pin(async move { Ok(result) })
    }

    fn open_shell<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u32>> + Send + 'a>> {
        Box::pin(async move { Ok(0) })
    }

    fn remote_file_type<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = connect::error::Result<Option<RemoteFileType>>> + Send + 'a>,
    > {
        let file_type = self.state.lock().unwrap().remote_paths.get(path).copied();
        Box::pin(async move { Ok(file_type) })
    }

    fn read_remote_dir<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<Vec<RemoteDirectoryEntry>>> + Send + 'a,
        >,
    > {
        let entries = self
            .state
            .lock()
            .unwrap()
            .remote_directories
            .get(path)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(entries) })
    }

    fn create_remote_dir_all<'a>(
        &'a mut self,
        _path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        Box::pin(async move { Ok(()) })
    }

    fn upload_file<'a>(
        &'a mut self,
        local_path: &'a Path,
        remote_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        let mut state = self.state.lock().unwrap();
        state
            .transfers
            .push((CopyDirection::Upload, local_path.to_path_buf(), remote_path.into()));
        Box::pin(async move { Ok(()) })
    }

    fn download_file<'a>(
        &'a mut self,
        remote_path: &'a str,
        local_path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        let mut state = self.state.lock().unwrap();
        state
            .transfers
            .push((CopyDirection::Download, local_path.to_path_buf(), remote_path.into()));
        Box::pin(async move { Ok(()) })
    }
}

#[derive(Debug, Clone)]
struct FakeConnectState {
    observed: ObservedHostKey,
    auth_attempts: Vec<&'static str>,
    key_result: bool,
    password_result: bool,
    shell_opened: bool,
    exit_status: u32,
}

impl FakeConnectSshClient {
    fn with_hostkey(fingerprint: &str) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(FakeConnectState {
                observed: ObservedHostKey {
                    host: "prod.example.com".into(),
                    port: 22,
                    algorithm: "ssh-ed25519".into(),
                    fingerprint: fingerprint.into(),
                    public_key: format!("public-key-{fingerprint}"),
                },
                auth_attempts: Vec::new(),
                key_result: true,
                password_result: true,
                shell_opened: false,
                exit_status: 0,
            })),
        }
    }

    fn key_rejected_then_password_succeeds() -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(FakeConnectState {
                observed: ObservedHostKey {
                    host: "prod.example.com".into(),
                    port: 22,
                    algorithm: "ssh-ed25519".into(),
                    fingerprint: "fp-123".into(),
                    public_key: "public-key-fp-123".into(),
                },
                auth_attempts: Vec::new(),
                key_result: false,
                password_result: true,
                shell_opened: false,
                exit_status: 0,
            })),
        }
    }

    fn with_exit_status(exit_status: u32) -> Self {
        let client = Self::with_hostkey("fp-123");
        client.state.lock().unwrap().exit_status = exit_status;
        client
    }

    fn auth_attempts(&self) -> Vec<&'static str> {
        self.state.lock().unwrap().auth_attempts.clone()
    }
}

impl SshClient for FakeConnectSshClient {
    fn connect<'a>(
        &'a self,
        _profile: &'a connect::store::Profile,
        _expected_host_key: Option<&'a connect::store::HostKeyRecord>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = connect::error::Result<Box<dyn SshSession + Send + 'static>>,
                > + Send
                + 'a,
        >,
    > {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            Ok(Box::new(FakeConnectSession { state }) as Box<dyn SshSession + Send>)
        })
    }
}

struct FakeConnectSession {
    state: Arc<std::sync::Mutex<FakeConnectState>>,
}

impl SshSession for FakeConnectSession {
    fn observe_host_key<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = connect::error::Result<ObservedHostKey>> + Send + 'a>,
    > {
        let observed = self.state.lock().unwrap().observed.clone();
        Box::pin(async move { Ok(observed) })
    }

    fn authenticate_public_key<'a>(
        &'a mut self,
        _username: &'a str,
        _private_key: &'a str,
        _passphrase: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = connect::error::Result<bool>> + Send + 'a>>
    {
        let result = {
            let mut state = self.state.lock().unwrap();
            state.auth_attempts.push("key");
            state.key_result
        };
        Box::pin(async move { Ok(result) })
    }

    fn authenticate_password<'a>(
        &'a mut self,
        _username: &'a str,
        _password: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = connect::error::Result<bool>> + Send + 'a>>
    {
        let result = {
            let mut state = self.state.lock().unwrap();
            state.auth_attempts.push("password");
            state.password_result
        };
        Box::pin(async move { Ok(result) })
    }

    fn open_shell<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = connect::error::Result<u32>> + Send + 'a>>
    {
        self.state.lock().unwrap().shell_opened = true;
        let exit_status = self.state.lock().unwrap().exit_status;
        Box::pin(async move { Ok(exit_status) })
    }
}

struct TestKey {
    path: PathBuf,
    contents: &'static str,
}

struct TestFile {
    path: PathBuf,
}

impl TestFile {
    fn write_temp(name: &str, contents: &str) -> Self {
        let root = unique_temp_path("connect-test-file");
        let path = root.join(name);
        std::fs::write(&path, contents).expect("test file should be written");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

impl TestKey {
    fn write_temp_pem() -> Self {
        let root = unique_temp_path("connect-test-key");
        let path = root.join("id_rsa");
        let contents = "-----BEGIN TEST PRIVATE KEY-----\nabc123\n-----END TEST PRIVATE KEY-----\n";
        std::fs::write(&path, contents).expect("test private key should be written");

        Self { path, contents }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn contents(&self) -> &str {
        self.contents
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}
