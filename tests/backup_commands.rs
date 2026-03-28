use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use connect::{
    app::{App, AppPaths, ProfileSecretsInput},
    cli::{
        commands::{backup, profile},
        BackupCommand, BackupCreateArgs, BackupRestoreArgs, ProfileCommand, ProfileExportArgs,
        ProfileImportArgs,
    },
    secrets::MemorySecretStore,
    store::ProfileInput,
    terminal::prompt::Prompt,
};

struct CommandHarness {
    root: PathBuf,
    app: App,
}

impl CommandHarness {
    fn new() -> Self {
        let root = unique_temp_path("connect-backup-command-tests");
        let app = App::new(
            AppPaths::from_root(&root),
            Arc::new(MemorySecretStore::default()),
        )
        .unwrap();
        Self { root, app }
    }
}

impl Drop for CommandHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn backup_restore_requires_confirmation_without_yes_flag() {
    let source = CommandHarness::new();
    source
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

    let archive_path = source.root.join("state.connectbak");
    let create_prompt = FakePrompt::new()
        .with_secret("backup.create.psk", "secret")
        .with_secret("backup.create.psk.confirm", "secret");
    let mut writer = Vec::new();
    backup::run(
        &source.app,
        &create_prompt,
        &BackupCommand::Create(BackupCreateArgs {
            output: archive_path.clone(),
        }),
        &mut writer,
    )
    .unwrap();

    let target = CommandHarness::new();
    target
        .app
        .save_profile(ProfileInput::new("keep", "keep.example.com", "deploy"))
        .unwrap();
    let restore_prompt = FakePrompt::new()
        .with_confirm("backup.restore.confirm", false)
        .with_secret("backup.restore.psk", "secret");
    let mut writer = Vec::new();
    backup::run(
        &target.app,
        &restore_prompt,
        &BackupCommand::Restore(BackupRestoreArgs {
            input: archive_path,
            yes: false,
        }),
        &mut writer,
    )
    .unwrap();

    assert_eq!(target.app.list_profiles().unwrap().len(), 1);
    assert!(String::from_utf8(writer).unwrap().contains("Aborted."));
}

#[test]
fn profile_export_and_import_round_trip_via_handlers() {
    let source = CommandHarness::new();
    source
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

    let archive_path = source.root.join("prod.connectprofile");
    let export_prompt = FakePrompt::new()
        .with_secret("profile.export.psk", "secret")
        .with_secret("profile.export.psk.confirm", "secret");
    let mut writer = Vec::new();
    profile::run(
        &source.app,
        &export_prompt,
        &ProfileCommand::Export(ProfileExportArgs {
            name: "prod".into(),
            output: archive_path.clone(),
        }),
        &mut writer,
    )
    .unwrap();

    let target = CommandHarness::new();
    let import_prompt = FakePrompt::new().with_secret("profile.import.psk", "secret");
    let mut writer = Vec::new();
    profile::run(
        &target.app,
        &import_prompt,
        &ProfileCommand::Import(ProfileImportArgs {
            input: archive_path,
        }),
        &mut writer,
    )
    .unwrap();

    let imported = target.app.get_profile("prod").unwrap();
    assert_eq!(imported.host, "prod.example.com");
    assert!(
        target
            .app
            .create_profile_export_snapshot("prod")
            .unwrap()
            .secret_bundle
            .password
            .is_some()
    );
}

#[derive(Debug, Default)]
struct FakePrompt {
    secret: HashMap<String, String>,
    confirm: HashMap<String, bool>,
}

impl FakePrompt {
    fn new() -> Self {
        Self::default()
    }

    fn with_secret(mut self, key: &str, value: &str) -> Self {
        self.secret.insert(key.to_string(), value.to_string());
        self
    }

    fn with_confirm(mut self, key: &str, value: bool) -> Self {
        self.confirm.insert(key.to_string(), value);
        self
    }
}

impl Prompt for FakePrompt {
    fn prompt(&self, _key: &str, _message: &str, _default: Option<&str>) -> connect::error::Result<String> {
        unreachable!("text prompt not expected in backup command tests")
    }

    fn prompt_secret(&self, key: &str, _message: &str) -> connect::error::Result<Option<String>> {
        Ok(self.secret.get(key).cloned())
    }

    fn confirm(&self, key: &str, _message: &str, default: bool) -> connect::error::Result<bool> {
        Ok(self.confirm.get(key).copied().unwrap_or(default))
    }
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()))
}
