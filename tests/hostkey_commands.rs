use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use assert_cmd::Command;
use connect::{
    app::{App, AppPaths},
    cli::{
        commands::hostkeys,
        types::{HostkeysCommand, HostkeysDeleteArgs, HostkeysListArgs},
    },
    error::Error,
    secrets::MemorySecretStore,
    ssh::{ObservedHostKey, ObservedHostKeySource},
    store::{HostKeyStore, ProfileInput},
    terminal::prompt::Prompt,
};

struct TestHarness {
    root: PathBuf,
    app: App,
}

impl TestHarness {
    fn new() -> Self {
        let root = unique_temp_path("connect-hostkey-tests");
        let paths = AppPaths::from_root(&root);
        let secrets = Arc::new(MemorySecretStore::default());
        let app = App::new(paths, secrets).expect("app should initialize");

        Self { root, app }
    }

    fn with_saved_hostkey(host: &str, port: u16) -> Self {
        let harness = Self::new();
        harness
            .app()
            .save_host_key(host, port, "ssh-ed25519", "fp-123", "pubkey-123")
            .expect("host key should be saved");
        harness
    }

    fn with_profile(name: &str) -> Self {
        let harness = Self::new();
        harness
            .app()
            .save_profile(ProfileInput::new(name, "prod.example.com", "deploy"))
            .expect("profile should be saved");
        harness
    }

    fn app(&self) -> &App {
        &self.app
    }

    fn hostkey_exists(&self, host: &str, port: u16) -> bool {
        self.hostkey_record(host, port).is_some()
    }

    fn hostkey_record(&self, host: &str, port: u16) -> Option<connect::store::HostKeyRecord> {
        let store = HostKeyStore::new(connect::store::Database::new(
            AppPaths::from_root(&self.root).database_path,
        ));
        store
            .get(host, port)
            .expect("host key lookup should succeed")
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn hostkey_delete_removes_saved_record() {
    let harness = TestHarness::with_saved_hostkey("prod.example.com", 22);

    hostkeys::run(
        harness.app(),
        &FakePrompt::unused(),
        &HostkeysCommand::Delete(HostkeysDeleteArgs {
            target: "prod.example.com:22".into(),
            yes: true,
        }),
        &mut Vec::new(),
    )
    .unwrap();

    assert!(!harness.hostkey_exists("prod.example.com", 22));
}

#[test]
fn hostkey_get_returns_saved_record_fields() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_host_key("prod.example.com", 22, "ssh-ed25519", "fp-123", "pubkey-123")
        .unwrap();

    let record = harness
        .hostkey_record("prod.example.com", 22)
        .expect("host key should exist");

    assert_eq!(record.host, "prod.example.com");
    assert_eq!(record.port, 22);
    assert_eq!(record.algorithm, "ssh-ed25519");
    assert_eq!(record.fingerprint, "fp-123");
    assert_eq!(record.public_key, "pubkey-123");
}

#[test]
fn hostkey_list_prints_deterministic_rows() {
    let harness = TestHarness::new();
    let mut output = Vec::new();

    harness
        .app()
        .save_host_key("b.example.com", 2200, "ssh-rsa", "fp-b", "pub-b")
        .unwrap();
    harness
        .app()
        .save_host_key("a.example.com", 22, "ssh-ed25519", "fp-a", "pub-a")
        .unwrap();

    hostkeys::run(
        harness.app(),
        &FakePrompt::unused(),
        &HostkeysCommand::List(HostkeysListArgs),
        &mut output,
    )
    .unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        "a.example.com:22\tssh-ed25519\tfp-a\nb.example.com:2200\tssh-rsa\tfp-b\n"
    );
}

#[test]
fn hostkey_delete_requires_host_port_format() {
    let harness = TestHarness::new();

    let error = hostkeys::run(
        harness.app(),
        &FakePrompt::unused(),
        &HostkeysCommand::Delete(HostkeysDeleteArgs {
            target: "prod.example.com".into(),
            yes: true,
        }),
        &mut Vec::new(),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "host key target must be in host:port format");
}

#[test]
fn hostkeys_list_command_routes_through_binary() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_host_key("prod.example.com", 22, "ssh-ed25519", "fp-123", "pubkey-123")
        .unwrap();

    connect_test_bin()
        .env("CONNECT_APP_ROOT", &harness.root)
        .args(["hostkeys", "list"])
        .assert()
        .success()
        .stdout("prod.example.com:22\tssh-ed25519\tfp-123\n");
}

#[test]
fn hostkeys_delete_command_routes_through_binary() {
    let harness = TestHarness::new();

    harness
        .app()
        .save_host_key("prod.example.com", 22, "ssh-ed25519", "fp-123", "pubkey-123")
        .unwrap();

    connect_test_bin()
        .env("CONNECT_APP_ROOT", &harness.root)
        .args(["hostkeys", "delete", "prod.example.com:22", "--yes"])
        .assert()
        .success()
        .stdout("Removed host key 'prod.example.com:22'.\n");

    assert!(!harness.hostkey_exists("prod.example.com", 22));
}

#[tokio::test]
async fn first_connect_prompts_accepts_and_reuses_saved_hostkey() {
    let harness = TestHarness::with_profile("prod");
    let prompt = FakePrompt::accepting();
    let ssh = FakeSshClient::with_hostkey("ssh-ed25519", "fp-123");

    harness
        .app()
        .connect_profile("prod", &ssh, &prompt)
        .await
        .unwrap();
    assert!(harness.hostkey_exists("prod.example.com", 22));

    harness
        .app()
        .connect_profile("prod", &ssh, &FakePrompt::unused())
        .await
        .unwrap();
}

#[tokio::test]
async fn first_connect_rejects_observed_endpoint_mismatch() {
    let harness = TestHarness::with_profile("prod");
    let ssh = FakeSshClient::with_observed_hostkey(
        "unexpected.example.com",
        2200,
        "ssh-ed25519",
        "fp-123",
    );

    let error = harness
        .app()
        .connect_profile("prod", &ssh, &FakePrompt::accepting())
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "observed host key endpoint does not match selected profile"
    );
    assert!(!harness.hostkey_exists("prod.example.com", 22));
    assert!(!harness.hostkey_exists("unexpected.example.com", 2200));
}

#[tokio::test]
async fn first_connect_shows_host_port_algorithm_and_fingerprint_in_prompt() {
    let harness = TestHarness::with_profile("prod");
    let prompt = FakePrompt::accepting();
    let ssh = FakeSshClient::with_hostkey("ssh-ed25519", "fp-123");

    harness
        .app()
        .connect_profile("prod", &ssh, &prompt)
        .await
        .unwrap();

    let message = prompt
        .last_confirm_message()
        .expect("trust prompt should be shown");
    assert!(message.contains("Host: prod.example.com"));
    assert!(message.contains("Port: 22"));
    assert!(message.contains("Algorithm: ssh-ed25519"));
    assert!(message.contains("Fingerprint: fp-123"));
}

#[tokio::test]
async fn first_connect_rejects_untrusted_hostkey() {
    let harness = TestHarness::with_profile("prod");
    let prompt = FakePrompt::rejecting();
    let ssh = FakeSshClient::with_hostkey("ssh-ed25519", "fp-123");

    let error = harness
        .app()
        .connect_profile("prod", &ssh, &prompt)
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "host key was not trusted");
    assert!(!harness.hostkey_exists("prod.example.com", 22));
}

#[tokio::test]
async fn connect_rejects_changed_saved_hostkey() {
    let harness = TestHarness::with_profile("prod");
    harness
        .app()
        .save_host_key("prod.example.com", 22, "ssh-ed25519", "fp-old", "pub-old")
        .unwrap();
    let ssh = FakeSshClient::with_hostkey("ssh-ed25519", "fp-new");

    let error = harness
        .app()
        .connect_profile("prod", &ssh, &FakePrompt::unused())
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "saved host key does not match the server host key"
    );
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

fn connect_test_bin() -> Command {
    Command::cargo_bin("connect").expect("binary should build")
}

#[derive(Debug, Default)]
struct FakePrompt {
    trust: Option<bool>,
    last_confirm_message: Arc<Mutex<Option<String>>>,
}

impl FakePrompt {
    fn accepting() -> Self {
        Self {
            trust: Some(true),
            last_confirm_message: Arc::new(Mutex::new(None)),
        }
    }

    fn rejecting() -> Self {
        Self {
            trust: Some(false),
            last_confirm_message: Arc::new(Mutex::new(None)),
        }
    }

    fn unused() -> Self {
        Self {
            trust: None,
            last_confirm_message: Arc::new(Mutex::new(None)),
        }
    }

    fn last_confirm_message(&self) -> Option<String> {
        self.last_confirm_message
            .lock()
            .expect("confirm message mutex should not be poisoned")
            .clone()
    }
}

impl Prompt for FakePrompt {
    fn prompt(
        &self,
        key: &str,
        _message: &str,
        _default: Option<&str>,
    ) -> connect::error::Result<String> {
        Err(Error::new(format!("unexpected text prompt for {key}")))
    }

    fn prompt_secret(&self, key: &str, _message: &str) -> connect::error::Result<Option<String>> {
        Err(Error::new(format!("unexpected secret prompt for {key}")))
    }

    fn confirm(&self, key: &str, message: &str, _default: bool) -> connect::error::Result<bool> {
        match key {
            "hostkey.trust" => {
                *self
                    .last_confirm_message
                    .lock()
                    .expect("confirm message mutex should not be poisoned") =
                    Some(message.to_string());
                self.trust
                    .ok_or_else(|| Error::new("unexpected host key trust prompt"))
            }
            _ => Err(Error::new(format!("unexpected confirm prompt for {key}"))),
        }
    }
}

#[derive(Debug, Clone)]
struct FakeSshClient {
    observed: ObservedHostKey,
}

impl FakeSshClient {
    fn with_hostkey(algorithm: &str, fingerprint: &str) -> Self {
        Self::with_observed_hostkey("prod.example.com", 22, algorithm, fingerprint)
    }

    fn with_observed_hostkey(host: &str, port: u16, algorithm: &str, fingerprint: &str) -> Self {
        Self {
            observed: ObservedHostKey {
                host: host.into(),
                port,
                algorithm: algorithm.into(),
                fingerprint: fingerprint.into(),
                public_key: format!("public-key-{fingerprint}"),
            },
        }
    }
}

impl ObservedHostKeySource for FakeSshClient {
    fn observe_host_key<'a>(
        &'a self,
        _profile: &'a connect::store::Profile,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<ObservedHostKey>> + Send + 'a>> {
        let observed = self.observed.clone();
        Box::pin(async move { Ok(observed) })
    }
}
