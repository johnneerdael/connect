use std::{
    future::Future,
    fs,
    net::TcpListener,
    path::PathBuf,
    pin::Pin,
    thread,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use assert_cmd::Command as AssertCommand;
use clap::Parser;
use connect::{
    app::{App, AppPaths, ProfileSecretsInput},
    cli::{Cli, Command as CliCommand},
    doctor::{
        self,
        checks::{
            collect_profile_checks, DoctorEnvironment, LocalDoctorCheckResult,
            LocalDoctorCheckStatus, LocalDoctorReport,
        },
    },
    error::Error,
    secrets::MemorySecretStore,
    ssh::{ObservedHostKey, SshClient, SshSession},
    store::{AuthMode, ProfileInput},
};

fn connect_test_bin() -> AssertCommand {
    AssertCommand::cargo_bin("connect").expect("binary should build")
}

fn unique_temp_root(prefix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic")
        .as_nanos();
    #[cfg(unix)]
    {
        PathBuf::from("/tmp").join(format!("{prefix}-{stamp}-{}", std::process::id()))
    }

    #[cfg(not(unix))]
    {
        std::env::temp_dir().join(format!("{prefix}-{stamp}-{}", std::process::id()))
    }
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(prefix: &str) -> Self {
        let path = unique_temp_root(prefix);
        fs::create_dir_all(&path).expect("temp root should be creatable");
        Self { path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn spawn_agent_socket(path: &PathBuf) -> thread::JoinHandle<()> {
    use std::os::unix::net::UnixListener;

    let listener = UnixListener::bind(path).expect("agent socket should bind");
    thread::spawn(move || {
        let _ = listener.accept();
    })
}

#[derive(Clone)]
struct FakeDoctorEnvironment {
    app_path_resolution: Result<(), String>,
    database_sanity: Result<(), String>,
    secret_backend: Result<(), String>,
    ssh_agent_available: bool,
}

impl DoctorEnvironment for FakeDoctorEnvironment {
    fn resolve_app_paths(&self) -> Result<connect::app::AppPaths, Error> {
        self.app_path_resolution
            .as_ref()
            .map_err(|message| Error::new(message.clone()))
            .map(|_| connect::app::AppPaths {
                config_dir: PathBuf::from("/tmp/connect-config"),
                data_dir: PathBuf::from("/tmp/connect-data"),
                database_path: PathBuf::from("/tmp/connect-data/connect.db"),
            })
    }

    fn check_database(&self, _paths: &connect::app::AppPaths) -> Result<(), Error> {
        self.database_sanity
            .as_ref()
            .map(|_| ())
            .map_err(|message| Error::new(message.clone()))
    }

    fn initialize_secret_backend(&self) -> Result<(), Error> {
        self.secret_backend
            .as_ref()
            .map(|_| ())
            .map_err(|message| Error::new(message.clone()))
    }

    fn ssh_agent_available(&self) -> bool {
        self.ssh_agent_available
    }
}

#[test]
fn doctor_without_profile_reports_local_environment_checks() {
    let env = FakeDoctorEnvironment {
        app_path_resolution: Ok(()),
        database_sanity: Ok(()),
        secret_backend: Ok(()),
        ssh_agent_available: true,
    };
    let mut output = Vec::new();

    let report = doctor::collect_local_checks(&env);
    doctor::output::write_report(&report, &mut output).unwrap();

    assert!(report.is_success());
    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "PASS app path resolution: resolved application directories\n",
            "PASS database open/read/write sanity: opened /tmp/connect-data/connect.db\n",
            "PASS secret backend initialization: initialized\n",
            "PASS SSH agent availability: available\n",
        )
    );
}

#[test]
fn doctor_exit_behavior_fails_when_any_required_local_check_fails() {
    let env = FakeDoctorEnvironment {
        app_path_resolution: Err("missing app dirs".into()),
        database_sanity: Ok(()),
        secret_backend: Ok(()),
        ssh_agent_available: false,
    };

    let report = doctor::collect_local_checks(&env);

    assert!(!report.is_success());
    assert_eq!(report.exit_code(), 1);
    assert_eq!(
        report.checks,
        vec![
            LocalDoctorCheckResult {
                name: "app path resolution".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: "missing app dirs".into(),
            },
            LocalDoctorCheckResult {
                name: "database open/read/write sanity".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: "skipped because app path resolution failed".into(),
            },
            LocalDoctorCheckResult {
                name: "secret backend initialization".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: "initialized".into(),
            },
            LocalDoctorCheckResult {
                name: "SSH agent availability".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: "not available".into(),
            },
        ]
    );
}

#[test]
fn doctor_report_aggregation_marks_all_passes_as_success() {
    let report = LocalDoctorReport {
        checks: vec![
            LocalDoctorCheckResult {
                name: "check-a".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: "ok".into(),
            },
            LocalDoctorCheckResult {
                name: "check-b".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: "ok".into(),
            },
        ],
    };

    assert!(report.is_success());
    assert_eq!(report.exit_code(), 0);
}

#[cfg(unix)]
#[test]
fn doctor_command_routes_through_binary_for_success() {
    let root = TempRoot::new("connect-doctor-success");
    let agent_socket = root.path.join("agent.sock");
    let agent_thread = spawn_agent_socket(&agent_socket);
    let database_path = root.path.join("data").join("connect.db");
    let expected_stdout = format!(
        "PASS app path resolution: resolved application directories\n\
PASS database open/read/write sanity: opened {}\n\
PASS secret backend initialization: initialized\n\
PASS SSH agent availability: available\n",
        database_path.display(),
    );

    connect_test_bin()
        .env("CONNECT_APP_ROOT", &root.path)
        .env("SSH_AUTH_SOCK", &agent_socket)
        .args(["doctor"])
        .assert()
        .success()
        .stdout(expected_stdout);

    let _ = agent_thread.join();
}

#[test]
fn doctor_command_routes_through_binary_for_failure() {
    let root = TempRoot::new("connect-doctor-failure");

    connect_test_bin()
        .env("CONNECT_APP_ROOT", &root.path)
        .env("SSH_AUTH_SOCK", root.path.join("missing-agent.sock"))
        .args(["doctor"])
        .assert()
        .failure()
        .stdout(predicates::str::contains("FAIL SSH agent availability"));
}

#[test]
fn doctor_command_parses_an_optional_profile_argument() {
    let parsed = Cli::try_parse_from(["connect", "doctor", "prod"]).expect("CLI should parse");

    match parsed.command {
        Some(CliCommand::Doctor(args)) => {
            assert_eq!(args.profile.as_deref(), Some("prod"));
        }
        other => panic!("expected doctor command, got {other:?}"),
    }
}

#[tokio::test]
async fn doctor_profile_reports_missing_profile_as_a_failed_check() {
    let harness = DoctorProfileHarness::new("connect-doctor-profile-missing");
    let env = FakeDoctorEnvironment {
        app_path_resolution: Ok(()),
        database_sanity: Ok(()),
        secret_backend: Ok(()),
        ssh_agent_available: true,
    };
    let report = collect_profile_checks(
        &env,
        &harness.app,
        "missing",
        &FakeDoctorSshClient::matched("127.0.0.1", harness.port),
    )
    .await;

    assert!(!report.is_success());
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "profile exists" && check.status == LocalDoctorCheckStatus::Fail));
}

#[tokio::test]
async fn doctor_profile_reports_successful_live_checks_for_a_valid_profile() {
    let harness = DoctorProfileHarness::new("connect-doctor-profile-success");
    let env = FakeDoctorEnvironment {
        app_path_resolution: Ok(()),
        database_sanity: Ok(()),
        secret_backend: Ok(()),
        ssh_agent_available: true,
    };
    harness
        .app
        .save_profile_with_secrets(
            ProfileInput::new("prod", "127.0.0.1", "deploy")
                .with_port(harness.port)
                .with_auth_mode(AuthMode::StoredOnly),
            ProfileSecretsInput {
                private_key: Some("private-key".into()),
                ..Default::default()
            },
        )
        .unwrap();

    let report = collect_profile_checks(
        &env,
        &harness.app,
        "prod",
        &FakeDoctorSshClient::matched("127.0.0.1", harness.port),
    )
        .await;

    assert!(report.is_success());
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "profile exists" && check.status == LocalDoctorCheckStatus::Pass));
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "SSH handshake" && check.status == LocalDoctorCheckStatus::Pass));
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "SSH auth usability" && check.status == LocalDoctorCheckStatus::Pass));
}

#[tokio::test]
async fn doctor_profile_rejects_a_host_key_mismatch() {
    let harness = DoctorProfileHarness::new("connect-doctor-profile-mismatch");
    let env = FakeDoctorEnvironment {
        app_path_resolution: Ok(()),
        database_sanity: Ok(()),
        secret_backend: Ok(()),
        ssh_agent_available: true,
    };
    harness
        .app
        .save_profile_with_secrets(
            ProfileInput::new("prod", "127.0.0.1", "deploy")
                .with_port(harness.port)
                .with_auth_mode(AuthMode::StoredOnly),
            ProfileSecretsInput {
                private_key: Some("private-key".into()),
                ..Default::default()
            },
        )
        .unwrap();
    harness
        .app
        .save_host_key(
            "127.0.0.1",
            harness.port,
            "ssh-ed25519",
            "fp-old",
            "public-key-fp-old",
        )
        .unwrap();

    let report = collect_profile_checks(
        &env,
        &harness.app,
        "prod",
        &FakeDoctorSshClient::mismatched("127.0.0.1", harness.port),
    )
        .await;

    assert!(!report.is_success());
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "host key verification" && check.status == LocalDoctorCheckStatus::Fail));
}

#[tokio::test]
async fn doctor_profile_rejects_an_unusable_auth_mode() {
    let harness = DoctorProfileHarness::new("connect-doctor-profile-auth-failure");
    let env = FakeDoctorEnvironment {
        app_path_resolution: Ok(()),
        database_sanity: Ok(()),
        secret_backend: Ok(()),
        ssh_agent_available: true,
    };
    harness
        .app
        .save_profile(
            ProfileInput::new("prod", "127.0.0.1", "deploy")
                .with_port(harness.port)
                .with_auth_mode(AuthMode::PasswordOnly),
        )
        .unwrap();

    let report = collect_profile_checks(
        &env,
        &harness.app,
        "prod",
        &FakeDoctorSshClient::matched("127.0.0.1", harness.port),
    )
        .await;

    assert!(!report.is_success());
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "SSH auth usability" && check.status == LocalDoctorCheckStatus::Fail));
}

#[test]
fn doctor_output_includes_pass_details() {
    let report = LocalDoctorReport {
        checks: vec![LocalDoctorCheckResult {
            name: "check-a".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: "all good".into(),
        }],
    };
    let mut output = Vec::new();

    doctor::output::write_report(&report, &mut output).unwrap();

    assert_eq!(String::from_utf8(output).unwrap(), "PASS check-a: all good\n");
}

struct DoctorProfileHarness {
    _root: TempRoot,
    _listener: TcpListener,
    app: App,
    port: u16,
}

impl DoctorProfileHarness {
    fn new(prefix: &str) -> Self {
        let root = TempRoot::new(prefix);
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener should bind");
        let port = listener.local_addr().expect("listener addr should resolve").port();
        let app = App::new(AppPaths::from_root(&root.path), Arc::new(MemorySecretStore::default()))
            .expect("app should initialize");
        Self {
            _root: root,
            _listener: listener,
            app,
            port,
        }
    }
}

#[derive(Clone)]
struct FakeDoctorSshClient {
    observed: ObservedHostKey,
    handshake_error: Option<String>,
    auth_attempts: Arc<Mutex<Vec<&'static str>>>,
    agent_result: bool,
    key_result: bool,
    password_result: bool,
}

impl FakeDoctorSshClient {
    fn matched(host: &str, port: u16) -> Self {
        Self {
            observed: ObservedHostKey {
                host: host.into(),
                port,
                algorithm: "ssh-ed25519".into(),
                fingerprint: "fp-123".into(),
                public_key: "public-key-fp-123".into(),
            },
            handshake_error: None,
            auth_attempts: Arc::new(Mutex::new(Vec::new())),
            agent_result: false,
            key_result: true,
            password_result: true,
        }
    }

    fn mismatched(host: &str, port: u16) -> Self {
        let mut client = Self::matched(host, port);
        client.observed.fingerprint = "fp-new".into();
        client.observed.public_key = "public-key-fp-new".into();
        client
    }
}

impl SshClient for FakeDoctorSshClient {
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
        let observed = self.observed.clone();
        let handshake_error = self.handshake_error.clone();
        let auth_attempts = Arc::clone(&self.auth_attempts);
        let agent_result = self.agent_result;
        let key_result = self.key_result;
        let password_result = self.password_result;

        Box::pin(async move {
            if let Some(message) = handshake_error {
                return Err(Error::new(message));
            }

            Ok(Box::new(FakeDoctorSshSession {
                observed,
                auth_attempts,
                agent_result,
                key_result,
                password_result,
            }) as Box<dyn SshSession + Send>)
        })
    }
}

struct FakeDoctorSshSession {
    observed: ObservedHostKey,
    auth_attempts: Arc<Mutex<Vec<&'static str>>>,
    agent_result: bool,
    key_result: bool,
    password_result: bool,
}

impl SshSession for FakeDoctorSshSession {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<ObservedHostKey>> + Send + 'a>> {
        let observed = self.observed.clone();
        Box::pin(async move { Ok(observed) })
    }

    fn authenticate_agent<'a>(
        &'a mut self,
        _username: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        let result = self.agent_result;
        let attempts = Arc::clone(&self.auth_attempts);
        Box::pin(async move {
            attempts.lock().unwrap().push("agent");
            Ok(result)
        })
    }

    fn authenticate_public_key<'a>(
        &'a mut self,
        _username: &'a str,
        _private_key: &'a str,
        _passphrase: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        let result = self.key_result;
        let attempts = Arc::clone(&self.auth_attempts);
        Box::pin(async move {
            attempts.lock().unwrap().push("key");
            Ok(result)
        })
    }

    fn authenticate_password<'a>(
        &'a mut self,
        _username: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        let result = self.password_result;
        let attempts = Arc::clone(&self.auth_attempts);
        Box::pin(async move {
            attempts.lock().unwrap().push("password");
            Ok(result)
        })
    }

    fn open_shell<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u32>> + Send + 'a>> {
        Box::pin(async move { Err(Error::new("doctor should not open a shell")) })
    }
}
