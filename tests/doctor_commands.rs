use std::{
    fs,
    path::PathBuf,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use assert_cmd::Command as AssertCommand;
use connect::{
    doctor::{
        self,
        checks::{
            DoctorEnvironment, LocalDoctorCheckResult, LocalDoctorCheckStatus, LocalDoctorReport,
        },
    },
    error::Error,
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
fn doctor_command_rejects_an_unexpected_profile_argument() {
    let root = TempRoot::new("connect-doctor-profile-rejected");

    connect_test_bin()
        .env("CONNECT_APP_ROOT", &root.path)
        .args(["doctor", "prod"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("unexpected argument 'prod'"));
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
