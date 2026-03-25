use std::path::PathBuf;

use connect::{
    doctor::{
        self,
        checks::{
            DoctorEnvironment, LocalDoctorCheckResult, LocalDoctorCheckStatus, LocalDoctorReport,
        },
    },
    error::Error,
};

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
            "PASS app path resolution\n",
            "PASS database open/read/write sanity\n",
            "PASS secret backend initialization\n",
            "PASS SSH agent availability\n",
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
