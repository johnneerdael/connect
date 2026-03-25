use std::fs;

use rusqlite::params;

use crate::{
    app::AppPaths,
    error::{Error, Result},
    secrets::KeyringSecretStore,
    ssh,
    store::Database,
};

const APP_NAME: &str = "connect";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDoctorCheckStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDoctorCheckResult {
    pub name: String,
    pub status: LocalDoctorCheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDoctorReport {
    pub checks: Vec<LocalDoctorCheckResult>,
}

impl LocalDoctorReport {
    pub fn is_success(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == LocalDoctorCheckStatus::Pass)
    }

    pub fn exit_code(&self) -> i32 {
        if self.is_success() {
            0
        } else {
            1
        }
    }
}

pub trait DoctorEnvironment {
    fn resolve_app_paths(&self) -> Result<AppPaths>;
    fn check_database(&self, paths: &AppPaths) -> Result<()>;
    fn initialize_secret_backend(&self) -> Result<()>;
    fn ssh_agent_available(&self) -> bool;
}

pub struct DefaultDoctorEnvironment;

impl DoctorEnvironment for DefaultDoctorEnvironment {
    fn resolve_app_paths(&self) -> Result<AppPaths> {
        AppPaths::detect()
    }

    fn check_database(&self, paths: &AppPaths) -> Result<()> {
        check_database_sanity(paths)
    }

    fn initialize_secret_backend(&self) -> Result<()> {
        let _ = KeyringSecretStore::new(APP_NAME)?;
        Ok(())
    }

    fn ssh_agent_available(&self) -> bool {
        ssh::agent_auth_available()
    }
}

pub fn collect_local_checks(env: &dyn DoctorEnvironment) -> LocalDoctorReport {
    let app_paths_result = env.resolve_app_paths();
    let mut checks = Vec::with_capacity(4);

    checks.push(match &app_paths_result {
        Ok(_) => LocalDoctorCheckResult {
            name: "app path resolution".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: "resolved application directories".into(),
        },
        Err(error) => LocalDoctorCheckResult {
            name: "app path resolution".into(),
            status: LocalDoctorCheckStatus::Fail,
            detail: error.to_string(),
        },
    });

    checks.push(match &app_paths_result {
        Ok(paths) => match env.check_database(paths) {
            Ok(()) => LocalDoctorCheckResult {
                name: "database open/read/write sanity".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: format!("opened {}", paths.database_path.display()),
            },
            Err(error) => LocalDoctorCheckResult {
                name: "database open/read/write sanity".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            },
        },
        Err(_) => LocalDoctorCheckResult {
            name: "database open/read/write sanity".into(),
            status: LocalDoctorCheckStatus::Fail,
            detail: "skipped because app path resolution failed".into(),
        },
    });

    checks.push(match env.initialize_secret_backend() {
        Ok(()) => LocalDoctorCheckResult {
            name: "secret backend initialization".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: "initialized".into(),
        },
        Err(error) => LocalDoctorCheckResult {
            name: "secret backend initialization".into(),
            status: LocalDoctorCheckStatus::Fail,
            detail: error.to_string(),
        },
    });

    checks.push(LocalDoctorCheckResult {
        name: "SSH agent availability".into(),
        status: if env.ssh_agent_available() {
            LocalDoctorCheckStatus::Pass
        } else {
            LocalDoctorCheckStatus::Fail
        },
        detail: if env.ssh_agent_available() {
            "available".into()
        } else {
            "not available".into()
        },
    });

    LocalDoctorReport { checks }
}

fn check_database_sanity(paths: &AppPaths) -> Result<()> {
    fs::create_dir_all(&paths.config_dir)?;
    if let Some(parent) = paths.database_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let database = Database::new(paths.database_path.clone());
    database.initialize()?;
    let mut connection = database.connect()?;
    let transaction = connection.transaction()?;

    let probe_name = format!(
        "__connect_doctor_probe_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| Error::new(format!("system clock error: {error}")))?
            .as_nanos()
    );

    transaction.execute(
        "INSERT INTO profiles (name, host, port, username, auth_mode, has_password, has_private_key, has_key_passphrase)
         VALUES (?1, ?2, ?3, ?4, 'auto', 0, 0, 0)",
        params![probe_name, "doctor.invalid", 22_i64, "doctor"],
    )?;

    let loaded_name: String = transaction.query_row(
        "SELECT name FROM profiles WHERE name = ?1",
        params![probe_name],
        |row| row.get(0),
    )?;

    if loaded_name != probe_name {
        return Err(Error::new("database probe read back unexpected data"));
    }

    transaction.rollback()?;
    Ok(())
}
