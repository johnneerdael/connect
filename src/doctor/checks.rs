use std::{fs, net::SocketAddr};

use rusqlite::params;
use tokio::runtime::Builder;
use tokio::{net::{lookup_host, TcpStream}, time::{timeout, Duration}};

use crate::{
    app::AppPaths,
    error::{Error, Result},
    secrets::KeyringSecretStore,
    ssh::{self, authenticate_session, verify_observed_host_key, HostKeyVerification, SshClient, SshConnectionContext},
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
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| runtime.block_on(ssh::agent_connection_available()))
            .unwrap_or(false)
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

    let ssh_agent_available = env.ssh_agent_available();
    checks.push(LocalDoctorCheckResult {
        name: "SSH agent availability".into(),
        status: if ssh_agent_available {
            LocalDoctorCheckStatus::Pass
        } else {
            LocalDoctorCheckStatus::Fail
        },
        detail: if ssh_agent_available {
            "available".into()
        } else {
            "not available".into()
        },
    });

    LocalDoctorReport { checks }
}

pub async fn collect_profile_checks(
    env: &dyn DoctorEnvironment,
    app: &crate::app::App,
    profile_name: &str,
    ssh_client: &dyn SshClient,
) -> LocalDoctorReport {
    let mut report = collect_local_checks(env);
    let profile = match app.get_profile(profile_name) {
        Ok(profile) => profile,
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "profile exists".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    };

    report.checks.push(LocalDoctorCheckResult {
        name: "profile exists".into(),
        status: LocalDoctorCheckStatus::Pass,
        detail: format!(
            "loaded {}@{}:{}",
            profile.username, profile.host, profile.port
        ),
    });

    let auth = match <crate::app::App as SshConnectionContext>::load_profile_auth(app, &profile) {
        Ok(auth) => auth,
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "stored secrets consistency".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    };

    report
        .checks
        .push(secret_consistency_check(&profile, &auth));
    report
        .checks
        .push(saved_host_key_check(app, &profile));

    let resolved = match resolve_profile_host(&profile).await {
        Ok(resolved) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "hostname resolution".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: format!(
                    "resolved {} to {}",
                    profile.host,
                    join_addresses(&resolved)
                ),
            });
            resolved
        }
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "hostname resolution".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    };

    match tcp_reachability_check(&profile, &resolved).await {
        Ok(addr) => report.checks.push(LocalDoctorCheckResult {
            name: "TCP reachability".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: format!("connected to {addr}"),
        }),
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "TCP reachability".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    }

    let stored_host_key = match <crate::app::App as SshConnectionContext>::load_host_key(app, &profile) {
        Ok(record) => record,
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "SSH handshake".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    };

    let mut session = match ssh_client.connect(&profile, None).await {
        Ok(session) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "SSH handshake".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: "connected".into(),
            });
            session
        }
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "SSH handshake".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    };

    let observed = match session.observe_host_key().await {
        Ok(observed) => observed,
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "host key verification".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    };

    match verify_observed_host_key(stored_host_key.as_ref(), &observed) {
        Ok(HostKeyVerification::Trusted) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "host key verification".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: "trusted".into(),
            });
        }
        Ok(HostKeyVerification::TrustOnFirstUse) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "host key verification".into(),
                status: LocalDoctorCheckStatus::Pass,
                detail: "trust on first use".into(),
            });
        }
        Err(error) => {
            report.checks.push(LocalDoctorCheckResult {
                name: "host key verification".into(),
                status: LocalDoctorCheckStatus::Fail,
                detail: error.to_string(),
            });
            return report;
        }
    }

    match authenticate_session(&mut *session, &profile, &auth).await {
        Ok(()) => report.checks.push(LocalDoctorCheckResult {
            name: "SSH auth usability".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: format!("usable under {}", profile.auth_mode),
        }),
        Err(error) => report.checks.push(LocalDoctorCheckResult {
            name: "SSH auth usability".into(),
            status: LocalDoctorCheckStatus::Fail,
            detail: error.to_string(),
        }),
    }

    report
}

fn secret_consistency_check(
    profile: &crate::store::Profile,
    auth: &crate::ssh::ProfileAuth,
) -> LocalDoctorCheckResult {
    let mismatches = [
        (
            "password",
            profile.has_password,
            auth.password.is_some(),
        ),
        (
            "private key",
            profile.has_private_key,
            auth.private_key.is_some(),
        ),
        (
            "key passphrase",
            profile.has_key_passphrase,
            auth.key_passphrase.is_some(),
        ),
    ]
    .into_iter()
    .filter_map(|(label, flag, actual)| {
        (flag != actual).then_some(format!("{label} flag={flag} secret={actual}"))
    })
    .collect::<Vec<_>>();

    if mismatches.is_empty() {
        LocalDoctorCheckResult {
            name: "stored secrets consistency".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: format!("consistent for {}", profile.auth_mode),
        }
    } else {
        LocalDoctorCheckResult {
            name: "stored secrets consistency".into(),
            status: LocalDoctorCheckStatus::Fail,
            detail: mismatches.join(", "),
        }
    }
}

fn saved_host_key_check(
    app: &crate::app::App,
    profile: &crate::store::Profile,
) -> LocalDoctorCheckResult {
    match <crate::app::App as SshConnectionContext>::load_host_key(app, profile) {
        Ok(Some(record)) => LocalDoctorCheckResult {
            name: "saved host key".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: format!(
                "present for {}:{} ({})",
                record.host, record.port, record.fingerprint
            ),
        },
        Ok(None) => LocalDoctorCheckResult {
            name: "saved host key".into(),
            status: LocalDoctorCheckStatus::Pass,
            detail: "absent".into(),
        },
        Err(error) => LocalDoctorCheckResult {
            name: "saved host key".into(),
            status: LocalDoctorCheckStatus::Fail,
            detail: error.to_string(),
        },
    }
}

async fn resolve_profile_host(profile: &crate::store::Profile) -> Result<Vec<SocketAddr>> {
    let resolved = lookup_host((profile.host.as_str(), profile.port))
        .await
        .map_err(Error::from)?
        .collect::<Vec<_>>();

    if resolved.is_empty() {
        Err(Error::new("hostname did not resolve to any socket addresses"))
    } else {
        Ok(resolved)
    }
}

async fn tcp_reachability_check(
    profile: &crate::store::Profile,
    resolved: &[SocketAddr],
) -> Result<SocketAddr> {
    let connect_future = async {
        for addr in resolved {
            if let Ok(stream) = TcpStream::connect(addr).await {
                return Ok::<SocketAddr, Error>(stream.peer_addr().map_err(Error::from)?);
            }
        }

        Err(Error::new(format!(
            "unable to connect to {}:{}",
            profile.host, profile.port
        )))
    };

    timeout(Duration::from_secs(5), connect_future)
        .await
        .map_err(|_| Error::new("TCP connection attempt timed out"))?
}

fn join_addresses(addresses: &[SocketAddr]) -> String {
    addresses
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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
