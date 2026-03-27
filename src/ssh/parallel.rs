use crate::{
    error::{Error, Result},
    store::Profile,
    terminal::prompt::Prompt,
};

use super::{
    connect_authenticated_session, plan_copy, CopyDestinationShape, CopyPlan, CopyPlannerConfig,
    CopySpec, PlannedCopySource, SshClient, SshConnectionContext, SshSession,
};

type DynSshSession = Box<dyn SshSession + Send + 'static>;

pub struct TransferSessionPool {
    effective_threads: usize,
    warnings: Vec<String>,
    primary: DynSshSession,
    extra_sessions: Vec<DynSshSession>,
}

impl TransferSessionPool {
    pub fn effective_threads(&self) -> usize {
        self.effective_threads
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn primary_session_mut(&mut self) -> &mut dyn SshSession {
        &mut *self.primary
    }

    pub fn prepare_plan(
        self,
        spec: CopySpec,
        destination_shape: CopyDestinationShape,
        source: PlannedCopySource,
    ) -> Result<PreparedTransferPlan> {
        let retry = spec.retry;
        let plan = plan_copy(
            spec,
            CopyPlannerConfig {
                effective_threads: self.effective_threads,
                retry,
            },
            destination_shape,
            source,
        )?;

        Ok(PreparedTransferPlan { pool: self, plan })
    }
}

pub struct PreparedTransferPlan {
    pool: TransferSessionPool,
    plan: CopyPlan,
}

impl PreparedTransferPlan {
    pub fn effective_threads(&self) -> usize {
        self.pool.effective_threads()
    }

    pub fn warnings(&self) -> &[String] {
        self.pool.warnings()
    }

    pub fn plan(&self) -> &CopyPlan {
        &self.plan
    }

    pub fn primary_session_mut(&mut self) -> &mut dyn SshSession {
        self.pool.primary_session_mut()
    }

    pub fn into_parts(self) -> (Vec<DynSshSession>, CopyPlan, usize, Vec<String>) {
        let mut sessions = Vec::with_capacity(1 + self.pool.extra_sessions.len());
        sessions.push(self.pool.primary);
        sessions.extend(self.pool.extra_sessions);
        (
            sessions,
            self.plan,
            self.pool.effective_threads,
            self.pool.warnings,
        )
    }
}

pub async fn establish_transfer_sessions(
    ssh: &dyn SshClient,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
    requested_threads: usize,
) -> Result<TransferSessionPool> {
    let requested_threads = requested_threads.max(1);
    let mut sessions = Vec::with_capacity(requested_threads);
    let mut first_degradable_error = None;

    for _ in 0..requested_threads {
        match connect_authenticated_session(ssh, profile, context, prompt).await {
            Ok(mut session) => {
                if requested_threads > 1 {
                    match session.supports_parallel_random_access().await {
                        Ok(true) => {}
                        Ok(false) | Err(_) => {
                            return Err(Error::new(
                                "threaded copy requires a random-access-capable sftp session",
                            ));
                        }
                    }
                }
                sessions.push(session);
            }
            Err(error) => {
                if is_degradable_establishment_error(&error) {
                    if first_degradable_error.is_none() {
                        first_degradable_error = Some(error);
                    }
                    break;
                }
                return Err(error);
            }
        }
    }

    if sessions.is_empty() {
        return Err(first_degradable_error.unwrap_or_else(|| {
            Error::new("failed to establish any random-access-capable transfer sessions")
        }));
    }

    if requested_threads > 1 && sessions.len() == 1 {
        return Err(Error::new(format!(
            "could not establish threaded mode: requested {requested_threads} sessions but only 1 random-access-capable transfer session was available"
        )));
    }

    let effective_threads = sessions.len();
    let warnings = if requested_threads > effective_threads {
        vec![format!(
            "parallel copy degraded from {requested_threads} requested sessions to {effective_threads} random-access-capable sessions"
        )]
    } else {
        Vec::new()
    };

    let mut sessions = sessions;
    let primary = sessions.remove(0);
    Ok(TransferSessionPool {
        effective_threads,
        warnings,
        primary,
        extra_sessions: sessions,
    })
}

fn is_degradable_establishment_error(error: &Error) -> bool {
    match error {
        Error::Io(io_error) => matches!(io_error.kind(), std::io::ErrorKind::ConnectionRefused),
        Error::Message(message) => {
            let message = message.to_ascii_lowercase();
            message.contains("too many concurrent sessions")
                || message.contains("administratively prohibited")
                || message.contains("connection refused")
                || message.contains("maxsessions")
                || message.contains("too many sessions")
        }
        _ => false,
    }
}
