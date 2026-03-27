use crate::{
    error::{Error, Result},
    store::Profile,
    terminal::prompt::Prompt,
};

use super::{connect_authenticated_session, SshClient, SshConnectionContext, SshSession};

type DynSshSession = Box<dyn SshSession + Send + 'static>;

pub struct TransferSessionPool {
    effective_threads: usize,
    warnings: Vec<String>,
    primary: DynSshSession,
    _extra_sessions: Vec<DynSshSession>,
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
    let mut first_error = None;

    for _ in 0..requested_threads {
        match connect_authenticated_session(ssh, profile, context, prompt).await {
            Ok(mut session) => {
                if requested_threads > 1
                    && sessions.is_empty()
                    && !session.supports_parallel_random_access().await?
                {
                    return Err(Error::new(
                        "random-access sftp support is unavailable for threaded copy",
                    ));
                }
                sessions.push(session);
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    if sessions.is_empty() {
        return Err(first_error.unwrap_or_else(|| {
            Error::new("failed to establish any authenticated transfer sessions")
        }));
    }

    if requested_threads > 1 && sessions.len() == 1 {
        return Err(Error::new(format!(
            "could not establish threaded mode: requested {requested_threads} sessions but only 1 authenticated transfer session was available"
        )));
    }

    let effective_threads = sessions.len();
    let warnings = if requested_threads > effective_threads {
        vec![format!(
            "parallel copy degraded from {requested_threads} requested sessions to {effective_threads} authenticated transfer sessions"
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
        _extra_sessions: sessions,
    })
}
