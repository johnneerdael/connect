use crate::{
    error::{Error, Result},
    store::{AuthMode, HostKeyRecord, Profile},
    terminal::prompt::Prompt,
};

use super::{
    verify_observed_host_key, HostKeyVerification, ObservedHostKey, SshClient, SshSession,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileAuth {
    pub auth_mode: AuthMode,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub key_passphrase: Option<String>,
}

impl ProfileAuth {
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.private_key.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSpec {
    pub command: Vec<String>,
    pub pty: bool,
}

impl ExecSpec {
    pub fn new(command: Vec<String>, pty: bool) -> Self {
        Self { command, pty }
    }

    pub fn command_line(&self) -> Result<String> {
        if self.command.is_empty() {
            return Err(Error::new("command is required"));
        }

        Ok(self
            .command
            .iter()
            .map(|segment| shell_quote(segment))
            .collect::<Vec<_>>()
            .join(" "))
    }
}

pub trait SshConnectionContext {
    fn load_profile_auth(&self, profile: &Profile) -> Result<ProfileAuth>;
    fn load_host_key(&self, profile: &Profile) -> Result<Option<HostKeyRecord>>;
    fn save_host_key(&self, observed: &ObservedHostKey) -> Result<()>;
}

pub async fn open_profile(
    ssh: &dyn SshClient,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
) -> Result<()> {
    let mut session = connect_authenticated_session(ssh, profile, context, prompt).await?;
    let exit_status = session.open_shell().await?;
    disconnect_session_best_effort(session);
    if exit_status == 0 {
        Ok(())
    } else {
        Err(Error::RemoteExitStatus(exit_status))
    }
}

pub async fn exec_profile(
    ssh: &dyn SshClient,
    spec: &ExecSpec,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
) -> Result<()> {
    let mut session = connect_authenticated_session(ssh, profile, context, prompt).await?;
    let exit_status = session.execute_command(spec).await?;
    disconnect_session_best_effort(session);
    if exit_status == 0 {
        Ok(())
    } else {
        Err(Error::RemoteExitStatus(exit_status))
    }
}

fn disconnect_session_best_effort(session: Box<dyn SshSession + Send + 'static>) {
    tokio::spawn(async move {
        let mut session = session;
        let _ = session.disconnect().await;
    });
}

pub(crate) async fn connect_authenticated_session(
    ssh: &dyn SshClient,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
) -> Result<Box<dyn SshSession + Send + 'static>> {
    let stored = context.load_host_key(profile)?;
    let mut session = ssh.connect(profile, stored.as_ref()).await?;
    let observed = session.observe_host_key().await?;
    if observed.host != profile.host || observed.port != profile.port {
        return Err(Error::new(
            "observed host key endpoint does not match selected profile",
        ));
    }

    match verify_observed_host_key(stored.as_ref(), &observed)? {
        HostKeyVerification::Trusted => {}
        HostKeyVerification::TrustOnFirstUse => {
            if !prompt.confirm_host_key_trust(&observed)? {
                return Err(Error::new("host key was not trusted"));
            }
            context.save_host_key(&observed)?;
        }
    }

    let auth = context.load_profile_auth(profile)?;
    authenticate_session(&mut *session, profile, &auth).await?;
    Ok(session)
}

pub async fn authenticate_session(
    session: &mut dyn SshSession,
    profile: &Profile,
    auth: &ProfileAuth,
) -> Result<()> {
    match auth.auth_mode {
        AuthMode::Auto => authenticate_auto(session, profile, auth).await,
        AuthMode::AgentOnly => authenticate_agent_only(session, profile).await,
        AuthMode::StoredOnly => authenticate_stored_only(session, profile, auth).await,
        AuthMode::PasswordOnly => authenticate_password_only(session, profile, auth).await,
    }
}

async fn authenticate_auto(
    session: &mut dyn SshSession,
    profile: &Profile,
    auth: &ProfileAuth,
) -> Result<()> {
    if super::agent_auth_available() && session.authenticate_agent(&profile.username).await? {
        return Ok(());
    }

    if try_stored_key(session, profile, auth).await? {
        return Ok(());
    }

    if try_password(session, profile, auth).await? {
        return Ok(());
    }

    if !super::agent_auth_available() && auth.is_empty() {
        Err(Error::new(
            "profile has no SSH authentication material and no SSH agent is available",
        ))
    } else {
        Err(Error::new("ssh authentication failed"))
    }
}

async fn authenticate_agent_only(session: &mut dyn SshSession, profile: &Profile) -> Result<()> {
    if !super::agent_auth_available() {
        return Err(Error::new("ssh agent is not available"));
    }

    if session.authenticate_agent(&profile.username).await? {
        Ok(())
    } else {
        Err(Error::new("ssh agent authentication failed"))
    }
}

async fn authenticate_stored_only(
    session: &mut dyn SshSession,
    profile: &Profile,
    auth: &ProfileAuth,
) -> Result<()> {
    if try_stored_key(session, profile, auth).await? {
        return Ok(());
    }

    if try_password(session, profile, auth).await? {
        return Ok(());
    }

    if auth.is_empty() {
        Err(Error::new(
            "profile has no stored SSH authentication material",
        ))
    } else {
        Err(Error::new("stored SSH authentication failed"))
    }
}

async fn authenticate_password_only(
    session: &mut dyn SshSession,
    profile: &Profile,
    auth: &ProfileAuth,
) -> Result<()> {
    if try_password(session, profile, auth).await? {
        Ok(())
    } else if auth.password.is_none() {
        Err(Error::new("profile has no stored password"))
    } else {
        Err(Error::new("password authentication failed"))
    }
}

async fn try_stored_key(
    session: &mut dyn SshSession,
    profile: &Profile,
    auth: &ProfileAuth,
) -> Result<bool> {
    match auth.private_key.as_deref() {
        Some(private_key) => {
            session
                .authenticate_public_key(
                    &profile.username,
                    private_key,
                    auth.key_passphrase.as_deref(),
                )
                .await
        }
        None => Ok(false),
    }
}

async fn try_password(
    session: &mut dyn SshSession,
    profile: &Profile,
    auth: &ProfileAuth,
) -> Result<bool> {
    match auth.password.as_deref() {
        Some(password) => {
            session
                .authenticate_password(&profile.username, password)
                .await
        }
        None => Ok(false),
    }
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        "''".to_string()
    } else if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}
