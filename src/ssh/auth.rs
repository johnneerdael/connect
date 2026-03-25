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
    drop(session);
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
    drop(session);
    if exit_status == 0 {
        Ok(())
    } else {
        Err(Error::RemoteExitStatus(exit_status))
    }
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

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::mpsc, thread, time::Duration};

    use crate::{
        ssh::ObservedHostKey,
        store::{AuthMode, HostKeyRecord, Profile},
        terminal::prompt::Prompt,
    };

    use super::*;

    #[test]
    fn open_profile_allows_runtime_to_shutdown_after_remote_exit() {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime should build");
            let ssh = TestSshClient::with_pending_disconnect();
            let profile = test_profile();
            let context = TestConnectionContext;
            let prompt = AcceptPrompt;

            let result = runtime.block_on(open_profile(&ssh, &profile, &context, &prompt));
            tx.send(result).expect("result should be sent");
        });

        let result = rx
            .recv_timeout(Duration::from_millis(250))
            .expect("open_profile should not block runtime shutdown");
        assert!(result.is_ok());
    }

    #[test]
    fn exec_profile_allows_runtime_to_shutdown_after_remote_exit() {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime should build");
            let ssh = TestSshClient::with_pending_disconnect();
            let profile = test_profile();
            let context = TestConnectionContext;
            let prompt = AcceptPrompt;
            let spec = ExecSpec::new(vec!["true".into()], false);

            let result = runtime.block_on(exec_profile(&ssh, &spec, &profile, &context, &prompt));
            tx.send(result).expect("result should be sent");
        });

        let result = rx
            .recv_timeout(Duration::from_millis(250))
            .expect("exec_profile should not block runtime shutdown");
        assert!(result.is_ok());
    }

    fn test_profile() -> Profile {
        Profile {
            name: "prod".into(),
            host: "prod.example.com".into(),
            port: 22,
            username: "deploy".into(),
            auth_mode: AuthMode::PasswordOnly,
            has_password: true,
            has_private_key: false,
            has_key_passphrase: false,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    struct TestConnectionContext;

    impl SshConnectionContext for TestConnectionContext {
        fn load_profile_auth(&self, _profile: &Profile) -> Result<ProfileAuth> {
            Ok(ProfileAuth {
                auth_mode: AuthMode::PasswordOnly,
                password: Some("secret".into()),
                private_key: None,
                key_passphrase: None,
            })
        }

        fn load_host_key(&self, _profile: &Profile) -> Result<Option<HostKeyRecord>> {
            Ok(None)
        }

        fn save_host_key(&self, _observed: &ObservedHostKey) -> Result<()> {
            Ok(())
        }
    }

    struct AcceptPrompt;

    impl Prompt for AcceptPrompt {
        fn prompt(&self, _key: &str, _message: &str, _default: Option<&str>) -> Result<String> {
            Ok(String::new())
        }

        fn prompt_secret(&self, _key: &str, _message: &str) -> Result<Option<String>> {
            Ok(None)
        }

        fn confirm(&self, _key: &str, _message: &str, _default: bool) -> Result<bool> {
            Ok(true)
        }
    }

    #[derive(Clone, Copy)]
    struct TestSshClient {
        pending_disconnect: bool,
    }

    impl TestSshClient {
        fn with_pending_disconnect() -> Self {
            Self {
                pending_disconnect: true,
            }
        }
    }

    impl SshClient for TestSshClient {
        fn connect<'a>(
            &'a self,
            profile: &'a Profile,
            _expected_host_key: Option<&'a HostKeyRecord>,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn SshSession + Send + 'static>>> + Send + 'a>>
        {
            let profile = profile.clone();
            let pending_disconnect = self.pending_disconnect;
            Box::pin(async move {
                Ok(Box::new(TestSession {
                    observed: ObservedHostKey {
                        host: profile.host.clone(),
                        port: profile.port,
                        algorithm: "ssh-ed25519".into(),
                        fingerprint: "fp-123".into(),
                        public_key: "pub-123".into(),
                    },
                    pending_disconnect,
                }) as Box<dyn SshSession + Send>)
            })
        }
    }

    struct TestSession {
        observed: ObservedHostKey,
        pending_disconnect: bool,
    }

    impl SshSession for TestSession {
        fn observe_host_key<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<ObservedHostKey>> + Send + 'a>> {
            let observed = self.observed.clone();
            Box::pin(async move { Ok(observed) })
        }

        fn authenticate_public_key<'a>(
            &'a mut self,
            _username: &'a str,
            _private_key: &'a str,
            _passphrase: Option<&'a str>,
        ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
            Box::pin(async move { Ok(false) })
        }

        fn authenticate_password<'a>(
            &'a mut self,
            _username: &'a str,
            _password: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
            Box::pin(async move { Ok(true) })
        }

        fn open_shell<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<u32>> + Send + 'a>> {
            Box::pin(async move { Ok(0) })
        }

        fn execute_command<'a>(
            &'a mut self,
            _spec: &'a ExecSpec,
        ) -> Pin<Box<dyn Future<Output = Result<u32>> + Send + 'a>> {
            Box::pin(async move { Ok(0) })
        }

        fn disconnect<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            let pending_disconnect = self.pending_disconnect;
            Box::pin(async move {
                if pending_disconnect {
                    std::future::pending::<()>().await;
                }
                Ok(())
            })
        }
    }
}
