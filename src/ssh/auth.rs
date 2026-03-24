use crate::{
    error::{Error, Result},
    store::{HostKeyRecord, Profile},
    terminal::prompt::Prompt,
};

use super::{
    verify_observed_host_key, HostKeyVerification, ObservedHostKey, SshClient, SshSession,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileAuth {
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub key_passphrase: Option<String>,
}

impl ProfileAuth {
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.private_key.is_none()
    }
}

pub trait SshConnectionContext {
    fn load_profile_auth(&self, profile: &Profile) -> Result<ProfileAuth>;
    fn load_host_key(&self, profile: &Profile) -> Result<Option<HostKeyRecord>>;
    fn save_host_key(&self, observed: &ObservedHostKey) -> Result<()>;
}

pub async fn connect_profile(
    ssh: &dyn SshClient,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
) -> Result<()> {
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
    let exit_status = session.open_shell().await?;
    if exit_status == 0 {
        Ok(())
    } else {
        Err(Error::RemoteExitStatus(exit_status))
    }
}

pub async fn authenticate_session(
    session: &mut dyn SshSession,
    profile: &Profile,
    auth: &ProfileAuth,
) -> Result<()> {
    if let Some(private_key) = auth.private_key.as_deref() {
        if session
            .authenticate_public_key(
                &profile.username,
                private_key,
                auth.key_passphrase.as_deref(),
            )
            .await?
        {
            return Ok(());
        }
    }

    if let Some(password) = auth.password.as_deref() {
        if session
            .authenticate_password(&profile.username, password)
            .await?
        {
            return Ok(());
        }
    }

    if auth.is_empty() {
        Err(Error::new("profile has no SSH authentication material"))
    } else {
        Err(Error::new("ssh authentication failed"))
    }
}
