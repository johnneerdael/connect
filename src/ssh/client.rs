use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    client::{self, Handle},
    keys::{self, PrivateKeyWithHashAlg, PublicKeyBase64},
    Disconnect,
};

use crate::{
    error::{Error, Result},
    store::{HostKeyRecord, Profile},
    terminal::interactive::InteractiveTerminal,
};

use super::{verify_observed_host_key, ObservedHostKey};

pub trait SshClient: Send + Sync {
    fn connect<'a>(
        &'a self,
        profile: &'a Profile,
        expected_host_key: Option<&'a HostKeyRecord>,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn SshSession + Send + 'static>>> + Send + 'a>>;
}

pub trait SshSession: Send {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<ObservedHostKey>> + Send + 'a>>;

    fn authenticate_public_key<'a>(
        &'a mut self,
        username: &'a str,
        private_key: &'a str,
        passphrase: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;

    fn authenticate_password<'a>(
        &'a mut self,
        username: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;

    fn open_shell<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<u32>> + Send + 'a>>;
}

#[derive(Debug, Default)]
pub struct RusshClient {
    terminal: InteractiveTerminal,
}

impl RusshClient {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SshClient for RusshClient {
    fn connect<'a>(
        &'a self,
        profile: &'a Profile,
        expected_host_key: Option<&'a HostKeyRecord>,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn SshSession + Send + 'static>>> + Send + 'a>>
    {
        Box::pin(async move {
            let handler = HostKeyRecorder::new(
                &profile.host,
                profile.port,
                expected_host_key.cloned(),
            );
            let observed_state = Arc::clone(&handler.observed);
            let mismatch_state = Arc::clone(&handler.host_key_mismatch);
            let config = Arc::new(client::Config {
                inactivity_timeout: Some(Duration::from_secs(30)),
                ..Default::default()
            });

            let handle = match client::connect(config, (profile.host.as_str(), profile.port), handler)
                .await
            {
                Ok(handle) => handle,
                Err(error) => {
                    if host_key_mismatch(&mismatch_state)? {
                        return Err(Error::new("saved host key does not match the server host key"));
                    }
                    return Err(map_ssh_error(error));
                }
            };
            let observed = host_key_from_state(&observed_state)?;

            Ok(Box::new(RusshSession {
                handle,
                observed,
                terminal: self.terminal.clone(),
            }) as Box<dyn SshSession + Send>)
        })
    }
}

struct RusshSession {
    handle: Handle<HostKeyRecorder>,
    observed: ObservedHostKey,
    terminal: InteractiveTerminal,
}

impl SshSession for RusshSession {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<ObservedHostKey>> + Send + 'a>> {
        let observed = self.observed.clone();
        Box::pin(async move { Ok(observed) })
    }

    fn authenticate_public_key<'a>(
        &'a mut self,
        username: &'a str,
        private_key: &'a str,
        passphrase: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            let private_key = keys::decode_secret_key(private_key, passphrase)
                .map_err(|error| Error::new(format!("failed to decode private key: {error}")))?;
            let hash_alg = self
                .handle
                .best_supported_rsa_hash()
                .await
                .map_err(map_ssh_error)?
                .flatten();
            let auth = self
                .handle
                .authenticate_publickey(
                    username,
                    PrivateKeyWithHashAlg::new(Arc::new(private_key), hash_alg),
                )
                .await
                .map_err(map_ssh_error)?;
            Ok(auth.success())
        })
    }

    fn authenticate_password<'a>(
        &'a mut self,
        username: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            let auth = self
                .handle
                .authenticate_password(username, password)
                .await
                .map_err(map_ssh_error)?;
            Ok(auth.success())
        })
    }

    fn open_shell<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<u32>> + Send + 'a>> {
        Box::pin(async move {
            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(map_ssh_error)?;
            let (columns, rows) = self.terminal.size();
            channel
                .request_pty(true, &self.terminal.term(), columns, rows, 0, 0, &[])
                .await
                .map_err(map_ssh_error)?;
            channel.request_shell(true).await.map_err(map_ssh_error)?;
            let exit_status = self.terminal.attach(&mut channel).await?;
            self.handle
                .disconnect(Disconnect::ByApplication, "", "English")
                .await
                .map_err(map_ssh_error)?;
            Ok(exit_status)
        })
    }
}

#[derive(Debug, Clone)]
struct HostKeyRecorder {
    host: String,
    port: u16,
    expected_host_key: Option<HostKeyRecord>,
    observed: Arc<Mutex<Option<ObservedHostKey>>>,
    host_key_mismatch: Arc<Mutex<bool>>,
}

impl HostKeyRecorder {
    fn new(host: &str, port: u16, expected_host_key: Option<HostKeyRecord>) -> Self {
        Self {
            host: host.to_string(),
            port,
            expected_host_key,
            observed: Arc::new(Mutex::new(None)),
            host_key_mismatch: Arc::new(Mutex::new(false)),
        }
    }
}

impl client::Handler for HostKeyRecorder {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let observed = ObservedHostKey {
            host: self.host.clone(),
            port: self.port,
            algorithm: server_public_key.algorithm().to_string(),
            fingerprint: server_public_key
                .fingerprint(keys::ssh_key::HashAlg::Sha256)
                .to_string(),
            public_key: server_public_key.public_key_base64(),
        };
        *self
            .observed
            .lock()
            .map_err(|_| russh::Error::IO(std::io::Error::other("host key recorder lock poisoned")))?
            = Some(observed.clone());
        if let Some(expected_host_key) = self.expected_host_key.as_ref() {
            if verify_observed_host_key(Some(expected_host_key), &observed).is_err() {
                *self
                    .host_key_mismatch
                    .lock()
                    .map_err(|_| russh::Error::IO(std::io::Error::other("host key mismatch lock poisoned")))? = true;
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn host_key_from_state(state: &Arc<Mutex<Option<ObservedHostKey>>>) -> Result<ObservedHostKey> {
    state
        .lock()
        .map_err(|_| Error::new("host key recorder lock poisoned"))?
        .clone()
        .ok_or_else(|| Error::new("server did not present a host key"))
}

fn host_key_mismatch(state: &Arc<Mutex<bool>>) -> Result<bool> {
    Ok(*state
        .lock()
        .map_err(|_| Error::new("host key mismatch lock poisoned"))?)
}

fn map_ssh_error(error: impl std::fmt::Display) -> Error {
    Error::new(format!("ssh error: {error}"))
}
