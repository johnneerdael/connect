use std::{
    future::Future,
    io::IsTerminal,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use filetime::{set_file_mtime, FileTime};
use russh::{
    client::{self, Handle},
    keys::agent::client::AgentClient,
    keys::{self, PrivateKeyWithHashAlg, PublicKeyBase64},
    Disconnect,
};
use russh_sftp::{
    client::fs::Metadata as SftpMetadata,
    client::{error::Error as SftpError, SftpSession},
    protocol::{FileAttributes, OpenFlags, StatusCode},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
};

use crate::{
    error::{Error, Result},
    store::{HostKeyRecord, Profile},
    terminal::interactive::InteractiveTerminal,
};

use super::{
    verify_observed_host_key, CopyTransferOptions, CopyTransferResult, ExecSpec, ObservedHostKey,
    RemoteDirectoryEntry, RemoteFileType,
};

type DynSshSession = Box<dyn SshSession + Send + 'static>;
type SshResultFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX_MISSES: usize = 3;
#[cfg(windows)]
const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

pub trait SshClient: Send + Sync {
    fn connect<'a>(
        &'a self,
        profile: &'a Profile,
        expected_host_key: Option<&'a HostKeyRecord>,
    ) -> SshResultFuture<'a, DynSshSession>;
}

pub trait SshSession: Send {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<ObservedHostKey>> + Send + 'a>>;

    fn authenticate_agent<'a>(
        &'a mut self,
        _username: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async { Ok(false) })
    }

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

    fn execute_command<'a>(
        &'a mut self,
        _spec: &'a ExecSpec,
    ) -> Pin<Box<dyn Future<Output = Result<u32>> + Send + 'a>> {
        Box::pin(async {
            Err(Error::new(
                "ssh session does not support remote command execution",
            ))
        })
    }

    fn disconnect<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn remote_file_type<'a>(
        &'a mut self,
        _path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RemoteFileType>>> + Send + 'a>> {
        Box::pin(async { Err(Error::new("ssh session does not support copy operations")) })
    }

    fn remote_file_size<'a>(
        &'a mut self,
        _path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>>> + Send + 'a>> {
        Box::pin(async { Err(Error::new("ssh session does not support copy operations")) })
    }

    fn read_remote_dir<'a>(
        &'a mut self,
        _path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<RemoteDirectoryEntry>>> + Send + 'a>> {
        Box::pin(async { Err(Error::new("ssh session does not support copy operations")) })
    }

    fn create_remote_dir_all<'a>(
        &'a mut self,
        _path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { Err(Error::new("ssh session does not support copy operations")) })
    }

    fn upload_file<'a>(
        &'a mut self,
        _local_path: &'a Path,
        _remote_path: &'a str,
        _options: CopyTransferOptions,
    ) -> Pin<Box<dyn Future<Output = Result<CopyTransferResult>> + Send + 'a>> {
        Box::pin(async { Err(Error::new("ssh session does not support copy operations")) })
    }

    fn download_file<'a>(
        &'a mut self,
        _remote_path: &'a str,
        _local_path: &'a Path,
        _options: CopyTransferOptions,
    ) -> Pin<Box<dyn Future<Output = Result<CopyTransferResult>> + Send + 'a>> {
        Box::pin(async { Err(Error::new("ssh session does not support copy operations")) })
    }
}

#[derive(Debug, Default)]
pub struct RusshClient {
    terminal: InteractiveTerminal,
}

impl RusshClient {
    pub fn new() -> Self {
        Self::default()
    }

    fn config() -> client::Config {
        client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: KEEPALIVE_MAX_MISSES,
            ..Default::default()
        }
    }
}

pub fn agent_auth_available() -> bool {
    #[cfg(unix)]
    {
        std::env::var_os("SSH_AUTH_SOCK").is_some()
    }

    #[cfg(windows)]
    {
        std::env::var_os("SSH_AUTH_SOCK").is_some()
            || std::path::Path::new(OPENSSH_AGENT_PIPE).exists()
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

pub async fn agent_connection_available() -> bool {
    connect_agent().await.is_ok()
}

impl SshClient for RusshClient {
    fn connect<'a>(
        &'a self,
        profile: &'a Profile,
        expected_host_key: Option<&'a HostKeyRecord>,
    ) -> SshResultFuture<'a, DynSshSession> {
        Box::pin(async move {
            let handler =
                HostKeyRecorder::new(&profile.host, profile.port, expected_host_key.cloned());
            let observed_state = Arc::clone(&handler.observed);
            let mismatch_state = Arc::clone(&handler.host_key_mismatch);
            let config = Arc::new(Self::config());

            let handle =
                match client::connect(config, (profile.host.as_str(), profile.port), handler).await
                {
                    Ok(handle) => handle,
                    Err(error) => {
                        if host_key_mismatch(&mismatch_state)? {
                            return Err(Error::new(
                                "saved host key does not match the server host key",
                            ));
                        }
                        return Err(map_ssh_error(error));
                    }
                };
            let observed = host_key_from_state(&observed_state)?;

            Ok(Box::new(RusshSession {
                handle,
                observed,
                terminal: self.terminal.clone(),
                sftp: None,
            }) as DynSshSession)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, SeekFrom};

    #[test]
    fn client_config_uses_keepalives_without_idle_disconnects() {
        let config = RusshClient::config();

        assert_eq!(config.inactivity_timeout, None);
        assert_eq!(config.keepalive_interval, Some(KEEPALIVE_INTERVAL));
        assert_eq!(config.keepalive_max, KEEPALIVE_MAX_MISSES);
    }

    #[tokio::test]
    async fn resume_copy_skips_prefix_on_both_sides() {
        let dir = tempfile::tempdir().expect("tempdir should exist");
        let source_path = dir.path().join("source.txt");
        let destination_path = dir.path().join("destination.txt");

        std::fs::write(&source_path, "hello-resume-upload").expect("source should be written");
        std::fs::write(&destination_path, "hello-").expect("destination prefix should exist");

        let mut source = File::open(&source_path).await.expect("source should open");
        let mut destination = OpenOptions::new()
            .write(true)
            .open(&destination_path)
            .await
            .expect("destination should open");

        let copied = copy_stream_from_offsets(
            &mut source,
            &mut destination,
            "resume test".into(),
            Some(std::fs::metadata(&source_path).unwrap().len()),
            false,
            6,
        )
        .await
        .expect("resume copy should succeed");

        assert_eq!(copied, 19);
        assert_eq!(
            std::fs::read_to_string(&destination_path).expect("destination should be readable"),
            "hello-resume-upload"
        );

        let mut source = File::open(&source_path)
            .await
            .expect("source should reopen");
        source
            .seek(SeekFrom::Start(6))
            .await
            .expect("source should seek");
        let mut suffix = vec![0_u8; 6];
        source
            .read_exact(&mut suffix)
            .await
            .expect("source suffix should be readable after seek");
        assert_eq!(suffix, b"resume");
    }

    #[tokio::test]
    async fn resumed_progress_starts_from_the_resume_offset() {
        let dir = tempfile::tempdir().expect("tempdir should exist");
        let source_path = dir.path().join("source.txt");
        let destination_path = dir.path().join("destination.txt");

        std::fs::write(&source_path, "hello-resume-upload").expect("source should be written");
        std::fs::write(&destination_path, "hello-").expect("destination prefix should exist");

        let mut source = File::open(&source_path).await.expect("source should open");
        source
            .seek(SeekFrom::Start(6))
            .await
            .expect("source should seek");
        let mut destination = OpenOptions::new()
            .write(true)
            .open(&destination_path)
            .await
            .expect("destination should open");
        destination
            .seek(SeekFrom::Start(6))
            .await
            .expect("destination should seek");

        let (mut progress_reader, mut progress_writer) = duplex(1024);
        let bytes_copied = copy_stream_with_progress(
            &mut source,
            &mut destination,
            &mut progress_writer,
            "resume test".into(),
            Some(std::fs::metadata(&source_path).unwrap().len()),
            true,
            6,
        )
        .await
        .expect("copy should succeed");
        drop(progress_writer);

        let mut progress = String::new();
        progress_reader
            .read_to_string(&mut progress)
            .await
            .expect("progress should be readable");

        assert_eq!(bytes_copied, 19);
        assert!(progress.contains("\rresume test: 6/19 bytes"));
        assert!(progress.contains("\rresume test: 19/19 bytes"));
        assert!(!progress.contains("\rresume test: 0/19 bytes"));
        assert!(progress.ends_with('\n'));
    }
}

struct RusshSession {
    handle: Handle<HostKeyRecorder>,
    observed: ObservedHostKey,
    terminal: InteractiveTerminal,
    sftp: Option<SftpSession>,
}

impl RusshSession {
    async fn sftp(&mut self) -> Result<&mut SftpSession> {
        if self.sftp.is_none() {
            let channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(map_ssh_error)?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(map_ssh_error)?;
            let sftp = SftpSession::new(channel.into_stream())
                .await
                .map_err(map_sftp_error)?;
            self.sftp = Some(sftp);
        }

        Ok(self
            .sftp
            .as_mut()
            .expect("sftp session should be initialized"))
    }
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

    fn authenticate_agent<'a>(
        &'a mut self,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            let mut agent = connect_agent().await?;
            let identities = agent
                .request_identities()
                .await
                .map_err(|error| Error::new(format!("ssh agent error: {error}")))?;

            if identities.is_empty() {
                return Ok(false);
            }

            for identity in identities {
                let hash_alg = match identity.algorithm() {
                    keys::ssh_key::Algorithm::Rsa { .. } => self
                        .handle
                        .best_supported_rsa_hash()
                        .await
                        .map_err(map_ssh_error)?
                        .flatten(),
                    _ => None,
                };
                let auth = self
                    .handle
                    .authenticate_publickey_with(username, identity, hash_alg, &mut agent)
                    .await
                    .map_err(|error| Error::new(format!("ssh agent auth error: {error}")))?;
                if auth.success() {
                    return Ok(true);
                }
            }

            Ok(false)
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
            self.terminal.attach(&mut channel).await
        })
    }

    fn execute_command<'a>(
        &'a mut self,
        spec: &'a ExecSpec,
    ) -> Pin<Box<dyn Future<Output = Result<u32>> + Send + 'a>> {
        Box::pin(async move {
            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(map_ssh_error)?;
            if spec.pty {
                let (columns, rows) = self.terminal.size();
                channel
                    .request_pty(true, &self.terminal.term(), columns, rows, 0, 0, &[])
                    .await
                    .map_err(map_ssh_error)?;
            }
            channel
                .exec(true, spec.command_line()?)
                .await
                .map_err(map_ssh_error)?;
            self.terminal
                .stream_command_output(&mut channel, spec.pty)
                .await
        })
    }

    fn disconnect<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.handle
                .disconnect(Disconnect::ByApplication, "", "English")
                .await
                .map_err(map_ssh_error)
        })
    }

    fn remote_file_type<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RemoteFileType>>> + Send + 'a>> {
        Box::pin(async move {
            let sftp = self.sftp().await?;
            match sftp.metadata(path).await {
                Ok(metadata) => Ok(Some(map_remote_file_type(metadata.file_type()))),
                Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => {
                    Ok(None)
                }
                Err(error) => Err(map_sftp_error(error)),
            }
        })
    }

    fn remote_file_size<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>>> + Send + 'a>> {
        Box::pin(async move {
            let sftp = self.sftp().await?;
            match sftp.metadata(path).await {
                Ok(metadata) => Ok(metadata.size),
                Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => {
                    Ok(None)
                }
                Err(error) => Err(map_sftp_error(error)),
            }
        })
    }

    fn read_remote_dir<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<RemoteDirectoryEntry>>> + Send + 'a>> {
        Box::pin(async move {
            let sftp = self.sftp().await?;
            let entries = sftp.read_dir(path).await.map_err(map_sftp_error)?;
            Ok(entries
                .map(|entry| RemoteDirectoryEntry {
                    name: entry.file_name(),
                    file_type: map_remote_file_type(entry.file_type()),
                })
                .collect())
        })
    }

    fn create_remote_dir_all<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if path.is_empty() || path == "/" {
                return Ok(());
            }

            let sftp = self.sftp().await?;
            let mut current = String::new();
            for component in path.split('/').filter(|segment| !segment.is_empty()) {
                current.push('/');
                current.push_str(component);
                if !sftp.try_exists(&current).await.map_err(map_sftp_error)? {
                    sftp.create_dir(&current).await.map_err(map_sftp_error)?;
                }
            }
            Ok(())
        })
    }

    fn upload_file<'a>(
        &'a mut self,
        local_path: &'a Path,
        remote_path: &'a str,
        options: CopyTransferOptions,
    ) -> Pin<Box<dyn Future<Output = Result<CopyTransferResult>> + Send + 'a>> {
        Box::pin(async move {
            let sftp = self.sftp().await?;
            let mut local = File::open(local_path).await?;
            let total_bytes = std::fs::metadata(local_path).map(|metadata| metadata.len())?;
            let mut remote = sftp
                .open_with_flags(
                    remote_path,
                    if options.resume_offset > 0 {
                        OpenFlags::CREATE | OpenFlags::WRITE
                    } else {
                        OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
                    },
                )
                .await
                .map_err(map_sftp_error)?;
            let bytes_copied = copy_stream_from_offsets(
                &mut local,
                &mut remote,
                progress_label("upload", local_path, remote_path),
                Some(total_bytes),
                options.show_progress,
                options.resume_offset,
            )
            .await?;
            remote.shutdown().await?;
            if let Ok(metadata) = std::fs::metadata(local_path) {
                let attrs = FileAttributes::from(&metadata);
                let _ = sftp.set_metadata(remote_path, attrs).await;
            }
            Ok(CopyTransferResult {
                bytes_copied,
                resumed_bytes: options.resume_offset,
            })
        })
    }

    fn download_file<'a>(
        &'a mut self,
        remote_path: &'a str,
        local_path: &'a Path,
        options: CopyTransferOptions,
    ) -> Pin<Box<dyn Future<Output = Result<CopyTransferResult>> + Send + 'a>> {
        Box::pin(async move {
            let sftp = self.sftp().await?;
            let mut remote = sftp.open(remote_path).await.map_err(map_sftp_error)?;
            let remote_metadata = remote.metadata().await.map_err(map_sftp_error)?;
            let total_bytes = remote_metadata.size;
            let mut local = if options.resume_offset > 0 {
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(local_path)
                    .await?
            } else {
                File::create(local_path).await?
            };
            let bytes_copied = copy_stream_from_offsets(
                &mut remote,
                &mut local,
                progress_label("download", local_path, remote_path),
                total_bytes,
                options.show_progress,
                options.resume_offset,
            )
            .await?;
            local.flush().await?;
            apply_local_metadata(local_path, &remote_metadata)?;
            Ok(CopyTransferResult {
                bytes_copied,
                resumed_bytes: options.resume_offset,
            })
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
        *self.observed.lock().map_err(|_| {
            russh::Error::IO(std::io::Error::other("host key recorder lock poisoned"))
        })? = Some(observed.clone());
        if let Some(expected_host_key) = self.expected_host_key.as_ref() {
            if verify_observed_host_key(Some(expected_host_key), &observed).is_err() {
                *self.host_key_mismatch.lock().map_err(|_| {
                    russh::Error::IO(std::io::Error::other("host key mismatch lock poisoned"))
                })? = true;
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

fn map_sftp_error(error: impl std::fmt::Display) -> Error {
    Error::new(format!("sftp error: {error}"))
}

fn map_remote_file_type(file_type: russh_sftp::protocol::FileType) -> RemoteFileType {
    if file_type.is_dir() {
        RemoteFileType::Directory
    } else if file_type.is_file() {
        RemoteFileType::File
    } else if file_type.is_symlink() {
        RemoteFileType::Symlink
    } else {
        RemoteFileType::Other
    }
}

#[cfg(unix)]
async fn connect_agent() -> Result<AgentClient<tokio::net::UnixStream>> {
    AgentClient::connect_env()
        .await
        .map_err(|error| Error::new(format!("ssh agent is not available: {error}")))
}

#[cfg(windows)]
async fn connect_agent() -> Result<AgentClient<tokio::net::windows::named_pipe::NamedPipeClient>> {
    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        AgentClient::connect_named_pipe(sock)
            .await
            .map_err(|error| Error::new(format!("ssh agent is not available: {error}")))
    } else {
        AgentClient::connect_named_pipe(OPENSSH_AGENT_PIPE)
            .await
            .map_err(|error| Error::new(format!("ssh agent is not available: {error}")))
    }
}

#[cfg(not(any(unix, windows)))]
async fn connect_agent() -> Result<()> {
    Err(Error::new("ssh agent is not supported on this platform"))
}

fn progress_label(direction: &str, local_path: &Path, remote_path: &str) -> String {
    format!("{direction} {} <-> {remote_path}", local_path.display())
}

async fn copy_stream_with_progress<R, W, P>(
    reader: &mut R,
    writer: &mut W,
    progress: &mut P,
    label: String,
    total_bytes: Option<u64>,
    show_progress_override: bool,
    initial_copied: u64,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    P: AsyncWrite + Unpin,
{
    let show_progress = show_progress_override || std::io::stderr().is_terminal();
    if show_progress {
        print_progress(progress, &label, initial_copied, total_bytes).await?;
    }

    let mut copied = initial_copied;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).await?;
        copied += u64::try_from(read).unwrap_or(u64::MAX);
        if show_progress {
            print_progress(progress, &label, copied, total_bytes).await?;
        }
    }
    writer.flush().await?;
    if show_progress {
        progress.write_all(b"\n").await?;
        progress.flush().await?;
    }
    Ok(copied)
}

async fn copy_stream_from_offsets<R, W>(
    reader: &mut R,
    writer: &mut W,
    label: String,
    total_bytes: Option<u64>,
    show_progress: bool,
    resume_offset: u64,
) -> Result<u64>
where
    R: AsyncRead + tokio::io::AsyncSeek + Unpin,
    W: AsyncWrite + tokio::io::AsyncSeek + Unpin,
{
    let mut progress = tokio::io::stderr();
    if resume_offset > 0 {
        reader.seek(std::io::SeekFrom::Start(resume_offset)).await?;
        writer.seek(std::io::SeekFrom::Start(resume_offset)).await?;
    }

    copy_stream_with_progress(
        reader,
        writer,
        &mut progress,
        label,
        total_bytes,
        show_progress,
        resume_offset,
    )
    .await
}

async fn print_progress<W>(
    stderr: &mut W,
    label: &str,
    copied: u64,
    total_bytes: Option<u64>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = match total_bytes {
        Some(total) if total > 0 => format!("\r{label}: {copied}/{total} bytes"),
        _ => format!("\r{label}: {copied} bytes"),
    };
    stderr.write_all(line.as_bytes()).await?;
    stderr.flush().await?;
    Ok(())
}

fn apply_local_metadata(local_path: &Path, metadata: &SftpMetadata) -> Result<()> {
    #[cfg(unix)]
    if let Some(mode) = metadata.permissions {
        let permissions = std::os::unix::fs::PermissionsExt::from_mode(mode & 0o777);
        let _ = std::fs::set_permissions(local_path, permissions);
    }

    if let Some(mtime) = metadata.mtime {
        let _ = set_file_mtime(local_path, FileTime::from_unix_time(i64::from(mtime), 0));
    }

    Ok(())
}
