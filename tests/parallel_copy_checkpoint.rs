use std::{
    collections::{HashMap, VecDeque},
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use connect::{
    app::{App, AppPaths},
    error::Error,
    secrets::{MemorySecretStore, SecretStore},
    ssh::{
        parse_copy_spec, checkpoint_path, CheckpointFileIdentity, ChunkRange,
        CopyCheckpointIdentity, CopyCheckpointState, CopyCheckpointStore, CopyDirection,
        CopyFileMetadata, CopyTransferMode, ObservedHostKey, RemoteFileType, SshClient, SshSession,
    },
    store::{AuthMode, HostKeyRecord, Profile, ProfileInput},
    terminal::prompt::Prompt,
};
use filetime::{set_file_mtime, FileTime};

const CHUNK_BYTES: u64 = 64 * 1024 * 1024;

#[test]
fn checkpoint_tracks_non_contiguous_completed_ranges() {
    let mut state = CopyCheckpointState::new(
        4 * CHUNK_BYTES,
        CheckpointFileIdentity::new(4 * CHUNK_BYTES, 1_700_000_000),
        None,
    );

    state.mark_completed(ChunkRange {
        start: CHUNK_BYTES,
        end: 2 * CHUNK_BYTES,
    });
    state.mark_completed(ChunkRange {
        start: 3 * CHUNK_BYTES,
        end: 4 * CHUNK_BYTES,
    });
    state.mark_completed(ChunkRange {
        start: 0,
        end: CHUNK_BYTES / 2,
    });
    state.mark_completed(ChunkRange {
        start: CHUNK_BYTES / 2,
        end: CHUNK_BYTES,
    });

    assert_eq!(
        state.completed_ranges(),
        &[
            ChunkRange {
                start: 0,
                end: 2 * CHUNK_BYTES,
            },
            ChunkRange {
                start: 3 * CHUNK_BYTES,
                end: 4 * CHUNK_BYTES,
            },
        ]
    );
}

#[test]
fn checkpoint_path_is_stable_for_source_destination_and_direction() {
    let root = tempfile::tempdir().unwrap();
    let identity = CopyCheckpointIdentity {
        profile_name: "prod".into(),
        direction: CopyDirection::Upload,
        source_path: "/tmp/source.bin".into(),
        destination_path: "/srv/destination.bin".into(),
        transfer_mode: CopyTransferMode::SingleFile,
    };

    let first = checkpoint_path(root.path(), &identity);
    let second = checkpoint_path(root.path(), &identity);

    assert_eq!(first, second);
    assert!(first.starts_with(root.path()));
}

#[test]
fn checkpoint_identity_includes_transfer_mode() {
    let root = tempfile::tempdir().unwrap();
    let upload_file = CopyCheckpointIdentity {
        profile_name: "prod".into(),
        direction: CopyDirection::Upload,
        source_path: "/tmp/source.bin".into(),
        destination_path: "/srv/destination.bin".into(),
        transfer_mode: CopyTransferMode::SingleFile,
    };
    let recursive = CopyCheckpointIdentity {
        transfer_mode: CopyTransferMode::RecursiveTree,
        ..upload_file.clone()
    };

    assert_ne!(
        checkpoint_path(root.path(), &upload_file),
        checkpoint_path(root.path(), &recursive)
    );
}

#[test]
fn checkpoint_identity_includes_profile_name() {
    let root = tempfile::tempdir().unwrap();
    let prod = CopyCheckpointIdentity {
        profile_name: "prod".into(),
        direction: CopyDirection::Upload,
        source_path: "/tmp/source.bin".into(),
        destination_path: "/srv/destination.bin".into(),
        transfer_mode: CopyTransferMode::SingleFile,
    };
    let staging = CopyCheckpointIdentity {
        profile_name: "staging".into(),
        ..prod.clone()
    };

    assert_ne!(
        checkpoint_path(root.path(), &prod),
        checkpoint_path(root.path(), &staging)
    );
}

#[tokio::test]
async fn threaded_upload_resumes_only_missing_ranges() {
    let harness = CheckpointHarness::with_profile("prod");
    let source = harness.create_sparse_file("resume-upload.bin", 4 * CHUNK_BYTES);
    let remote_path = "/tmp/resume-upload.bin";
    let source_identity = file_identity(&source);
    let remote_identity = CheckpointFileIdentity::new(4 * CHUNK_BYTES, 1_700_000_123);

    let mut state = CopyCheckpointState::new(
        4 * CHUNK_BYTES,
        source_identity,
        Some(remote_identity),
    );
    state.mark_completed(ChunkRange {
        start: 0,
        end: CHUNK_BYTES,
    });
    state.mark_completed(ChunkRange {
        start: 2 * CHUNK_BYTES,
        end: 3 * CHUNK_BYTES,
    });

    let identity = CopyCheckpointIdentity {
        profile_name: "prod".into(),
        direction: CopyDirection::Upload,
        source_path: source.display().to_string(),
        destination_path: remote_path.into(),
        transfer_mode: CopyTransferMode::SingleFile,
    };
    harness.checkpoints().save(&identity, &state).unwrap();

    let ssh = FakeThreadedCopySshClient::new().with_remote_file(
        remote_path,
        RemoteFileType::File,
        CopyFileMetadata::new(4 * CHUNK_BYTES, Some(1_700_000_999)),
    );
    let mut spec = parse_copy_spec(
        &source.display().to_string(),
        &format!("prod:{remote_path}"),
        false,
        true,
        false,
    )
    .unwrap();
    spec.effective_threads = 4;

    let summary = harness
        .app()
        .copy(&spec, &ssh, &AcceptPrompt)
        .await
        .unwrap();

    assert_eq!(summary.resumed_bytes, 2 * CHUNK_BYTES);
    assert_eq!(summary.bytes_copied, 2 * CHUNK_BYTES);
    assert_eq!(
        ssh.recorded_upload_ranges(remote_path),
        vec![
            ChunkRange {
                start: CHUNK_BYTES,
                end: 2 * CHUNK_BYTES,
            },
            ChunkRange {
                start: 3 * CHUNK_BYTES,
                end: 4 * CHUNK_BYTES,
            },
        ]
    );
    assert!(
        !harness
            .checkpoints()
            .checkpoint_path(&identity)
            .exists()
    );
}

#[tokio::test]
async fn incompatible_checkpoint_state_is_rejected() {
    let harness = CheckpointHarness::with_profile("prod");
    let source = harness.create_sparse_file("incompatible-upload.bin", 2 * CHUNK_BYTES);
    let remote_path = "/tmp/incompatible-upload.bin";

    let identity = CopyCheckpointIdentity {
        profile_name: "prod".into(),
        direction: CopyDirection::Upload,
        source_path: source.display().to_string(),
        destination_path: remote_path.into(),
        transfer_mode: CopyTransferMode::SingleFile,
    };
    let mut state = CopyCheckpointState::new(
        2 * CHUNK_BYTES,
        CheckpointFileIdentity::new(2 * CHUNK_BYTES, 1),
        Some(CheckpointFileIdentity::new(2 * CHUNK_BYTES, 2)),
    );
    state.mark_completed(ChunkRange {
        start: 0,
        end: CHUNK_BYTES,
    });
    harness.checkpoints().save(&identity, &state).unwrap();

    let ssh = FakeThreadedCopySshClient::new().with_remote_file(
        remote_path,
        RemoteFileType::File,
        CopyFileMetadata::new(2 * CHUNK_BYTES, Some(2)),
    );
    let mut spec = parse_copy_spec(
        &source.display().to_string(),
        &format!("prod:{remote_path}"),
        false,
        true,
        false,
    )
    .unwrap();
    spec.effective_threads = 2;

    let error = harness
        .app()
        .copy(&spec, &ssh, &AcceptPrompt)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("incompatible checkpoint"));
    assert!(ssh.recorded_upload_ranges(remote_path).is_empty());
}

#[tokio::test]
async fn retry_requeues_transient_chunk_failures_but_not_fatal_ones() {
    let transient_harness = CheckpointHarness::with_profile("prod");
    let transient_source =
        transient_harness.create_sparse_file("transient-retry.bin", 2 * CHUNK_BYTES);
    let transient_remote = "/tmp/transient-retry.bin";
    let transient_ssh = FakeThreadedCopySshClient::new()
        .with_chunk_failure(
            transient_remote,
            ChunkRange {
                start: 0,
                end: CHUNK_BYTES,
            },
            ChunkFailure::Transient,
        )
        .with_remote_file(
            transient_remote,
            RemoteFileType::File,
            CopyFileMetadata::new(0, Some(1_700_000_000)),
        );
    let mut transient_spec = parse_copy_spec(
        &transient_source.display().to_string(),
        &format!("prod:{transient_remote}"),
        false,
        false,
        false,
    )
    .unwrap();
    transient_spec.effective_threads = 2;
    transient_spec.retry = true;

    transient_harness
        .app()
        .copy(&transient_spec, &transient_ssh, &AcceptPrompt)
        .await
        .unwrap();

    assert_eq!(
        transient_ssh.upload_attempts_for(
            transient_remote,
            ChunkRange {
                start: 0,
                end: CHUNK_BYTES,
            }
        ),
        2
    );

    let fatal_harness = CheckpointHarness::with_profile("prod");
    let fatal_source = fatal_harness.create_sparse_file("fatal-retry.bin", 2 * CHUNK_BYTES);
    let fatal_remote = "/tmp/fatal-retry.bin";
    let fatal_ssh = FakeThreadedCopySshClient::new()
        .with_chunk_failure(
            fatal_remote,
            ChunkRange {
                start: CHUNK_BYTES,
                end: 2 * CHUNK_BYTES,
            },
            ChunkFailure::Fatal,
        )
        .with_remote_file(
            fatal_remote,
            RemoteFileType::File,
            CopyFileMetadata::new(0, Some(1_700_000_000)),
        );
    let mut fatal_spec = parse_copy_spec(
        &fatal_source.display().to_string(),
        &format!("prod:{fatal_remote}"),
        false,
        false,
        false,
    )
    .unwrap();
    fatal_spec.effective_threads = 2;
    fatal_spec.retry = true;

    let error = fatal_harness
        .app()
        .copy(&fatal_spec, &fatal_ssh, &AcceptPrompt)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("fatal"));
    assert_eq!(
        fatal_ssh.upload_attempts_for(
            fatal_remote,
            ChunkRange {
                start: CHUNK_BYTES,
                end: 2 * CHUNK_BYTES,
            }
        ),
        1
    );
}

struct CheckpointHarness {
    root: PathBuf,
    app: App,
    checkpoint_root: PathBuf,
    profile_name: String,
}

impl CheckpointHarness {
    fn with_profile(name: &str) -> Self {
        let root = unique_temp_path("connect-parallel-copy-checkpoint");
        let paths = AppPaths::from_root(&root);
        let checkpoint_root = paths.copy_checkpoint_dir();
        let secrets = Arc::new(MemorySecretStore::default());
        let app = App::new(paths, secrets.clone()).unwrap();
        app.save_profile(
            ProfileInput::new(name, format!("{name}.example.com"), "deploy")
                .with_auth_mode(AuthMode::PasswordOnly)
                .with_copy_threads(4),
        )
        .unwrap();
        app.save_host_key(
            &format!("{name}.example.com"),
            22,
            "ssh-ed25519",
            "fp-123",
            "public-key-fp-123",
        )
        .unwrap();
        secrets.set_password(name, "super-secret").unwrap();
        app.update_profile_secret_flags(name, true, false, false)
            .unwrap();

        Self {
            root,
            app,
            checkpoint_root,
            profile_name: name.to_string(),
        }
    }

    fn app(&self) -> &App {
        &self.app
    }

    fn checkpoints(&self) -> CopyCheckpointStore {
        CopyCheckpointStore::new(
            self.checkpoint_root
                .join(profile_checkpoint_namespace(&self.profile_name)),
        )
    }

    fn create_sparse_file(&self, name: &str, size: u64) -> PathBuf {
        let path = self.root.join(name);
        let file = fs::File::create(&path).unwrap();
        file.set_len(size).unwrap();
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_file_mtime(&path, FileTime::from_system_time(mtime)).unwrap();
        path
    }
}

impl Drop for CheckpointHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn profile_checkpoint_namespace(profile_name: &str) -> String {
    let payload = format!("v1\0{}\0{}.example.com\0{}\0{}", profile_name, profile_name, 22, "deploy");
    format!("{:016x}", fnv1a64(payload.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkFailure {
    Transient,
    Fatal,
}

#[derive(Debug, Default)]
struct FakeThreadedCopyState {
    remote_types: HashMap<String, RemoteFileType>,
    remote_metadata: HashMap<String, CopyFileMetadata>,
    upload_ranges: HashMap<String, Vec<ChunkRange>>,
    upload_attempts: HashMap<(String, ChunkRange), usize>,
    upload_failures: HashMap<(String, ChunkRange), VecDeque<ChunkFailure>>,
}

#[derive(Debug, Clone, Default)]
struct FakeThreadedCopySshClient {
    state: Arc<Mutex<FakeThreadedCopyState>>,
}

impl FakeThreadedCopySshClient {
    fn new() -> Self {
        Self::default()
    }

    fn with_remote_file(self, path: &str, file_type: RemoteFileType, metadata: CopyFileMetadata) -> Self {
        let mut state = self.state.lock().unwrap();
        state.remote_types.insert(path.into(), file_type);
        state.remote_metadata.insert(path.into(), metadata);
        drop(state);
        self
    }

    fn with_chunk_failure(self, path: &str, range: ChunkRange, failure: ChunkFailure) -> Self {
        self.state
            .lock()
            .unwrap()
            .upload_failures
            .entry((path.into(), range))
            .or_default()
            .push_back(failure);
        self
    }

    fn recorded_upload_ranges(&self, path: &str) -> Vec<ChunkRange> {
        self.state
            .lock()
            .unwrap()
            .upload_ranges
            .get(path)
            .cloned()
            .unwrap_or_default()
    }

    fn upload_attempts_for(&self, path: &str, range: ChunkRange) -> usize {
        self.state
            .lock()
            .unwrap()
            .upload_attempts
            .get(&(path.into(), range))
            .copied()
            .unwrap_or_default()
    }
}

impl SshClient for FakeThreadedCopySshClient {
    fn connect<'a>(
        &'a self,
        _profile: &'a Profile,
        _expected_host_key: Option<&'a HostKeyRecord>,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<Box<dyn SshSession + Send + 'static>>>
                + Send
                + 'a,
        >,
    > {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            Ok(Box::new(FakeThreadedCopySession { state }) as Box<dyn SshSession + Send>)
        })
    }
}

struct FakeThreadedCopySession {
    state: Arc<Mutex<FakeThreadedCopyState>>,
}

impl SshSession for FakeThreadedCopySession {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<ObservedHostKey>> + Send + 'a>> {
        Box::pin(async move {
            Ok(ObservedHostKey {
                host: "prod.example.com".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                fingerprint: "fp-123".into(),
                public_key: "public-key-fp-123".into(),
            })
        })
    }

    fn authenticate_public_key<'a>(
        &'a mut self,
        _username: &'a str,
        _private_key: &'a str,
        _passphrase: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        Box::pin(async move { Ok(false) })
    }

    fn authenticate_password<'a>(
        &'a mut self,
        _username: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        Box::pin(async move { Ok(true) })
    }

    fn open_shell<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u32>> + Send + 'a>> {
        Box::pin(async move { Ok(0) })
    }

    fn supports_parallel_random_access<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        Box::pin(async move { Ok(true) })
    }

    fn resolve_remote_path<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<String>> + Send + 'a>> {
        Box::pin(async move { Ok(path.to_string()) })
    }

    fn remote_file_type<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<Option<RemoteFileType>>> + Send + 'a>>
    {
        let file_type = self.state.lock().unwrap().remote_types.get(path).copied();
        Box::pin(async move { Ok(file_type) })
    }

    fn remote_file_size<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<Option<u64>>> + Send + 'a>> {
        let size = self
            .state
            .lock()
            .unwrap()
            .remote_metadata
            .get(path)
            .map(|metadata| metadata.size_bytes());
        Box::pin(async move { Ok(size) })
    }

    fn remote_file_metadata<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<Option<CopyFileMetadata>>> + Send + 'a>>
    {
        let metadata = self.state.lock().unwrap().remote_metadata.get(path).copied();
        Box::pin(async move { Ok(metadata) })
    }

    fn create_remote_dir_all<'a>(
        &'a mut self,
        _path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        Box::pin(async move { Ok(()) })
    }

    fn prepare_remote_file_destination<'a>(
        &'a mut self,
        path: &'a str,
        truncate: bool,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        let mut state = self.state.lock().unwrap();
        state.remote_types.insert(path.into(), RemoteFileType::File);
        if truncate {
            state
                .remote_metadata
                .insert(path.into(), CopyFileMetadata::new(0, Some(1_700_000_000)));
        } else {
            state
                .remote_metadata
                .entry(path.into())
                .or_insert_with(|| CopyFileMetadata::new(0, Some(1_700_000_000)));
        }
        Box::pin(async move { Ok(()) })
    }

    fn upload_file_range<'a>(
        &'a mut self,
        local_path: &'a Path,
        remote_path: &'a str,
        range: ChunkRange,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u64>> + Send + 'a>> {
        let outcome = {
            let mut state = self.state.lock().unwrap();
            *state
                .upload_attempts
                .entry((remote_path.into(), range))
                .or_default() += 1;

            if let Some(failures) = state.upload_failures.get_mut(&(remote_path.into(), range)) {
                if let Some(failure) = failures.pop_front() {
                    let error = match failure {
                        ChunkFailure::Transient => Error::new("transient chunk failure"),
                        ChunkFailure::Fatal => Error::new("fatal chunk failure"),
                    };
                    return Box::pin(async move { Err(error) });
                }
            }

            state
                .upload_ranges
                .entry(remote_path.into())
                .or_default()
                .push(range);

            let modified = fs::metadata(local_path)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|mtime| mtime.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            state.remote_types.insert(remote_path.into(), RemoteFileType::File);
            state.remote_metadata.insert(
                remote_path.into(),
                CopyFileMetadata::new(
                    fs::metadata(local_path).map(|metadata| metadata.len()).unwrap_or(range.end),
                    Some(modified),
                ),
            );
            Ok(range.end - range.start)
        };

        Box::pin(async move { outcome })
    }
}

#[derive(Debug)]
struct AcceptPrompt;

impl Prompt for AcceptPrompt {
    fn prompt(&self, _key: &str, _message: &str, _default: Option<&str>) -> connect::error::Result<String> {
        Err(Error::new("unexpected text prompt"))
    }

    fn prompt_secret(&self, _key: &str, _message: &str) -> connect::error::Result<Option<String>> {
        Err(Error::new("unexpected secret prompt"))
    }

    fn confirm(&self, _key: &str, _message: &str, _default: bool) -> connect::error::Result<bool> {
        Ok(true)
    }
}

fn file_identity(path: &Path) -> CheckpointFileIdentity {
    let metadata = fs::metadata(path).unwrap();
    let modified = metadata
        .modified()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    CheckpointFileIdentity::new(metadata.len(), modified)
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let temp_root = std::env::temp_dir();
    let process_id = std::process::id();

    for _ in 0..1024 {
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = temp_root.join(format!("{prefix}-{process_id}-{id}"));

        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("failed to create temp dir {}: {error}", path.display()),
        }
    }

    panic!("failed to allocate temp dir for {prefix}");
}
