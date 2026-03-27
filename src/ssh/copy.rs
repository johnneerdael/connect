use std::{
    collections::{HashSet, VecDeque},
    convert::TryFrom,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex as AsyncMutex, task::JoinSet};

use crate::{
    error::{Error, Result},
    store::Profile,
    terminal::prompt::Prompt,
};

use super::{
    connect_authenticated_session, establish_transfer_sessions,
    progress::{AggregateProgressSnapshot, ProgressMode, ThreadedProgressReporter},
    CheckpointFileIdentity, ChunkRange, CopyCheckpointIdentity, CopyCheckpointState,
    CopyCheckpointStore, CopyFileMetadata, CopyTransferMode, SshClient, SshConnectionContext,
    SshSession,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePath {
    pub profile: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyEndpoint {
    Local(PathBuf),
    Remote(RemotePath),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CopyDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteFileType {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDirectoryEntry {
    pub name: String,
    pub file_type: RemoteFileType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySpec {
    pub source: CopyEndpoint,
    pub destination: CopyEndpoint,
    pub recursive: bool,
    pub resume: bool,
    pub retry: bool,
    pub progress: bool,
    pub effective_threads: usize,
}

impl CopySpec {
    pub fn direction(&self) -> Result<CopyDirection> {
        match (&self.source, &self.destination) {
            (CopyEndpoint::Local(_), CopyEndpoint::Remote(_)) => Ok(CopyDirection::Upload),
            (CopyEndpoint::Remote(_), CopyEndpoint::Local(_)) => Ok(CopyDirection::Download),
            _ => Err(Error::new(
                "copy requires exactly one remote path in profile:/path format",
            )),
        }
    }

    pub fn remote_profile(&self) -> Result<&str> {
        match (&self.source, &self.destination) {
            (CopyEndpoint::Remote(remote), _) | (_, CopyEndpoint::Remote(remote)) => {
                Ok(&remote.profile)
            }
            _ => Err(Error::new(
                "copy requires exactly one remote path in profile:/path format",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyPlannerConfig {
    pub effective_threads: usize,
    pub retry: bool,
}

impl CopyPlannerConfig {
    pub fn new(effective_threads: usize) -> Self {
        Self {
            effective_threads,
            retry: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPlan {
    pub mode: CopyPlanMode,
    pub jobs: Vec<CopyJob>,
    pub effective_threads: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyPlanMode {
    SingleStream,
    StripedFile { chunks: Vec<ChunkRange> },
    QueuedTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyJob {
    WholeFile {
        source_path: String,
        destination_path: String,
        size: u64,
        policy: CopyJobPolicy,
        checkpoint: CopyCheckpointIdentity,
    },
    StripedFile {
        source_path: String,
        destination_path: String,
        size: u64,
        chunks: Vec<ChunkRange>,
        policy: CopyJobPolicy,
        checkpoint: CopyCheckpointIdentity,
    },
    CreateDirectory {
        source_path: String,
        destination_path: String,
        checkpoint: CopyCheckpointIdentity,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyJobPolicy {
    pub resume: CopyResumeStrategy,
    pub retry: CopyRetryStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyResumeStrategy {
    Disabled,
    DestinationSizeResume,
    Checkpointed { checkpoint: CopyCheckpointIdentity },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyRetryStrategy {
    Disabled,
    RetryWholeFile,
    RetryStripedChunks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedCopySource {
    File {
        path: String,
        size: u64,
    },
    Tree {
        root: String,
        entries: Vec<PlannedCopyTreeEntry>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedCopyTreeEntry {
    File { path: String, size: u64 },
    Directory { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyDestinationShape {
    pub existing_directory: bool,
}

impl CopyDestinationShape {
    pub fn new(existing_directory: bool) -> Self {
        Self { existing_directory }
    }
}

pub fn plan_copy(
    spec: CopySpec,
    config: CopyPlannerConfig,
    destination_shape: CopyDestinationShape,
    source: PlannedCopySource,
) -> Result<CopyPlan> {
    let direction = validate_planning_endpoints(&spec)?;
    let effective_threads = config.effective_threads;
    let profile_name = spec.remote_profile()?.to_string();

    match (spec.recursive, source) {
        (false, PlannedCopySource::File { path, size }) => {
            let checkpoint = CopyCheckpointIdentity {
                profile_name: profile_name.clone(),
                direction,
                source_path: path.clone(),
                destination_path: endpoint_destination_path(&spec.destination),
                transfer_mode: CopyTransferMode::SingleFile,
            };

            if effective_threads > 1 && size > STRIPE_THRESHOLD_BYTES {
                let chunks = build_chunk_ranges(size, effective_threads);
                Ok(CopyPlan {
                    mode: CopyPlanMode::StripedFile {
                        chunks: chunks.clone(),
                    },
                    jobs: vec![CopyJob::StripedFile {
                        source_path: path,
                        destination_path: endpoint_destination_path(&spec.destination),
                        size,
                        chunks,
                        policy: CopyJobPolicy {
                            resume: striped_resume_strategy(&spec, &checkpoint),
                            retry: striped_retry_strategy(config.retry),
                        },
                        checkpoint,
                    }],
                    effective_threads,
                })
            } else {
                Ok(CopyPlan {
                    mode: CopyPlanMode::SingleStream,
                    jobs: vec![CopyJob::WholeFile {
                        source_path: path,
                        destination_path: endpoint_destination_path(&spec.destination),
                        size,
                        policy: CopyJobPolicy {
                            resume: whole_file_resume_strategy(&spec),
                            retry: whole_file_retry_strategy(config.retry),
                        },
                        checkpoint,
                    }],
                    effective_threads,
                })
            }
        }
        (true, PlannedCopySource::Tree { root, entries }) => {
            let destination_root =
                recursive_destination_root(&spec.destination, &root, destination_shape);
            let mut jobs = Vec::new();
            jobs.push(copy_directory_job(
                profile_name.clone(),
                direction,
                root.clone(),
                destination_root.clone(),
            ));
            for entry in entries {
                match entry {
                    PlannedCopyTreeEntry::File { path, size } => {
                        let source_path = format!("{root}/{path}");
                        let destination_path = recursive_job_destination_path(
                            &spec.destination,
                            &destination_root,
                            &path,
                        );
                        let checkpoint = CopyCheckpointIdentity {
                            profile_name: profile_name.clone(),
                            direction,
                            source_path: source_path.clone(),
                            destination_path: destination_path.clone(),
                            transfer_mode: CopyTransferMode::RecursiveTree,
                        };

                        if effective_threads > 1 && size > STRIPE_THRESHOLD_BYTES {
                            let chunks = build_chunk_ranges(size, effective_threads);
                            jobs.push(CopyJob::StripedFile {
                                source_path,
                                destination_path,
                                size,
                                chunks,
                                policy: CopyJobPolicy {
                                    resume: striped_resume_strategy(&spec, &checkpoint),
                                    retry: striped_retry_strategy(config.retry),
                                },
                                checkpoint,
                            });
                        } else {
                            jobs.push(CopyJob::WholeFile {
                                source_path,
                                destination_path,
                                size,
                                policy: CopyJobPolicy {
                                    resume: whole_file_resume_strategy(&spec),
                                    retry: whole_file_retry_strategy(config.retry),
                                },
                                checkpoint,
                            });
                        }
                    }
                    PlannedCopyTreeEntry::Directory { path } => {
                        let source_path = format!("{root}/{path}");
                        let destination_path = recursive_job_destination_path(
                            &spec.destination,
                            &destination_root,
                            &path,
                        );
                        let checkpoint = CopyCheckpointIdentity {
                            profile_name: profile_name.clone(),
                            direction,
                            source_path: source_path.clone(),
                            destination_path: destination_path.clone(),
                            transfer_mode: CopyTransferMode::RecursiveTree,
                        };

                        jobs.push(CopyJob::CreateDirectory {
                            source_path,
                            destination_path,
                            checkpoint,
                        });
                    }
                }
            }

            Ok(CopyPlan {
                mode: if effective_threads > 1 {
                    CopyPlanMode::QueuedTree
                } else {
                    CopyPlanMode::SingleStream
                },
                jobs,
                effective_threads,
            })
        }
        (false, PlannedCopySource::Tree { .. }) => Err(Error::new(
            "copy planner received a recursive source description for a non-recursive copy",
        )),
        (true, PlannedCopySource::File { .. }) => Err(Error::new(
            "copy planner received a single-file source description for a recursive copy",
        )),
    }
}

const STRIPE_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;

fn whole_file_resume_strategy(spec: &CopySpec) -> CopyResumeStrategy {
    if spec.resume {
        CopyResumeStrategy::DestinationSizeResume
    } else {
        CopyResumeStrategy::Disabled
    }
}

fn striped_resume_strategy(
    spec: &CopySpec,
    checkpoint: &CopyCheckpointIdentity,
) -> CopyResumeStrategy {
    if spec.resume {
        CopyResumeStrategy::Checkpointed {
            checkpoint: checkpoint.clone(),
        }
    } else {
        CopyResumeStrategy::Disabled
    }
}

fn whole_file_retry_strategy(retry: bool) -> CopyRetryStrategy {
    if retry {
        CopyRetryStrategy::RetryWholeFile
    } else {
        CopyRetryStrategy::Disabled
    }
}

fn striped_retry_strategy(retry: bool) -> CopyRetryStrategy {
    if retry {
        CopyRetryStrategy::RetryStripedChunks
    } else {
        CopyRetryStrategy::Disabled
    }
}

fn recursive_destination_root(
    destination: &CopyEndpoint,
    source_root: &str,
    destination_shape: CopyDestinationShape,
) -> String {
    if !destination_shape.existing_directory {
        return endpoint_destination_path(destination);
    }

    let source_root_name = path_tail(source_root);
    match destination {
        CopyEndpoint::Remote(remote) => join_remote(&remote.path, &source_root_name),
        CopyEndpoint::Local(path) => path.join(source_root_name).display().to_string(),
    }
}

fn recursive_job_destination_path(
    destination: &CopyEndpoint,
    destination_root: &str,
    relative_path: &str,
) -> String {
    match destination {
        CopyEndpoint::Remote(_) => join_remote(destination_root, relative_path),
        CopyEndpoint::Local(_) => Path::new(destination_root)
            .join(relative_path)
            .display()
            .to_string(),
    }
}

fn copy_directory_job(
    profile_name: String,
    direction: CopyDirection,
    source_path: String,
    destination_path: String,
) -> CopyJob {
    let checkpoint = CopyCheckpointIdentity {
        profile_name,
        direction,
        source_path: source_path.clone(),
        destination_path: destination_path.clone(),
        transfer_mode: CopyTransferMode::RecursiveTree,
    };

    CopyJob::CreateDirectory {
        checkpoint,
        source_path,
        destination_path,
    }
}

fn validate_planning_endpoints(spec: &CopySpec) -> Result<CopyDirection> {
    match (&spec.source, &spec.destination) {
        (CopyEndpoint::Local(_), CopyEndpoint::Remote(_)) => Ok(CopyDirection::Upload),
        (CopyEndpoint::Remote(_), CopyEndpoint::Local(_)) => Ok(CopyDirection::Download),
        _ => Err(Error::new(
            "copy requires exactly one remote path in profile:/path format",
        )),
    }
}

fn build_chunk_ranges(size: u64, effective_threads: usize) -> Vec<ChunkRange> {
    let chunk_count = effective_threads
        .min(usize::try_from(size.div_ceil(STRIPE_THRESHOLD_BYTES)).unwrap_or(usize::MAX));
    let chunk_count = chunk_count.max(1);
    let chunk_count_u64 = chunk_count as u64;
    let base = size / chunk_count_u64;
    let remainder = size % chunk_count_u64;
    let mut start = 0_u64;
    let mut chunks = Vec::with_capacity(chunk_count);

    for index in 0..chunk_count_u64 {
        let extra = u64::from(index < remainder);
        let end = start + base + extra;
        chunks.push(ChunkRange { start, end });
        start = end;
    }

    if let Some(last) = chunks.last_mut() {
        last.end = size;
    }

    chunks
}

fn plan_local_tree(root: &Path) -> Result<Vec<PlannedCopyTreeEntry>> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let relative_path = path
                .strip_prefix(root)
                .map_err(|error| Error::new(format!("failed to build local plan entry: {error}")))?
                .display()
                .to_string();

            if file_type.is_dir() {
                entries.push(PlannedCopyTreeEntry::Directory {
                    path: relative_path.clone(),
                });
                stack.push(path);
            } else if file_type.is_file() {
                entries.push(PlannedCopyTreeEntry::File {
                    path: relative_path,
                    size: entry.metadata()?.len(),
                });
            } else if file_type.is_symlink() {
                let metadata = fs::metadata(&path)?;
                if metadata.is_file() {
                    entries.push(PlannedCopyTreeEntry::File {
                        path: relative_path,
                        size: metadata.len(),
                    });
                } else if metadata.is_dir() {
                    return Err(Error::new(format!(
                        "symlinked directories are not supported during recursive copy: {}",
                        path.display()
                    )));
                } else {
                    return Err(Error::new(format!(
                        "unsupported local symlink target type: {}",
                        path.display()
                    )));
                }
            } else {
                return Err(Error::new(format!(
                    "unsupported local file type: {}",
                    path.display()
                )));
            }
        }
    }

    Ok(entries)
}

async fn plan_remote_tree(
    session: &mut dyn SshSession,
    root: &str,
) -> Result<Vec<PlannedCopyTreeEntry>> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_string()];

    while let Some(current) = stack.pop() {
        for entry in session.read_remote_dir(&current).await? {
            let path = join_remote(&current, &entry.name);
            let relative_path = path
                .strip_prefix(&format!("{}/", root.trim_end_matches('/')))
                .or_else(|| path.strip_prefix(root))
                .unwrap_or(&path)
                .trim_start_matches('/')
                .to_string();

            match entry.file_type {
                RemoteFileType::Directory => {
                    entries.push(PlannedCopyTreeEntry::Directory {
                        path: relative_path.clone(),
                    });
                    stack.push(path);
                }
                RemoteFileType::File | RemoteFileType::Symlink => {
                    let size = session
                        .remote_file_size(&path)
                        .await?
                        .ok_or_else(|| Error::new(format!("remote path was not found: {path}")))?;
                    entries.push(PlannedCopyTreeEntry::File {
                        path: relative_path,
                        size,
                    });
                }
                RemoteFileType::Other => {
                    return Err(Error::new(format!("unsupported remote file type: {path}")))
                }
            }
        }
    }

    Ok(entries)
}

fn endpoint_destination_path(endpoint: &CopyEndpoint) -> String {
    match endpoint {
        CopyEndpoint::Local(path) => path.display().to_string(),
        CopyEndpoint::Remote(remote) => remote.path.clone(),
    }
}

fn path_tail(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.trim_matches('/').to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyTransferOptions {
    pub resume_offset: u64,
    pub show_progress: bool,
    pub finish_progress_line: bool,
}

impl Default for CopyTransferOptions {
    fn default() -> Self {
        Self {
            resume_offset: 0,
            show_progress: false,
            finish_progress_line: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CopyTransferResult {
    pub bytes_copied: u64,
    pub resumed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySummary {
    pub direction: CopyDirection,
    pub bytes_copied: u64,
    pub resumed_bytes: u64,
    pub destination: String,
    pub effective_threads: usize,
    pub failed_files: usize,
    pub warnings: Vec<String>,
}

impl fmt::Display for CopySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "copy {} complete: {} bytes copied ({} resumed) to {} (effective threads: {})",
            self.direction,
            self.bytes_copied,
            self.resumed_bytes,
            self.destination,
            self.effective_threads
        )?;
        if self.failed_files > 0 {
            write!(f, ", failed files: {}", self.failed_files)?;
        }
        Ok(())
    }
}

impl fmt::Display for CopyDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            CopyDirection::Upload => "upload",
            CopyDirection::Download => "download",
        };
        f.write_str(label)
    }
}

pub fn parse_copy_spec(
    source: &str,
    destination: &str,
    recursive: bool,
    resume: bool,
    progress: bool,
) -> Result<CopySpec> {
    let source = parse_endpoint("source", source)?;
    let destination = parse_endpoint("destination", destination)?;

    match (&source, &destination) {
        (CopyEndpoint::Local(local), CopyEndpoint::Remote(_)) => {
            validate_local_source(local, recursive)?
        }
        (CopyEndpoint::Remote(_), CopyEndpoint::Local(_)) => {}
        _ => {
            return Err(Error::new(
                "copy requires exactly one remote path in profile:/path format",
            ))
        }
    }

    Ok(CopySpec {
        source,
        destination,
        recursive,
        resume,
        retry: false,
        progress,
        effective_threads: 1,
    })
}

pub async fn copy_profile(
    ssh: &dyn SshClient,
    spec: &CopySpec,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
    checkpoint_root: &Path,
) -> Result<CopySummary> {
    let checkpoint_root = checkpoint_root.join(profile_checkpoint_namespace(profile));
    if spec.effective_threads > 1 {
        let mut prepared = prepare_threaded_copy(ssh, spec, profile, context, prompt).await?;
        match prepared.plan().mode.clone() {
            CopyPlanMode::SingleStream => {
                let effective_threads = prepared.effective_threads();
                let warnings = prepared.warnings().to_vec();
                let mut summary =
                    execute_copy_with_retry(prepared.primary_session_mut(), spec).await?;
                summary.effective_threads = effective_threads;
                summary.warnings = warnings;
                Ok(summary)
            }
            CopyPlanMode::StripedFile { .. } => {
                execute_threaded_striped_copy(prepared, &checkpoint_root).await
            }
            CopyPlanMode::QueuedTree => {
                execute_threaded_recursive_copy(prepared, &checkpoint_root).await
            }
        }
    } else {
        let mut session = connect_authenticated_session(ssh, profile, context, prompt).await?;
        let mut summary = execute_copy_with_retry(&mut *session, spec).await?;
        summary.effective_threads = 1;
        summary.warnings = Vec::new();
        Ok(summary)
    }
}

const MAX_THREADED_CHUNK_ATTEMPTS: usize = 3;
const MAX_THREADED_WHOLE_FILE_ATTEMPTS: usize = 3;

#[derive(Debug, Clone)]
struct ThreadedStripedJob {
    direction: CopyDirection,
    local_path: PathBuf,
    remote_path: String,
    size: u64,
    chunks: Vec<ChunkRange>,
    policy: CopyJobPolicy,
    checkpoint: CopyCheckpointIdentity,
}

#[derive(Debug, Clone, Copy)]
struct ChunkWork {
    range: ChunkRange,
    attempt: usize,
}

#[derive(Debug, Clone)]
struct ThreadedWholeFileJob {
    direction: CopyDirection,
    local_path: PathBuf,
    remote_path: String,
    size: u64,
    resume_offset: u64,
    retry: CopyRetryStrategy,
}

#[derive(Debug, Clone)]
enum ThreadedTreeWork {
    WholeFile {
        job: ThreadedWholeFileJob,
        attempt: usize,
    },
    StripedChunk {
        state: Arc<Mutex<ThreadedRecursiveStripedState>>,
        range: ChunkRange,
        attempt: usize,
    },
}

#[derive(Debug)]
struct ThreadedRecursiveStripedState {
    job: ThreadedStripedJob,
    remaining_chunks: usize,
    checkpoint_state: CopyCheckpointState,
    failed: bool,
    finalized: bool,
}

#[derive(Debug, Default)]
struct ThreadedRecursiveStats {
    bytes_copied: u64,
    resumed_bytes: u64,
}

#[derive(Debug, Default)]
struct ThreadedRecursiveFailures {
    failed_keys: HashSet<String>,
    messages: Vec<String>,
}

async fn execute_threaded_striped_copy(
    prepared: super::PreparedTransferPlan,
    checkpoint_root: &Path,
) -> Result<CopySummary> {
    let (mut sessions, plan, effective_threads, warnings, show_progress) = prepared.into_parts();
    let job = threaded_striped_job(&plan)?;
    let total_bytes = job.size;
    let progress_label = threaded_progress_label(job.direction, &threaded_destination_label(&job));
    let progress = Arc::new(AsyncMutex::new(ThreadedProgressReporter::new(
        tokio::io::stderr(),
        ProgressMode::from_stderr(show_progress),
    )));
    let checkpoint_store = CopyCheckpointStore::new(checkpoint_root.to_path_buf());
    let primary = sessions
        .first_mut()
        .ok_or_else(|| Error::new("threaded copy prepared without any transfer sessions"))?;
    let (initial_state, missing_ranges, resume_from_checkpoint) =
        load_threaded_checkpoint(primary.as_mut(), &job, &checkpoint_store).await?;
    let resumed_bytes = initial_state.resumed_bytes();
    render_threaded_progress(
        progress.as_ref(),
        &progress_label,
        resumed_bytes,
        total_bytes,
        resumed_bytes,
        effective_threads,
        0,
    )
    .await?;

    if missing_ranges.is_empty() {
        apply_threaded_metadata(primary.as_mut(), &job).await?;
        checkpoint_store.delete(&job.checkpoint)?;
        progress.lock().await.finish().await?;
        return Ok(CopySummary {
            direction: job.direction,
            bytes_copied: 0,
            resumed_bytes,
            destination: threaded_destination_label(&job),
            effective_threads,
            failed_files: 0,
            warnings,
        });
    }

    prepare_threaded_destination(primary.as_mut(), &job, resume_from_checkpoint).await?;

    let queue = Arc::new(Mutex::new(VecDeque::from(
        missing_ranges
            .into_iter()
            .map(|range| ChunkWork { range, attempt: 1 })
            .collect::<Vec<_>>(),
    )));
    let checkpoint_state = Arc::new(Mutex::new(initial_state));
    let checkpoint_store = Arc::new(checkpoint_store);
    let shared_error = Arc::new(Mutex::new(None));
    let copied_bytes = Arc::new(Mutex::new(0_u64));
    let retry_enabled = matches!(job.policy.retry, CopyRetryStrategy::RetryStripedChunks);
    let mut join_set: JoinSet<Result<(Box<dyn SshSession + Send>, u64)>> = JoinSet::new();

    for session in sessions {
        let queue = Arc::clone(&queue);
        let checkpoint_state = Arc::clone(&checkpoint_state);
        let checkpoint_store = Arc::clone(&checkpoint_store);
        let shared_error = Arc::clone(&shared_error);
        let copied_bytes = Arc::clone(&copied_bytes);
        let progress = Arc::clone(&progress);
        let progress_label = progress_label.clone();
        let job = job.clone();

        join_set.spawn(async move {
            let mut session = session;
            let mut copied = 0_u64;
            loop {
                if shared_error.lock().unwrap().is_some() {
                    break Ok((session, copied));
                }

                let Some(work) = queue.lock().unwrap().pop_front() else {
                    break Ok((session, copied));
                };

                match execute_threaded_chunk(session.as_mut(), &job, work.range).await {
                    Ok(bytes) => {
                        let destination_identity =
                            threaded_destination_identity(session.as_mut(), &job).await?;
                        {
                            let mut state = checkpoint_state.lock().unwrap();
                            state.mark_completed(work.range);
                            state.set_destination(destination_identity);
                            checkpoint_store.save(&job.checkpoint, &state)?;
                        }
                        copied = copied.saturating_add(bytes);
                        let aggregate_copied = {
                            let mut guard = copied_bytes.lock().unwrap();
                            *guard = guard.saturating_add(bytes);
                            *guard
                        };
                        render_threaded_progress(
                            progress.as_ref(),
                            &progress_label,
                            resumed_bytes.saturating_add(aggregate_copied),
                            total_bytes,
                            resumed_bytes,
                            effective_threads,
                            0,
                        )
                        .await?;
                    }
                    Err(error)
                        if retry_enabled
                            && work.attempt < MAX_THREADED_CHUNK_ATTEMPTS
                            && is_transient_copy_error(&error) =>
                    {
                        queue.lock().unwrap().push_back(ChunkWork {
                            range: work.range,
                            attempt: work.attempt + 1,
                        });
                    }
                    Err(error) => {
                        set_shared_copy_error(&shared_error, error);
                        break Ok((session, copied));
                    }
                }
            }
        });
    }

    let mut bytes_copied = 0_u64;
    let mut metadata_session: Option<Box<dyn SshSession + Send>> = None;
    while let Some(result) = join_set.join_next().await {
        let (session, copied) = result
            .map_err(|error| Error::new(format!("threaded copy worker failed: {error}")))??;
        if metadata_session.is_none() {
            metadata_session = Some(session);
        }
        bytes_copied = bytes_copied.saturating_add(copied);
    }

    let shared_error = {
        let mut guard = shared_error.lock().unwrap();
        guard.take()
    };
    if let Some(error) = shared_error {
        progress.lock().await.finish().await?;
        return Err(error);
    }

    let mut metadata_session = metadata_session
        .ok_or_else(|| Error::new("threaded copy finished without a transfer session"))?;
    apply_threaded_metadata(metadata_session.as_mut(), &job).await?;
    checkpoint_store.delete(&job.checkpoint)?;
    progress.lock().await.finish().await?;
    Ok(CopySummary {
        direction: job.direction,
        bytes_copied,
        resumed_bytes,
        destination: threaded_destination_label(&job),
        effective_threads,
        failed_files: 0,
        warnings,
    })
}

async fn execute_threaded_recursive_copy(
    prepared: super::PreparedTransferPlan,
    checkpoint_root: &Path,
) -> Result<CopySummary> {
    let (mut sessions, plan, effective_threads, warnings, show_progress) = prepared.into_parts();
    let direction = recursive_plan_direction(&plan)?;
    let destination = recursive_plan_destination(&plan)?;
    let progress_label = threaded_progress_label(direction, &destination);
    let total_bytes = plan_total_bytes(&plan);
    let progress = Arc::new(AsyncMutex::new(ThreadedProgressReporter::new(
        tokio::io::stderr(),
        ProgressMode::from_stderr(show_progress),
    )));
    let checkpoint_store = Arc::new(CopyCheckpointStore::new(checkpoint_root.to_path_buf()));
    let primary = sessions.first_mut().ok_or_else(|| {
        Error::new("threaded recursive copy prepared without any transfer sessions")
    })?;
    let queue = Arc::new(Mutex::new(VecDeque::new()));
    let stats = Arc::new(Mutex::new(ThreadedRecursiveStats::default()));
    let failures = Arc::new(Mutex::new(ThreadedRecursiveFailures::default()));

    prepare_recursive_tree_work(
        primary.as_mut(),
        &plan,
        checkpoint_store.as_ref(),
        queue.as_ref(),
        stats.as_ref(),
        failures.as_ref(),
    )
    .await?;
    {
        let (copied, resumed) = {
            let guard = stats.lock().unwrap();
            (guard.bytes_copied, guard.resumed_bytes)
        };
        render_threaded_progress(
            progress.as_ref(),
            &progress_label,
            copied.saturating_add(resumed),
            total_bytes,
            resumed,
            effective_threads,
            0,
        )
        .await?;
    }

    let mut join_set: JoinSet<Result<()>> = JoinSet::new();
    for session in sessions {
        let queue = Arc::clone(&queue);
        let stats = Arc::clone(&stats);
        let failures = Arc::clone(&failures);
        let checkpoint_store = Arc::clone(&checkpoint_store);
        let progress = Arc::clone(&progress);
        let progress_label = progress_label.clone();

        join_set.spawn(async move {
            let mut session = session;
            loop {
                let Some(work) = queue.lock().unwrap().pop_front() else {
                    break Ok(());
                };

                match work {
                    ThreadedTreeWork::WholeFile { job, attempt } => {
                        if recursive_failure_recorded(failures.as_ref(), &job.remote_path) {
                            continue;
                        }

                        match execute_threaded_whole_file(session.as_mut(), &job).await {
                            Ok(result) => {
                                let (copied, resumed) = {
                                    let mut guard = stats.lock().unwrap();
                                    guard.bytes_copied =
                                        guard.bytes_copied.saturating_add(result.bytes_copied);
                                    guard.resumed_bytes =
                                        guard.resumed_bytes.saturating_add(result.resumed_bytes);
                                    (guard.bytes_copied, guard.resumed_bytes)
                                };
                                render_threaded_progress(
                                    progress.as_ref(),
                                    &progress_label,
                                    copied.saturating_add(resumed),
                                    total_bytes,
                                    resumed,
                                    effective_threads,
                                    {
                                        let guard = failures.lock().unwrap();
                                        guard.failed_keys.len()
                                    },
                                )
                                .await?;
                            }
                            Err(error)
                                if matches!(job.retry, CopyRetryStrategy::RetryWholeFile)
                                    && attempt < MAX_THREADED_WHOLE_FILE_ATTEMPTS
                                    && is_transient_copy_error(&error) =>
                            {
                                queue
                                    .lock()
                                    .unwrap()
                                    .push_back(ThreadedTreeWork::WholeFile {
                                        job,
                                        attempt: attempt + 1,
                                    });
                            }
                            Err(error) => {
                                record_recursive_failure(
                                    failures.as_ref(),
                                    &job.remote_path,
                                    format!("{}: {}", job.remote_path, error),
                                );
                                let failed_files = {
                                    let guard = failures.lock().unwrap();
                                    guard.failed_keys.len()
                                };
                                let (copied, resumed) = {
                                    let guard = stats.lock().unwrap();
                                    (guard.bytes_copied, guard.resumed_bytes)
                                };
                                render_threaded_progress(
                                    progress.as_ref(),
                                    &progress_label,
                                    copied.saturating_add(resumed),
                                    total_bytes,
                                    resumed,
                                    effective_threads,
                                    failed_files,
                                )
                                .await?;
                            }
                        }
                    }
                    ThreadedTreeWork::StripedChunk {
                        state,
                        range,
                        attempt,
                    } => {
                        let job = {
                            let guard = state.lock().unwrap();
                            if guard.failed {
                                continue;
                            }
                            guard.job.clone()
                        };

                        match execute_threaded_chunk(session.as_mut(), &job, range).await {
                            Ok(bytes) => {
                                let destination_identity =
                                    threaded_destination_identity(session.as_mut(), &job).await?;
                                let should_finalize = {
                                    let mut guard = state.lock().unwrap();
                                    if guard.failed {
                                        let snapshot = stats.lock().unwrap();
                                        (false, snapshot.bytes_copied, snapshot.resumed_bytes)
                                    } else {
                                        guard.checkpoint_state.mark_completed(range);
                                        guard
                                            .checkpoint_state
                                            .set_destination(destination_identity);
                                        checkpoint_store
                                            .save(&job.checkpoint, &guard.checkpoint_state)?;
                                        guard.remaining_chunks =
                                            guard.remaining_chunks.saturating_sub(1);
                                        let mut stats = stats.lock().unwrap();
                                        stats.bytes_copied =
                                            stats.bytes_copied.saturating_add(bytes);
                                        (
                                            guard.remaining_chunks == 0 && !guard.finalized,
                                            stats.bytes_copied,
                                            stats.resumed_bytes,
                                        )
                                    }
                                };
                                render_threaded_progress(
                                    progress.as_ref(),
                                    &progress_label,
                                    should_finalize.1.saturating_add(should_finalize.2),
                                    total_bytes,
                                    should_finalize.2,
                                    effective_threads,
                                    {
                                        let guard = failures.lock().unwrap();
                                        guard.failed_keys.len()
                                    },
                                )
                                .await?;

                                if should_finalize.0 {
                                    apply_threaded_metadata(session.as_mut(), &job).await?;
                                    checkpoint_store.delete(&job.checkpoint)?;
                                    let mut guard = state.lock().unwrap();
                                    guard.finalized = true;
                                }
                            }
                            Err(error)
                                if matches!(
                                    job.policy.retry,
                                    CopyRetryStrategy::RetryStripedChunks
                                ) && attempt < MAX_THREADED_CHUNK_ATTEMPTS
                                    && is_transient_copy_error(&error) =>
                            {
                                queue
                                    .lock()
                                    .unwrap()
                                    .push_back(ThreadedTreeWork::StripedChunk {
                                        state,
                                        range,
                                        attempt: attempt + 1,
                                    });
                            }
                            Err(error) => {
                                {
                                    let mut guard = state.lock().unwrap();
                                    guard.failed = true;
                                }
                                record_recursive_failure(
                                    failures.as_ref(),
                                    &job.remote_path,
                                    format!("{}: {}", job.remote_path, error),
                                );
                                let failed_files = {
                                    let guard = failures.lock().unwrap();
                                    guard.failed_keys.len()
                                };
                                let (copied, resumed) = {
                                    let guard = stats.lock().unwrap();
                                    (guard.bytes_copied, guard.resumed_bytes)
                                };
                                render_threaded_progress(
                                    progress.as_ref(),
                                    &progress_label,
                                    copied.saturating_add(resumed),
                                    total_bytes,
                                    resumed,
                                    effective_threads,
                                    failed_files,
                                )
                                .await?;
                            }
                        }
                    }
                }
            }
        });
    }

    while let Some(result) = join_set.join_next().await {
        result
            .map_err(|error| Error::new(format!("threaded recursive worker failed: {error}")))??;
    }

    let (failure_count, failure_message) = {
        let guard = failures.lock().unwrap();
        (guard.messages.len(), guard.messages.join("; "))
    };
    if failure_count > 0 {
        progress.lock().await.finish().await?;
        return Err(Error::new(format!(
            "threaded recursive copy failed for {} file(s): {}",
            failure_count, failure_message
        )));
    }

    let (bytes_copied, resumed_bytes) = {
        let guard = stats.lock().unwrap();
        (guard.bytes_copied, guard.resumed_bytes)
    };
    progress.lock().await.finish().await?;
    Ok(CopySummary {
        direction,
        bytes_copied,
        resumed_bytes,
        destination,
        effective_threads,
        failed_files: 0,
        warnings,
    })
}

fn threaded_striped_job(plan: &CopyPlan) -> Result<ThreadedStripedJob> {
    match plan.jobs.as_slice() {
        [CopyJob::StripedFile {
            source_path,
            destination_path,
            size,
            chunks,
            policy,
            checkpoint,
        }] => Ok(match checkpoint.direction {
            CopyDirection::Upload => ThreadedStripedJob {
                direction: CopyDirection::Upload,
                local_path: PathBuf::from(source_path),
                remote_path: destination_path.clone(),
                size: *size,
                chunks: chunks.clone(),
                policy: policy.clone(),
                checkpoint: checkpoint.clone(),
            },
            CopyDirection::Download => ThreadedStripedJob {
                direction: CopyDirection::Download,
                local_path: PathBuf::from(destination_path),
                remote_path: source_path.clone(),
                size: *size,
                chunks: chunks.clone(),
                policy: policy.clone(),
                checkpoint: checkpoint.clone(),
            },
        }),
        _ => Err(Error::new(
            "threaded striped copy expected exactly one striped single-file job",
        )),
    }
}

async fn prepare_recursive_tree_work(
    session: &mut dyn SshSession,
    plan: &CopyPlan,
    checkpoint_store: &CopyCheckpointStore,
    queue: &Mutex<VecDeque<ThreadedTreeWork>>,
    stats: &Mutex<ThreadedRecursiveStats>,
    failures: &Mutex<ThreadedRecursiveFailures>,
) -> Result<()> {
    for job in &plan.jobs {
        match job {
            CopyJob::CreateDirectory {
                destination_path,
                checkpoint,
                ..
            } => match checkpoint.direction {
                CopyDirection::Upload => session.create_remote_dir_all(destination_path).await?,
                CopyDirection::Download => fs::create_dir_all(destination_path)?,
            },
            CopyJob::WholeFile {
                source_path,
                destination_path,
                size,
                policy,
                ..
            } => {
                let job = threaded_whole_file_job(
                    session,
                    plan,
                    source_path,
                    destination_path,
                    *size,
                    policy,
                )
                .await?;

                if job.resume_offset >= job.size {
                    let mut guard = stats.lock().unwrap();
                    guard.resumed_bytes = guard.resumed_bytes.saturating_add(job.size);
                } else {
                    queue
                        .lock()
                        .unwrap()
                        .push_back(ThreadedTreeWork::WholeFile { job, attempt: 1 });
                }
            }
            CopyJob::StripedFile {
                source_path,
                destination_path,
                size,
                chunks,
                policy,
                checkpoint,
            } => {
                let job = threaded_striped_tree_job(
                    plan,
                    source_path,
                    destination_path,
                    *size,
                    chunks,
                    policy,
                    checkpoint,
                )?;
                let (initial_state, missing_ranges, resume_from_checkpoint) =
                    load_threaded_checkpoint(session, &job, checkpoint_store).await?;
                {
                    let mut guard = stats.lock().unwrap();
                    guard.resumed_bytes = guard
                        .resumed_bytes
                        .saturating_add(initial_state.resumed_bytes());
                }

                if missing_ranges.is_empty() {
                    apply_threaded_metadata(session, &job).await?;
                    checkpoint_store.delete(&job.checkpoint)?;
                    continue;
                }

                prepare_threaded_destination(session, &job, resume_from_checkpoint).await?;
                let state = Arc::new(Mutex::new(ThreadedRecursiveStripedState {
                    job,
                    remaining_chunks: missing_ranges.len(),
                    checkpoint_state: initial_state,
                    failed: false,
                    finalized: false,
                }));

                for range in missing_ranges {
                    queue
                        .lock()
                        .unwrap()
                        .push_back(ThreadedTreeWork::StripedChunk {
                            state: Arc::clone(&state),
                            range,
                            attempt: 1,
                        });
                }
            }
        }
    }

    let queued = !queue.lock().unwrap().is_empty();
    if !queued && !failures.lock().unwrap().messages.is_empty() {
        return Err(Error::new(
            "threaded recursive copy could not schedule any transferable work",
        ));
    }

    Ok(())
}

async fn threaded_whole_file_job(
    session: &mut dyn SshSession,
    plan: &CopyPlan,
    source_path: &str,
    destination_path: &str,
    size: u64,
    policy: &CopyJobPolicy,
) -> Result<ThreadedWholeFileJob> {
    let direction = recursive_plan_direction(plan)?;
    let (local_path, remote_path, resume_offset) = match direction {
        CopyDirection::Upload => {
            let local_path = PathBuf::from(source_path);
            let resume_offset = match policy.resume {
                CopyResumeStrategy::DestinationSizeResume => {
                    resolve_upload_resume_offset(session, &local_path, destination_path, true)
                        .await?
                }
                CopyResumeStrategy::Disabled | CopyResumeStrategy::Checkpointed { .. } => 0,
            };
            (local_path, destination_path.to_string(), resume_offset)
        }
        CopyDirection::Download => {
            let local_path = PathBuf::from(destination_path);
            let resume_offset = match policy.resume {
                CopyResumeStrategy::DestinationSizeResume => {
                    resolve_download_resume_offset(session, source_path, &local_path, true).await?
                }
                CopyResumeStrategy::Disabled | CopyResumeStrategy::Checkpointed { .. } => 0,
            };
            (local_path, source_path.to_string(), resume_offset)
        }
    };

    Ok(ThreadedWholeFileJob {
        direction,
        local_path,
        remote_path,
        size,
        resume_offset,
        retry: policy.retry,
    })
}

fn threaded_striped_tree_job(
    plan: &CopyPlan,
    source_path: &str,
    destination_path: &str,
    size: u64,
    chunks: &[ChunkRange],
    policy: &CopyJobPolicy,
    checkpoint: &CopyCheckpointIdentity,
) -> Result<ThreadedStripedJob> {
    let direction = recursive_plan_direction(plan)?;
    Ok(match direction {
        CopyDirection::Upload => ThreadedStripedJob {
            direction,
            local_path: PathBuf::from(source_path),
            remote_path: destination_path.to_string(),
            size,
            chunks: chunks.to_vec(),
            policy: policy.clone(),
            checkpoint: checkpoint.clone(),
        },
        CopyDirection::Download => ThreadedStripedJob {
            direction,
            local_path: PathBuf::from(destination_path),
            remote_path: source_path.to_string(),
            size,
            chunks: chunks.to_vec(),
            policy: policy.clone(),
            checkpoint: checkpoint.clone(),
        },
    })
}

async fn load_threaded_checkpoint(
    session: &mut dyn SshSession,
    job: &ThreadedStripedJob,
    checkpoint_store: &CopyCheckpointStore,
) -> Result<(CopyCheckpointState, Vec<ChunkRange>, bool)> {
    let source_identity = threaded_source_identity(session, job).await?;
    let current_destination = threaded_destination_identity(session, job).await?;

    match &job.policy.resume {
        CopyResumeStrategy::Checkpointed { checkpoint } => {
            if let Some(state) = checkpoint_store.load(checkpoint)? {
                validate_threaded_checkpoint(job, &state, source_identity, current_destination)?;
                let missing = state.incomplete_ranges(&job.chunks);
                Ok((state, missing, true))
            } else {
                Ok((
                    CopyCheckpointState::new(job.size, source_identity, current_destination),
                    job.chunks.clone(),
                    false,
                ))
            }
        }
        CopyResumeStrategy::Disabled | CopyResumeStrategy::DestinationSizeResume => {
            checkpoint_store.delete(&job.checkpoint)?;
            Ok((
                CopyCheckpointState::new(job.size, source_identity, current_destination),
                job.chunks.clone(),
                false,
            ))
        }
    }
}

async fn execute_threaded_whole_file(
    session: &mut dyn SshSession,
    job: &ThreadedWholeFileJob,
) -> Result<CopyTransferResult> {
    match job.direction {
        CopyDirection::Upload => {
            session
                .upload_file(
                    &job.local_path,
                    &job.remote_path,
                    CopyTransferOptions {
                        resume_offset: job.resume_offset,
                        show_progress: false,
                        finish_progress_line: false,
                    },
                )
                .await
        }
        CopyDirection::Download => {
            session
                .download_file(
                    &job.remote_path,
                    &job.local_path,
                    CopyTransferOptions {
                        resume_offset: job.resume_offset,
                        show_progress: false,
                        finish_progress_line: false,
                    },
                )
                .await
        }
    }
}

fn validate_threaded_checkpoint(
    job: &ThreadedStripedJob,
    state: &CopyCheckpointState,
    source_identity: CheckpointFileIdentity,
    destination_identity: Option<CheckpointFileIdentity>,
) -> Result<()> {
    let destination_size = destination_identity.map(|identity| identity.size_bytes());
    if state.total_bytes() != job.size
        || state.source() != source_identity
        || state.destination().map(|identity| identity.size_bytes()) != destination_size
    {
        return Err(Error::new(format!(
            "incompatible checkpoint state for {} -> {}",
            job.checkpoint.source_path, job.checkpoint.destination_path
        )));
    }

    Ok(())
}

async fn prepare_threaded_destination(
    session: &mut dyn SshSession,
    job: &ThreadedStripedJob,
    resume_from_checkpoint: bool,
) -> Result<()> {
    match job.direction {
        CopyDirection::Upload => {
            if let Some(parent) = remote_parent(&job.remote_path) {
                session.create_remote_dir_all(&parent).await?;
            }
            if !resume_from_checkpoint {
                session
                    .prepare_remote_file_destination(&job.remote_path, true)
                    .await?;
            }
        }
        CopyDirection::Download => {
            prepare_local_file_destination(&job.local_path, !resume_from_checkpoint)?
        }
    }
    Ok(())
}

async fn execute_threaded_chunk(
    session: &mut dyn SshSession,
    job: &ThreadedStripedJob,
    range: ChunkRange,
) -> Result<u64> {
    match job.direction {
        CopyDirection::Upload => {
            session
                .upload_file_range(&job.local_path, &job.remote_path, range)
                .await
        }
        CopyDirection::Download => {
            session
                .download_file_range(&job.remote_path, &job.local_path, range)
                .await
        }
    }
}

async fn threaded_source_identity(
    session: &mut dyn SshSession,
    job: &ThreadedStripedJob,
) -> Result<CheckpointFileIdentity> {
    match job.direction {
        CopyDirection::Upload => local_file_identity(&job.local_path),
        CopyDirection::Download => session
            .remote_file_metadata(&job.remote_path)
            .await?
            .map(Into::into)
            .ok_or_else(|| Error::new(format!("remote path was not found: {}", job.remote_path))),
    }
}

async fn threaded_destination_identity(
    session: &mut dyn SshSession,
    job: &ThreadedStripedJob,
) -> Result<Option<CheckpointFileIdentity>> {
    match job.direction {
        CopyDirection::Upload => Ok(session
            .remote_file_metadata(&job.remote_path)
            .await?
            .map(Into::into)),
        CopyDirection::Download => Ok(local_file_metadata(&job.local_path)?.map(Into::into)),
    }
}

fn local_file_identity(path: &Path) -> Result<CheckpointFileIdentity> {
    local_file_metadata(path)?
        .map(Into::into)
        .ok_or_else(|| Error::new(format!("local path was not found: {}", path.display())))
}

fn local_file_metadata(path: &Path) -> Result<Option<CopyFileMetadata>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(CopyFileMetadata::new(
            metadata.len(),
            metadata
                .modified()
                .ok()
                .and_then(|mtime| mtime.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs()),
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn prepare_local_file_destination(path: &Path, truncate: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(truncate)
        .open(path)?;
    if truncate {
        file.set_len(0)?;
    }
    Ok(())
}

fn set_shared_copy_error(shared_error: &Arc<Mutex<Option<Error>>>, error: Error) {
    let mut guard = shared_error.lock().unwrap();
    if guard.is_none() {
        *guard = Some(error);
    }
}

fn recursive_plan_direction(plan: &CopyPlan) -> Result<CopyDirection> {
    match plan.jobs.first() {
        Some(CopyJob::CreateDirectory { checkpoint, .. })
        | Some(CopyJob::WholeFile { checkpoint, .. })
        | Some(CopyJob::StripedFile { checkpoint, .. }) => Ok(checkpoint.direction),
        None => Err(Error::new(
            "threaded recursive copy plan did not contain any jobs",
        )),
    }
}

fn recursive_plan_destination(plan: &CopyPlan) -> Result<String> {
    match plan.jobs.first() {
        Some(CopyJob::CreateDirectory {
            destination_path, ..
        })
        | Some(CopyJob::WholeFile {
            destination_path, ..
        })
        | Some(CopyJob::StripedFile {
            destination_path, ..
        }) => Ok(destination_path.clone()),
        None => Err(Error::new(
            "threaded recursive copy plan did not contain any jobs",
        )),
    }
}

fn recursive_failure_recorded(failures: &Mutex<ThreadedRecursiveFailures>, key: &str) -> bool {
    failures.lock().unwrap().failed_keys.contains(key)
}

fn record_recursive_failure(
    failures: &Mutex<ThreadedRecursiveFailures>,
    key: &str,
    message: String,
) {
    let mut guard = failures.lock().unwrap();
    if guard.failed_keys.insert(key.to_string()) {
        guard.messages.push(message);
    }
}

fn threaded_destination_label(job: &ThreadedStripedJob) -> String {
    match job.direction {
        CopyDirection::Upload => job.remote_path.clone(),
        CopyDirection::Download => job.local_path.display().to_string(),
    }
}

fn threaded_progress_label(direction: CopyDirection, destination: &str) -> String {
    format!("threaded {direction} {destination}")
}

fn plan_total_bytes(plan: &CopyPlan) -> u64 {
    plan.jobs
        .iter()
        .map(|job| match job {
            CopyJob::WholeFile { size, .. } | CopyJob::StripedFile { size, .. } => *size,
            CopyJob::CreateDirectory { .. } => 0,
        })
        .sum()
}

async fn render_threaded_progress(
    progress: &AsyncMutex<ThreadedProgressReporter<tokio::io::Stderr>>,
    label: &str,
    copied_bytes: u64,
    total_bytes: u64,
    resumed_bytes: u64,
    effective_threads: usize,
    failed_files: usize,
) -> Result<()> {
    progress
        .lock()
        .await
        .render(&AggregateProgressSnapshot {
            label: label.to_string(),
            copied_bytes,
            total_bytes,
            resumed_bytes,
            effective_threads,
            failed_files,
        })
        .await
}

async fn apply_threaded_metadata(
    session: &mut dyn SshSession,
    job: &ThreadedStripedJob,
) -> Result<()> {
    match job.direction {
        CopyDirection::Upload => {
            session
                .apply_uploaded_file_metadata(&job.local_path, &job.remote_path)
                .await
        }
        CopyDirection::Download => {
            session
                .apply_downloaded_file_metadata(&job.remote_path, &job.local_path)
                .await
        }
    }
}

fn profile_checkpoint_namespace(profile: &Profile) -> String {
    let payload = format!(
        "v1\0{}\0{}\0{}\0{}",
        profile.name, profile.host, profile.port, profile.username
    );
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

async fn prepare_threaded_copy(
    ssh: &dyn SshClient,
    spec: &CopySpec,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
) -> Result<super::PreparedTransferPlan> {
    let mut pool =
        establish_transfer_sessions(ssh, profile, context, prompt, spec.effective_threads).await?;
    let (planning_spec, destination_shape, source) =
        inspect_planning_inputs(pool.primary_session_mut(), spec).await?;
    pool.prepare_plan(planning_spec, destination_shape, source)
}

async fn inspect_planning_inputs(
    session: &mut dyn SshSession,
    spec: &CopySpec,
) -> Result<(CopySpec, CopyDestinationShape, PlannedCopySource)> {
    match (&spec.source, &spec.destination) {
        (CopyEndpoint::Local(source), CopyEndpoint::Remote(destination)) => {
            let mut planning_spec = spec.clone();
            let resolved_destination = session.resolve_remote_path(&destination.path).await?;
            planning_spec.destination = CopyEndpoint::Remote(RemotePath {
                profile: destination.profile.clone(),
                path: resolved_destination.clone(),
            });

            let metadata = fs::metadata(source)?;
            if metadata.is_dir() {
                let destination_shape = CopyDestinationShape::new(matches!(
                    session.remote_file_type(&resolved_destination).await?,
                    Some(RemoteFileType::Directory)
                ));
                Ok((
                    planning_spec,
                    destination_shape,
                    PlannedCopySource::Tree {
                        root: source.display().to_string(),
                        entries: plan_local_tree(source)?,
                    },
                ))
            } else {
                Ok((
                    planning_spec,
                    CopyDestinationShape::new(false),
                    PlannedCopySource::File {
                        path: source.display().to_string(),
                        size: metadata.len(),
                    },
                ))
            }
        }
        (CopyEndpoint::Remote(source), CopyEndpoint::Local(destination)) => {
            let mut planning_spec = spec.clone();
            let resolved_source = session.resolve_remote_path(&source.path).await?;
            planning_spec.source = CopyEndpoint::Remote(RemotePath {
                profile: source.profile.clone(),
                path: resolved_source.clone(),
            });

            let destination_shape = CopyDestinationShape::new(path_is_directory(destination)?);
            match session.remote_file_type(&resolved_source).await? {
                Some(RemoteFileType::Directory) => Ok((
                    planning_spec,
                    destination_shape,
                    PlannedCopySource::Tree {
                        root: resolved_source.clone(),
                        entries: plan_remote_tree(session, &resolved_source).await?,
                    },
                )),
                Some(RemoteFileType::File) | Some(RemoteFileType::Symlink) => Ok((
                    planning_spec,
                    destination_shape,
                    PlannedCopySource::File {
                        path: resolved_source.clone(),
                        size: session
                            .remote_file_size(&resolved_source)
                            .await?
                            .ok_or_else(|| {
                                Error::new(format!("remote path was not found: {resolved_source}"))
                            })?,
                    },
                )),
                Some(RemoteFileType::Other) => Err(Error::new(format!(
                    "unsupported remote file type: {resolved_source}"
                ))),
                None => Err(Error::new(format!(
                    "remote path was not found: {resolved_source}"
                ))),
            }
        }
        _ => Err(Error::new(
            "copy requires exactly one remote path in profile:/path format",
        )),
    }
}

async fn execute_copy_with_retry(
    session: &mut dyn SshSession,
    spec: &CopySpec,
) -> Result<CopySummary> {
    const MAX_ATTEMPTS: usize = 3;

    let attempts = if spec.retry { MAX_ATTEMPTS } else { 1 };
    let mut last_error = None;
    for _ in 0..attempts {
        match execute_copy(session, spec).await {
            Ok(summary) => return Ok(summary),
            Err(error) if spec.retry && is_transient_copy_error(&error) => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_error.unwrap_or_else(|| Error::new("copy failed after retry attempts")))
}

fn is_transient_copy_error(error: &Error) -> bool {
    matches!(error, Error::Message(message) if message.to_ascii_lowercase().contains("transient"))
}

async fn execute_copy(session: &mut dyn SshSession, spec: &CopySpec) -> Result<CopySummary> {
    match (&spec.source, &spec.destination) {
        (CopyEndpoint::Local(source), CopyEndpoint::Remote(destination)) => {
            upload(session, source, &destination.path, spec).await
        }
        (CopyEndpoint::Remote(source), CopyEndpoint::Local(destination)) => {
            download(session, &source.path, destination, spec).await
        }
        _ => Err(Error::new(
            "copy requires exactly one remote path in profile:/path format",
        )),
    }
}

async fn upload(
    session: &mut dyn SshSession,
    source: &Path,
    destination: &str,
    spec: &CopySpec,
) -> Result<CopySummary> {
    let resolved_destination = session.resolve_remote_path(destination).await?;
    let metadata = fs::metadata(source)?;
    if metadata.is_dir() {
        if !spec.recursive {
            return Err(Error::new("copying directories requires --recursive"));
        }

        let root = resolve_remote_directory_target(session, source, &resolved_destination).await?;
        let result = upload_dir_recursive(
            session,
            source,
            &root,
            CopyTransferOptions {
                resume_offset: 0,
                show_progress: spec.progress,
                finish_progress_line: true,
            },
        )
        .await?;
        Ok(CopySummary {
            direction: CopyDirection::Upload,
            bytes_copied: result.bytes_copied,
            resumed_bytes: result.resumed_bytes,
            destination: root,
            effective_threads: 1,
            failed_files: 0,
            warnings: Vec::new(),
        })
    } else if metadata.is_file() {
        let target = resolve_remote_file_target(session, source, &resolved_destination).await?;
        let resume_offset =
            resolve_upload_resume_offset(session, source, &target, spec.resume).await?;
        if let Some(parent) = remote_parent(&target) {
            session.create_remote_dir_all(&parent).await?;
        }
        let result = session
            .upload_file(
                source,
                &target,
                CopyTransferOptions {
                    resume_offset,
                    show_progress: spec.progress,
                    finish_progress_line: true,
                },
            )
            .await?;
        Ok(CopySummary {
            direction: CopyDirection::Upload,
            bytes_copied: result.bytes_copied,
            resumed_bytes: result.resumed_bytes,
            destination: target,
            effective_threads: 1,
            failed_files: 0,
            warnings: Vec::new(),
        })
    } else {
        Err(Error::new(format!(
            "unsupported local file type: {}",
            source.display()
        )))
    }
}

async fn download(
    session: &mut dyn SshSession,
    source: &str,
    destination: &Path,
    spec: &CopySpec,
) -> Result<CopySummary> {
    let resolved_source = session.resolve_remote_path(source).await?;
    match session.remote_file_type(&resolved_source).await? {
        Some(RemoteFileType::Directory) => {
            if !spec.recursive {
                return Err(Error::new("copying directories requires --recursive"));
            }

            let root = resolve_local_directory_target(&resolved_source, destination)?;
            let result = download_dir_recursive(
                session,
                &resolved_source,
                &root,
                CopyTransferOptions {
                    resume_offset: 0,
                    show_progress: spec.progress,
                    finish_progress_line: true,
                },
            )
            .await?;
            Ok(CopySummary {
                direction: CopyDirection::Download,
                bytes_copied: result.bytes_copied,
                resumed_bytes: result.resumed_bytes,
                destination: root.display().to_string(),
                effective_threads: 1,
                failed_files: 0,
                warnings: Vec::new(),
            })
        }
        Some(RemoteFileType::File) | Some(RemoteFileType::Symlink) => {
            let target = resolve_local_file_target(&resolved_source, destination)?;
            let resume_offset =
                resolve_download_resume_offset(session, &resolved_source, &target, spec.resume)
                    .await?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let result = session
                .download_file(
                    &resolved_source,
                    &target,
                    CopyTransferOptions {
                        resume_offset,
                        show_progress: spec.progress,
                        finish_progress_line: true,
                    },
                )
                .await?;
            Ok(CopySummary {
                direction: CopyDirection::Download,
                bytes_copied: result.bytes_copied,
                resumed_bytes: result.resumed_bytes,
                destination: target.display().to_string(),
                effective_threads: 1,
                failed_files: 0,
                warnings: Vec::new(),
            })
        }
        Some(RemoteFileType::Other) => Err(Error::new(format!(
            "unsupported remote file type: {resolved_source}"
        ))),
        None => Err(Error::new(format!(
            "remote path was not found: {resolved_source}"
        ))),
    }
}

async fn upload_dir_recursive(
    session: &mut dyn SshSession,
    local_dir: &Path,
    remote_dir: &str,
    options: CopyTransferOptions,
) -> Result<CopyTransferResult> {
    let mut stack = vec![(local_dir.to_path_buf(), remote_dir.to_string())];
    let mut bytes_copied = 0_u64;

    while let Some((local_dir, remote_dir)) = stack.pop() {
        session.create_remote_dir_all(&remote_dir).await?;

        for entry in fs::read_dir(&local_dir)? {
            let entry = entry?;
            let local_path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let remote_path = join_remote(&remote_dir, &name);
            let file_type = entry.file_type()?;

            if file_type.is_dir() {
                stack.push((local_path, remote_path));
            } else if file_type.is_file() {
                let result = session
                    .upload_file(&local_path, &remote_path, options)
                    .await?;
                bytes_copied = bytes_copied.saturating_add(result.bytes_copied);
            } else if file_type.is_symlink() {
                let metadata = fs::metadata(&local_path)?;
                if metadata.is_file() {
                    let result = session
                        .upload_file(&local_path, &remote_path, options)
                        .await?;
                    bytes_copied = bytes_copied.saturating_add(result.bytes_copied);
                } else if metadata.is_dir() {
                    return Err(Error::new(format!(
                        "symlinked directories are not supported during recursive copy: {}",
                        local_path.display()
                    )));
                } else {
                    return Err(Error::new(format!(
                        "unsupported local symlink target type: {}",
                        local_path.display()
                    )));
                }
            } else {
                return Err(Error::new(format!(
                    "unsupported local file type: {}",
                    local_path.display()
                )));
            }
        }
    }

    Ok(CopyTransferResult {
        bytes_copied,
        resumed_bytes: 0,
    })
}

async fn download_dir_recursive(
    session: &mut dyn SshSession,
    remote_dir: &str,
    local_dir: &Path,
    options: CopyTransferOptions,
) -> Result<CopyTransferResult> {
    let mut stack = vec![(remote_dir.to_string(), local_dir.to_path_buf())];
    let mut bytes_copied = 0_u64;

    while let Some((remote_dir, local_dir)) = stack.pop() {
        fs::create_dir_all(&local_dir)?;

        for entry in session.read_remote_dir(&remote_dir).await? {
            let remote_path = join_remote(&remote_dir, &entry.name);
            let local_path = local_dir.join(&entry.name);

            match entry.file_type {
                RemoteFileType::Directory => {
                    stack.push((remote_path, local_path));
                }
                RemoteFileType::File | RemoteFileType::Symlink => {
                    let result = session
                        .download_file(&remote_path, &local_path, options)
                        .await?;
                    bytes_copied = bytes_copied.saturating_add(result.bytes_copied);
                }
                RemoteFileType::Other => {
                    return Err(Error::new(format!(
                        "unsupported remote file type: {remote_path}"
                    )))
                }
            }
        }
    }

    Ok(CopyTransferResult {
        bytes_copied,
        resumed_bytes: 0,
    })
}

async fn resolve_upload_resume_offset(
    session: &mut dyn SshSession,
    source: &Path,
    destination: &str,
    resume: bool,
) -> Result<u64> {
    if !resume {
        return Ok(0);
    }

    let source_size = fs::metadata(source)?.len();
    let destination_size = match session.remote_file_size(destination).await? {
        Some(size) => size,
        None => return Ok(0),
    };

    if destination_size > source_size {
        return Err(Error::new(
            "cannot resume copy: destination is larger than the source",
        ));
    }

    Ok(destination_size)
}

async fn resolve_download_resume_offset(
    session: &mut dyn SshSession,
    source: &str,
    destination: &Path,
    resume: bool,
) -> Result<u64> {
    if !resume {
        return Ok(0);
    }

    let source_size = session
        .remote_file_size(source)
        .await?
        .ok_or_else(|| Error::new(format!("remote path was not found: {source}")))?;
    let destination_size = match fs::metadata(destination) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(Error::from(error)),
    };

    if destination_size > source_size {
        return Err(Error::new(
            "cannot resume copy: destination is larger than the source",
        ));
    }

    Ok(destination_size)
}

async fn resolve_remote_file_target(
    session: &mut dyn SshSession,
    source: &Path,
    destination: &str,
) -> Result<String> {
    match session.remote_file_type(destination).await? {
        Some(RemoteFileType::Directory) => Ok(join_remote(destination, &local_name(source)?)),
        _ => Ok(destination.to_string()),
    }
}

async fn resolve_remote_directory_target(
    session: &mut dyn SshSession,
    source: &Path,
    destination: &str,
) -> Result<String> {
    match session.remote_file_type(destination).await? {
        Some(RemoteFileType::Directory) => Ok(join_remote(destination, &local_name(source)?)),
        Some(_) => Err(Error::new(
            "cannot copy a directory onto an existing remote file",
        )),
        None => Ok(destination.to_string()),
    }
}

fn resolve_local_file_target(source: &str, destination: &Path) -> Result<PathBuf> {
    if path_is_directory(destination)? {
        Ok(destination.join(remote_name(source)?))
    } else {
        Ok(destination.to_path_buf())
    }
}

fn resolve_local_directory_target(source: &str, destination: &Path) -> Result<PathBuf> {
    if path_is_directory(destination)? {
        Ok(destination.join(remote_name(source)?))
    } else {
        Ok(destination.to_path_buf())
    }
}

fn parse_endpoint(field: &str, value: &str) -> Result<CopyEndpoint> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::new(format!("{field} cannot be empty")));
    }

    match parse_remote_path(trimmed) {
        Some(remote) => Ok(CopyEndpoint::Remote(remote)),
        None => Ok(CopyEndpoint::Local(PathBuf::from(trimmed))),
    }
}

fn parse_remote_path(value: &str) -> Option<RemotePath> {
    let (raw_profile, path) = value.split_once(':')?;
    let (forced_remote, profile) = match raw_profile.strip_prefix('@') {
        Some(profile) => (true, profile.trim()),
        None => (false, raw_profile.trim()),
    };
    if profile.is_empty()
        || !(path.starts_with('/') || path == "~" || path == "~/" || path.starts_with("~/"))
    {
        return None;
    }

    if !forced_remote && is_windows_drive_path(profile, path) {
        return None;
    }

    Some(RemotePath {
        profile: profile.to_string(),
        path: path.to_string(),
    })
}

fn is_windows_drive_path(profile: &str, path: &str) -> bool {
    profile.len() == 1
        && profile
            .chars()
            .next()
            .is_some_and(|drive| drive.is_ascii_alphabetic())
        && path.starts_with('/')
}

fn validate_local_source(path: &Path, recursive: bool) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.is_dir() && !recursive {
        return Err(Error::new("copying directories requires --recursive"));
    }
    Ok(())
}

fn path_is_directory(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::from(error)),
    }
}

fn local_name(path: &Path) -> Result<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| Error::new(format!("path has no file name: {}", path.display())))
}

fn remote_name(path: &str) -> Result<String> {
    path.rsplit('/')
        .find(|segment| !segment.is_empty())
        .map(std::string::ToString::to_string)
        .ok_or_else(|| Error::new(format!("path has no file name: {path}")))
}

fn remote_parent(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }

    trimmed.rfind('/').map(|index| {
        if index == 0 {
            "/".to_string()
        } else {
            trimmed[..index].to_string()
        }
    })
}

fn join_remote(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", base.trim_end_matches('/'), name)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_remote_path, RemotePath};

    #[test]
    fn parse_remote_path_rejects_windows_drive_paths() {
        assert_eq!(parse_remote_path("C:/Users/alice/file.txt"), None);
    }

    #[test]
    fn parse_remote_path_accepts_profile_syntax() {
        assert_eq!(
            parse_remote_path("prod:/tmp/file.txt"),
            Some(RemotePath {
                profile: "prod".into(),
                path: "/tmp/file.txt".into(),
            })
        );
    }

    #[test]
    fn parse_remote_path_accepts_explicit_remote_prefix() {
        assert_eq!(
            parse_remote_path("@p:/tmp/file.txt"),
            Some(RemotePath {
                profile: "p".into(),
                path: "/tmp/file.txt".into(),
            })
        );
    }

    #[test]
    fn parse_remote_path_accepts_escaped_at_profile() {
        assert_eq!(
            parse_remote_path("@@prod:/tmp/file.txt"),
            Some(RemotePath {
                profile: "@prod".into(),
                path: "/tmp/file.txt".into(),
            })
        );
    }
}
