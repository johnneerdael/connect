use std::{
    convert::TryFrom,
    fmt, fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    store::Profile,
    terminal::prompt::Prompt,
};

use super::{
    connect_authenticated_session, establish_transfer_sessions, SshClient, SshConnectionContext,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyCheckpointIdentity {
    pub direction: CopyDirection,
    pub source_path: String,
    pub destination_path: String,
    pub recursive: bool,
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

    match (spec.recursive, source) {
        (false, PlannedCopySource::File { path, size }) => {
            let checkpoint = CopyCheckpointIdentity {
                direction,
                source_path: path.clone(),
                destination_path: endpoint_destination_path(&spec.destination),
                recursive: false,
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
                            direction,
                            source_path: source_path.clone(),
                            destination_path: destination_path.clone(),
                            recursive: true,
                        };

                        if effective_threads > 1 && size > STRIPE_THRESHOLD_BYTES {
                            let chunks = build_chunk_ranges(size, effective_threads);
                            jobs.push(CopyJob::StripedFile {
                                source_path,
                                destination_path,
                                size,
                                chunks,
                                policy: CopyJobPolicy {
                                    resume: CopyResumeStrategy::Disabled,
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
                                    resume: CopyResumeStrategy::Disabled,
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
                            direction,
                            source_path: source_path.clone(),
                            destination_path: destination_path.clone(),
                            recursive: true,
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
    direction: CopyDirection,
    source_path: String,
    destination_path: String,
) -> CopyJob {
    let checkpoint = CopyCheckpointIdentity {
        direction,
        source_path: source_path.clone(),
        destination_path: destination_path.clone(),
        recursive: true,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CopyTransferOptions {
    pub resume_offset: u64,
    pub show_progress: bool,
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
        )
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

    if recursive && resume {
        return Err(Error::new(
            "--resume is only supported for single-file copy operations",
        ));
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
) -> Result<CopySummary> {
    if spec.effective_threads > 1 {
        let mut prepared = prepare_threaded_copy(ssh, spec, profile, context, prompt).await?;
        match &prepared.plan().mode {
            CopyPlanMode::SingleStream => {
                let effective_threads = prepared.effective_threads();
                let warnings = prepared.warnings().to_vec();
                let mut summary = execute_copy_with_retry(prepared.primary_session_mut(), spec).await?;
                summary.effective_threads = effective_threads;
                summary.warnings = warnings;
                Ok(summary)
            }
            CopyPlanMode::StripedFile { .. } | CopyPlanMode::QueuedTree => Err(Error::new(
                "threaded copy executor is not implemented yet; session pool and plan were prepared successfully",
            )),
        }
    } else {
        let mut session = connect_authenticated_session(ssh, profile, context, prompt).await?;
        let mut summary = execute_copy_with_retry(&mut *session, spec).await?;
        summary.effective_threads = 1;
        summary.warnings = Vec::new();
        Ok(summary)
    }
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
    let metadata = fs::metadata(source)?;
    if metadata.is_dir() {
        if !spec.recursive {
            return Err(Error::new("copying directories requires --recursive"));
        }

        let root = resolve_remote_directory_target(session, source, destination).await?;
        let result = upload_dir_recursive(
            session,
            source,
            &root,
            CopyTransferOptions {
                resume_offset: 0,
                show_progress: spec.progress,
            },
        )
        .await?;
        Ok(CopySummary {
            direction: CopyDirection::Upload,
            bytes_copied: result.bytes_copied,
            resumed_bytes: result.resumed_bytes,
            destination: root,
            effective_threads: 1,
            warnings: Vec::new(),
        })
    } else if metadata.is_file() {
        let target = resolve_remote_file_target(session, source, destination).await?;
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
                },
            )
            .await?;
        Ok(CopySummary {
            direction: CopyDirection::Upload,
            bytes_copied: result.bytes_copied,
            resumed_bytes: result.resumed_bytes,
            destination: target,
            effective_threads: 1,
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
    match session.remote_file_type(source).await? {
        Some(RemoteFileType::Directory) => {
            if !spec.recursive {
                return Err(Error::new("copying directories requires --recursive"));
            }

            let root = resolve_local_directory_target(source, destination)?;
            let result = download_dir_recursive(
                session,
                source,
                &root,
                CopyTransferOptions {
                    resume_offset: 0,
                    show_progress: spec.progress,
                },
            )
            .await?;
            Ok(CopySummary {
                direction: CopyDirection::Download,
                bytes_copied: result.bytes_copied,
                resumed_bytes: result.resumed_bytes,
                destination: root.display().to_string(),
                effective_threads: 1,
                warnings: Vec::new(),
            })
        }
        Some(RemoteFileType::File) | Some(RemoteFileType::Symlink) => {
            let target = resolve_local_file_target(source, destination)?;
            let resume_offset =
                resolve_download_resume_offset(session, source, &target, spec.resume).await?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let result = session
                .download_file(
                    source,
                    &target,
                    CopyTransferOptions {
                        resume_offset,
                        show_progress: spec.progress,
                    },
                )
                .await?;
            Ok(CopySummary {
                direction: CopyDirection::Download,
                bytes_copied: result.bytes_copied,
                resumed_bytes: result.resumed_bytes,
                destination: target.display().to_string(),
                effective_threads: 1,
                warnings: Vec::new(),
            })
        }
        Some(RemoteFileType::Other) => Err(Error::new(format!(
            "unsupported remote file type: {source}"
        ))),
        None => Err(Error::new(format!("remote path was not found: {source}"))),
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
    if profile.is_empty() || !path.starts_with('/') {
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
