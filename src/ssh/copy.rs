use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    store::Profile,
    terminal::prompt::Prompt,
};

use super::{auth::connect_authenticated_session, SshClient, SshConnectionContext, SshSession};

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
    pub progress: bool,
}

impl CopySpec {
    pub fn direction(&self) -> CopyDirection {
        match (&self.source, &self.destination) {
            (CopyEndpoint::Local(_), CopyEndpoint::Remote(_)) => CopyDirection::Upload,
            (CopyEndpoint::Remote(_), CopyEndpoint::Local(_)) => CopyDirection::Download,
            _ => unreachable!("copy specs must have exactly one remote endpoint"),
        }
    }

    pub fn remote_profile(&self) -> &str {
        match (&self.source, &self.destination) {
            (CopyEndpoint::Remote(remote), _) | (_, CopyEndpoint::Remote(remote)) => {
                &remote.profile
            }
            _ => unreachable!("copy specs must have exactly one remote endpoint"),
        }
    }
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
}

impl fmt::Display for CopySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "copy {} complete: {} bytes copied ({} resumed) to {}",
            self.direction, self.bytes_copied, self.resumed_bytes, self.destination
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
        progress,
    })
}

pub async fn copy_profile(
    ssh: &dyn SshClient,
    spec: &CopySpec,
    profile: &Profile,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
) -> Result<()> {
    let mut session = connect_authenticated_session(ssh, profile, context, prompt).await?;
    let summary = execute_copy(&mut *session, spec).await?;
    eprintln!("{summary}");
    Ok(())
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
