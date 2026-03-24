use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use assert_cmd::Command;
use connect::ssh::{parse_copy_spec, CopyEndpoint};
use predicates::str::contains;

fn connect_test_bin() -> Command {
    Command::cargo_bin("connect").expect("binary should build")
}

#[test]
fn parse_copy_spec_accepts_upload_from_local_to_remote() {
    let file = temp_file("connect-copy-file", "artifact.txt", "hello");
    let spec = parse_copy_spec(
        file.to_string_lossy().as_ref(),
        "prod:/tmp/file.txt",
        false,
    )
    .unwrap();

    match &spec.source {
        CopyEndpoint::Local(path) => assert_eq!(path, &file),
        other => panic!("expected local source, got {other:?}"),
    }

    match &spec.destination {
        CopyEndpoint::Remote(remote) => {
            assert_eq!(remote.profile, "prod");
            assert_eq!(remote.path, "/tmp/file.txt");
        }
        other => panic!("expected remote destination, got {other:?}"),
    }
}

#[test]
fn parse_copy_spec_accepts_download_from_remote_to_local() {
    let spec = parse_copy_spec("prod:/tmp/file.txt", "./downloads/file.txt", false).unwrap();

    match &spec.source {
        CopyEndpoint::Remote(remote) => {
            assert_eq!(remote.profile, "prod");
            assert_eq!(remote.path, "/tmp/file.txt");
        }
        other => panic!("expected remote source, got {other:?}"),
    }

    match &spec.destination {
        CopyEndpoint::Local(path) => assert_eq!(path, Path::new("./downloads/file.txt")),
        other => panic!("expected local destination, got {other:?}"),
    }
}

#[test]
fn parse_copy_spec_treats_windows_drive_paths_as_local_destination() {
    let spec = parse_copy_spec("prod:/tmp/file.txt", "C:/Users/alice/file.txt", false).unwrap();

    match &spec.source {
        CopyEndpoint::Remote(remote) => {
            assert_eq!(remote.profile, "prod");
            assert_eq!(remote.path, "/tmp/file.txt");
        }
        other => panic!("expected remote source, got {other:?}"),
    }

    match &spec.destination {
        CopyEndpoint::Local(path) => assert_eq!(path, Path::new("C:/Users/alice/file.txt")),
        other => panic!("expected local destination, got {other:?}"),
    }
}

#[test]
fn parse_copy_spec_accepts_explicit_remote_prefix_for_single_letter_profile() {
    let spec = parse_copy_spec("@p:/tmp/file.txt", "./downloads/file.txt", false).unwrap();

    match &spec.source {
        CopyEndpoint::Remote(remote) => {
            assert_eq!(remote.profile, "p");
            assert_eq!(remote.path, "/tmp/file.txt");
        }
        other => panic!("expected remote source, got {other:?}"),
    }

    match &spec.destination {
        CopyEndpoint::Local(path) => assert_eq!(path, Path::new("./downloads/file.txt")),
        other => panic!("expected local destination, got {other:?}"),
    }
}

#[test]
fn parse_copy_spec_rejects_local_to_local_invocations() {
    let error = parse_copy_spec("fixtures/file.txt", "./downloads/file.txt", false).unwrap_err();
    assert_eq!(
        error.to_string(),
        "copy requires exactly one remote path in profile:/path format"
    );
}

#[test]
fn parse_copy_spec_rejects_remote_to_remote_invocations() {
    let error = parse_copy_spec("prod:/tmp/file.txt", "stage:/tmp/file.txt", false).unwrap_err();
    assert_eq!(
        error.to_string(),
        "copy requires exactly one remote path in profile:/path format"
    );
}

#[test]
fn copy_rejects_directory_without_recursive_flag() {
    let tree = temp_dir("connect-copy-tree");
    std::fs::create_dir(tree.join("nested")).unwrap();
    std::fs::write(tree.join("nested/file.txt"), "hello").unwrap();

    connect_test_bin()
        .args([
            "copy",
            tree.to_string_lossy().as_ref(),
            "prod:/tmp/tree",
        ])
        .assert()
        .failure()
        .stderr(contains("--recursive"));

    let _ = std::fs::remove_dir_all(tree);
}

fn temp_dir(prefix: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    let temp_root = std::env::temp_dir();
    let process_id = std::process::id();

    for _ in 0..1024 {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = temp_root.join(format!("{prefix}-{process_id}-{id}"));

        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("failed to create test temp dir {}: {error}", path.display()),
        }
    }

    panic!("failed to allocate a unique temp dir for {prefix}");
}

fn temp_file(prefix: &str, name: &str, contents: &str) -> PathBuf {
    let dir = temp_dir(prefix);
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}
