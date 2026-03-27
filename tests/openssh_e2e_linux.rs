#![cfg(target_os = "linux")]

use std::{
    env, fs,
    future::Future,
    io::{self, Read, Write},
    net::TcpListener,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};

use connect::{
    app::{App, AppPaths, ProfileSecretsInput},
    doctor::checks::{collect_profile_checks, DoctorEnvironment, LocalDoctorCheckStatus},
    error::Error,
    secrets::MemorySecretStore,
    ssh::{parse_copy_spec, ExecSpec, RusshClient, SshClient, SshSession},
    store::{AuthMode, HostKeyRecord, Profile, ProfileInput},
    terminal::prompt::Prompt,
};
use filetime::{set_file_mtime, FileTime};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener as TokioTcpListener,
};

#[tokio::test]
async fn openssh_end_to_end_supports_tofu_exec_agent_auth_and_recursive_copy() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let rejecting_prompt = RejectPrompt;
    let ssh = RusshClient::new();

    let stored_app = harness.app_with_profile("stored", AuthMode::StoredOnly, true);
    let stored_exec = ExecSpec::new(vec!["sh".into(), "-lc".into(), "true".into()], false);
    stored_app
        .exec("stored", &stored_exec, &ssh, &prompt)
        .await
        .expect("first stored-key exec should succeed");

    let host_keys = stored_app.list_host_keys().expect("host keys should load");
    assert_eq!(
        host_keys.len(),
        1,
        "first connect should persist the TOFU host key"
    );
    assert_eq!(host_keys[0].host, "127.0.0.1");
    assert_eq!(host_keys[0].port, harness.port());

    stored_app
        .exec("stored", &stored_exec, &ssh, &rejecting_prompt)
        .await
        .expect("saved host key should avoid re-prompting");

    let pty_exec = ExecSpec::new(
        vec![
            "sh".into(),
            "-lc".into(),
            "test -t 0 && test -t 1 && exit 0 || exit 17".into(),
        ],
        true,
    );
    stored_app
        .exec("stored", &pty_exec, &ssh, &rejecting_prompt)
        .await
        .expect("PTY exec should succeed");

    let quiet_exec = ExecSpec::new(vec!["sh".into(), "-lc".into(), "sleep 31".into()], false);
    tokio::time::timeout(
        Duration::from_secs(45),
        stored_app.exec("stored", &quiet_exec, &ssh, &rejecting_prompt),
    )
    .await
    .expect("quiet exec should not hang")
    .expect("quiet exec should survive keepalives");

    let failing_exec = ExecSpec::new(vec!["sh".into(), "-lc".into(), "exit 23".into()], false);
    let error = stored_app
        .exec("stored", &failing_exec, &ssh, &rejecting_prompt)
        .await
        .expect_err("non-zero exec should propagate the remote exit code");
    assert!(matches!(error, Error::RemoteExitStatus(23)));

    let local_tree = harness.root().join("local-tree");
    let nested_dir = local_tree.join("nested");
    fs::create_dir_all(&nested_dir).expect("nested local directory should exist");
    let local_file = nested_dir.join("hello.txt");
    fs::write(&local_file, "hello over sftp\n").expect("local test file should be written");
    fs::set_permissions(&local_file, fs::Permissions::from_mode(0o640))
        .expect("test file mode should be set");
    let source_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    set_file_mtime(&local_file, FileTime::from_system_time(source_mtime))
        .expect("test file mtime should be set");

    let remote_tree = harness.root().join("remote-tree");
    let upload_spec = parse_copy_spec(
        local_tree.to_str().expect("local path should be utf-8"),
        &format!("stored:{}", remote_tree.display()),
        true,
        false,
        false,
    )
    .expect("upload spec should parse");
    stored_app
        .copy(&upload_spec, &ssh, &rejecting_prompt)
        .await
        .expect("recursive upload should succeed");

    let download_root = harness.root().join("downloaded-tree");
    let download_spec = parse_copy_spec(
        &format!("stored:{}", remote_tree.display()),
        download_root
            .to_str()
            .expect("download path should be utf-8"),
        true,
        false,
        false,
    )
    .expect("download spec should parse");
    stored_app
        .copy(&download_spec, &ssh, &rejecting_prompt)
        .await
        .expect("recursive download should succeed");

    let downloaded_file = download_root.join("nested").join("hello.txt");
    assert_eq!(
        fs::read_to_string(&downloaded_file).expect("downloaded file should exist"),
        "hello over sftp\n"
    );
    assert_eq!(
        fs::metadata(&downloaded_file)
            .expect("downloaded metadata should exist")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(&downloaded_file)
            .expect("downloaded metadata should exist")
            .mtime(),
        fs::metadata(&local_file)
            .expect("source metadata should exist")
            .mtime()
    );

    let agent = SshAgentGuard::start(harness.user_key_path());
    let agent_app = harness.app_with_profile("agent", AuthMode::AgentOnly, false);
    let agent_exec = ExecSpec::new(vec!["sh".into(), "-lc".into(), "true".into()], false);
    agent_app
        .exec("agent", &agent_exec, &ssh, &prompt)
        .await
        .expect("agent-only auth should succeed with ssh-agent");
    drop(agent);
}

#[tokio::test]
async fn openssh_end_to_end_supports_resumable_upload_and_download() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let ssh = RusshClient::new();
    let app = harness.app_with_profile("resume", AuthMode::StoredOnly, true);

    let upload_source = harness.root().join("resume-upload.txt");
    fs::write(&upload_source, "hello-resume-upload").expect("upload source should exist");
    let upload_remote = harness.root().join("remote-resume-upload.txt");
    run_remote_command(
        harness.port(),
        harness.user_key_path(),
        &format!(
            "printf %s {} > {}",
            shell_single_quote("hello-"),
            shell_single_quote(&upload_remote.display().to_string())
        ),
    )
    .expect("remote partial upload file should be created");

    let upload_spec = parse_copy_spec(
        upload_source.to_str().expect("upload path should be utf-8"),
        &format!("resume:{}", upload_remote.display()),
        false,
        true,
        false,
    )
    .expect("resumable upload spec should parse");
    app.copy(&upload_spec, &ssh, &prompt)
        .await
        .expect("resumable upload should succeed");
    assert_eq!(
        fs::read_to_string(&upload_remote).expect("remote upload file should be readable"),
        "hello-resume-upload"
    );

    let download_remote = harness.root().join("remote-resume-download.txt");
    run_remote_command(
        harness.port(),
        harness.user_key_path(),
        &format!(
            "printf %s {} > {}",
            shell_single_quote("download-resume"),
            shell_single_quote(&download_remote.display().to_string())
        ),
    )
    .expect("remote download source should be created");
    let download_local = harness.root().join("resume-download.txt");
    fs::write(&download_local, "download-").expect("local partial download should exist");

    let download_spec = parse_copy_spec(
        &format!("resume:{}", download_remote.display()),
        download_local
            .to_str()
            .expect("download path should be utf-8"),
        false,
        true,
        false,
    )
    .expect("resumable download spec should parse");
    app.copy(&download_spec, &ssh, &prompt)
        .await
        .expect("resumable download should succeed");
    assert_eq!(
        fs::read_to_string(&download_local).expect("downloaded file should exist"),
        "download-resume"
    );
}

#[tokio::test]
async fn openssh_parallel_copy_degrades_when_server_session_budget_is_limited() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let ssh = LimitedConnectSshClient::new(RusshClient::new(), 2);
    let app = harness.app_with_profile("degraded", AuthMode::StoredOnly, true);

    let source = harness.root().join("parallel-degrade.txt");
    fs::write(&source, "hello-parallel-degrade").expect("source file should exist");
    let mut spec = parse_copy_spec(
        source.to_str().expect("source path should be utf-8"),
        &format!("degraded:{}/parallel-degrade.txt", harness.root().display()),
        false,
        false,
        false,
    )
    .expect("copy spec should parse");
    spec.effective_threads = 4;

    let summary = app
        .copy(&spec, &ssh, &prompt)
        .await
        .expect("copy should degrade rather than fail");

    assert_eq!(summary.effective_threads, 2);
    assert!(summary
        .warnings
        .iter()
        .any(|warning| warning.contains("degraded")));
}

#[tokio::test]
async fn openssh_threaded_upload_resumes_from_checkpoint_after_interruption() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let app = harness.app_with_profile("threaded-upload-resume", AuthMode::StoredOnly, true);
    let source = harness.root().join("threaded-upload-source.bin");
    let remote = harness.root().join("threaded-upload-remote.bin");
    write_pattern_file(&source, 96 * 1024 * 1024);
    fs::set_permissions(&source, fs::Permissions::from_mode(0o640))
        .expect("source mode should be set");
    let source_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_100_000);
    set_file_mtime(&source, FileTime::from_system_time(source_mtime))
        .expect("source mtime should be set");

    let failing_ssh = FaultInjectingSshClient::new(
        RusshClient::new(),
        RangeFailureSpec::fatal_upload_once(remote.display().to_string()),
    );
    let mut first_spec = parse_copy_spec(
        source.to_str().expect("source path should be utf-8"),
        &format!("threaded-upload-resume:{}", remote.display()),
        false,
        false,
        false,
    )
    .expect("copy spec should parse");
    first_spec.effective_threads = 4;

    let error = app
        .copy(&first_spec, &failing_ssh, &prompt)
        .await
        .expect_err("first threaded upload should fail");
    assert!(error
        .to_string()
        .contains("injected fatal threaded upload failure"));
    assert!(
        harness
            .app_checkpoint_dir("threaded-upload-resume")
            .read_dir()
            .is_ok(),
        "checkpoint directory should exist after interrupted threaded upload"
    );

    let mut resume_spec = parse_copy_spec(
        source.to_str().expect("source path should be utf-8"),
        &format!("threaded-upload-resume:{}", remote.display()),
        false,
        true,
        false,
    )
    .expect("resume copy spec should parse");
    resume_spec.effective_threads = 4;

    let summary = app
        .copy(&resume_spec, &RusshClient::new(), &prompt)
        .await
        .expect("threaded upload resume should succeed");

    assert!(summary.resumed_bytes > 0);
    assert_files_equal(&source, &remote);
    assert_eq!(
        fs::metadata(&remote)
            .expect("remote metadata should exist")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(&remote)
            .expect("remote metadata should exist")
            .mtime(),
        fs::metadata(&source)
            .expect("source metadata should exist")
            .mtime()
    );
    assert_checkpoint_dir_empty(harness.app_checkpoint_dir("threaded-upload-resume"));
}

#[tokio::test]
async fn openssh_threaded_download_resumes_from_checkpoint_after_interruption() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let app = harness.app_with_profile("threaded-download-resume", AuthMode::StoredOnly, true);
    let remote = harness.root().join("threaded-download-source.bin");
    let local = harness.root().join("threaded-download-local.bin");
    write_pattern_file(&remote, 96 * 1024 * 1024);
    fs::set_permissions(&remote, fs::Permissions::from_mode(0o600))
        .expect("remote mode should be set");
    let remote_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_200_000);
    set_file_mtime(&remote, FileTime::from_system_time(remote_mtime))
        .expect("remote mtime should be set");

    let failing_ssh = FaultInjectingSshClient::new(
        RusshClient::new(),
        RangeFailureSpec::fatal_download_once(remote.display().to_string()),
    );
    let mut first_spec = parse_copy_spec(
        &format!("threaded-download-resume:{}", remote.display()),
        local.to_str().expect("local path should be utf-8"),
        false,
        false,
        false,
    )
    .expect("copy spec should parse");
    first_spec.effective_threads = 4;

    let error = app
        .copy(&first_spec, &failing_ssh, &prompt)
        .await
        .expect_err("first threaded download should fail");
    assert!(error
        .to_string()
        .contains("injected fatal threaded download failure"));
    assert!(local.exists(), "partial local file should be preserved");

    let mut resume_spec = parse_copy_spec(
        &format!("threaded-download-resume:{}", remote.display()),
        local.to_str().expect("local path should be utf-8"),
        false,
        true,
        false,
    )
    .expect("resume copy spec should parse");
    resume_spec.effective_threads = 4;

    let summary = app
        .copy(&resume_spec, &RusshClient::new(), &prompt)
        .await
        .expect("threaded download resume should succeed");

    assert!(summary.resumed_bytes > 0);
    assert_files_equal(&remote, &local);
    assert_eq!(
        fs::metadata(&local)
            .expect("local metadata should exist")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&local)
            .expect("local metadata should exist")
            .mtime(),
        fs::metadata(&remote)
            .expect("remote metadata should exist")
            .mtime()
    );
    assert_checkpoint_dir_empty(harness.app_checkpoint_dir("threaded-download-resume"));
}

#[tokio::test]
async fn openssh_threaded_upload_retries_transient_chunk_failures() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let app = harness.app_with_profile("threaded-upload-retry", AuthMode::StoredOnly, true);
    let source = harness.root().join("threaded-upload-retry-source.bin");
    let remote = harness.root().join("threaded-upload-retry-remote.bin");
    write_pattern_file(&source, 96 * 1024 * 1024);

    let retrying_ssh = FaultInjectingSshClient::new(
        RusshClient::new(),
        RangeFailureSpec::transient_upload_once(remote.display().to_string()),
    );
    let mut spec = parse_copy_spec(
        source.to_str().expect("source path should be utf-8"),
        &format!("threaded-upload-retry:{}", remote.display()),
        false,
        false,
        false,
    )
    .expect("copy spec should parse");
    spec.effective_threads = 4;
    spec.retry = true;

    let summary = app
        .copy(&spec, &retrying_ssh, &prompt)
        .await
        .expect("threaded upload retry should succeed");

    assert_eq!(summary.bytes_copied, 96 * 1024 * 1024);
    assert_files_equal(&source, &remote);
    assert_checkpoint_dir_empty(harness.app_checkpoint_dir("threaded-upload-retry"));
}

#[tokio::test]
async fn openssh_threaded_recursive_upload_and_download_succeeds() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let ssh = RusshClient::new();
    let app = harness.app_with_profile("threaded-recursive", AuthMode::StoredOnly, true);

    let source_root = harness.root().join("threaded-recursive-source");
    let nested = source_root.join("nested");
    fs::create_dir_all(&nested).expect("nested source directory should exist");
    fs::write(source_root.join("small.txt"), "small threaded payload\n")
        .expect("small source file should exist");
    write_pattern_file(&source_root.join("large.bin"), 96 * 1024 * 1024);
    fs::write(nested.join("child.txt"), "nested threaded payload\n")
        .expect("nested source file should exist");

    let remote_root = harness.root().join("threaded-recursive-remote");
    let mut upload_spec = parse_copy_spec(
        source_root.to_str().expect("source root should be utf-8"),
        &format!("threaded-recursive:{}", remote_root.display()),
        true,
        false,
        false,
    )
    .expect("recursive threaded upload spec should parse");
    upload_spec.effective_threads = 4;

    app.copy(&upload_spec, &ssh, &prompt)
        .await
        .expect("threaded recursive upload should succeed");

    let download_root = harness.root().join("threaded-recursive-download");
    let mut download_spec = parse_copy_spec(
        &format!("threaded-recursive:{}", remote_root.display()),
        download_root
            .to_str()
            .expect("download root should be utf-8"),
        true,
        false,
        false,
    )
    .expect("recursive threaded download spec should parse");
    download_spec.effective_threads = 4;

    app.copy(&download_spec, &ssh, &prompt)
        .await
        .expect("threaded recursive download should succeed");

    assert_eq!(
        fs::read_to_string(download_root.join("small.txt")).expect("small file should download"),
        "small threaded payload\n"
    );
    assert_eq!(
        fs::read_to_string(download_root.join("nested").join("child.txt"))
            .expect("nested file should download"),
        "nested threaded payload\n"
    );
    assert_files_equal(
        &source_root.join("large.bin"),
        &download_root.join("large.bin"),
    );
}

#[tokio::test]
async fn openssh_threaded_recursive_upload_resumes_from_checkpoint_after_interruption() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let app = harness.app_with_profile("threaded-recursive-resume", AuthMode::StoredOnly, true);

    let source_root = harness.root().join("threaded-recursive-resume-source");
    fs::create_dir_all(&source_root).expect("source root should exist");
    fs::write(source_root.join("small.txt"), "resume tree payload\n")
        .expect("small source file should exist");
    write_pattern_file(&source_root.join("large.bin"), 96 * 1024 * 1024);

    let remote_root = harness.root().join("threaded-recursive-resume-remote");
    let failing_ssh = FaultInjectingSshClient::new(
        RusshClient::new(),
        RangeFailureSpec::fatal_upload_once(remote_root.join("large.bin").display().to_string()),
    );
    let mut first_spec = parse_copy_spec(
        source_root.to_str().expect("source root should be utf-8"),
        &format!("threaded-recursive-resume:{}", remote_root.display()),
        true,
        false,
        false,
    )
    .expect("first recursive threaded upload spec should parse");
    first_spec.effective_threads = 4;

    let error = app
        .copy(&first_spec, &failing_ssh, &prompt)
        .await
        .expect_err("first recursive threaded upload should fail");
    assert!(error
        .to_string()
        .contains("injected fatal threaded upload failure"));
    assert!(
        harness
            .app_checkpoint_dir("threaded-recursive-resume")
            .read_dir()
            .is_ok(),
        "checkpoint directory should exist after interrupted recursive threaded upload"
    );

    let mut resume_spec = parse_copy_spec(
        source_root.to_str().expect("source root should be utf-8"),
        &format!("threaded-recursive-resume:{}", remote_root.display()),
        true,
        true,
        false,
    )
    .expect("resume recursive threaded upload spec should parse");
    resume_spec.effective_threads = 4;

    let summary = app
        .copy(&resume_spec, &RusshClient::new(), &prompt)
        .await
        .expect("recursive threaded upload resume should succeed");

    assert!(summary.resumed_bytes > 0);
    assert_eq!(
        fs::read_to_string(&remote_root.join("small.txt")).expect("small remote file should exist"),
        "resume tree payload\n"
    );
    assert_files_equal(
        &source_root.join("large.bin"),
        &remote_root.join("large.bin"),
    );
    assert_checkpoint_dir_empty(harness.app_checkpoint_dir("threaded-recursive-resume"));
}

#[tokio::test]
async fn openssh_threaded_recursive_upload_retries_transient_failures() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let app = harness.app_with_profile("threaded-recursive-retry", AuthMode::StoredOnly, true);

    let source_root = harness.root().join("threaded-recursive-retry-source");
    fs::create_dir_all(&source_root).expect("source root should exist");
    fs::write(source_root.join("small.txt"), "retry tree payload\n")
        .expect("small source file should exist");
    write_pattern_file(&source_root.join("large.bin"), 96 * 1024 * 1024);

    let remote_root = harness.root().join("threaded-recursive-retry-remote");
    let retrying_ssh = FaultInjectingSshClient::new(
        RusshClient::new(),
        RangeFailureSpec::transient_upload_once(
            remote_root.join("large.bin").display().to_string(),
        ),
    );
    let mut spec = parse_copy_spec(
        source_root.to_str().expect("source root should be utf-8"),
        &format!("threaded-recursive-retry:{}", remote_root.display()),
        true,
        false,
        false,
    )
    .expect("recursive threaded retry spec should parse");
    spec.effective_threads = 4;
    spec.retry = true;

    let summary = app
        .copy(&spec, &retrying_ssh, &prompt)
        .await
        .expect("recursive threaded retry should succeed");

    assert_eq!(
        summary.bytes_copied,
        u64::try_from(fs::metadata(source_root.join("small.txt")).unwrap().len()).unwrap()
            + 96 * 1024 * 1024
    );
    assert_eq!(
        fs::read_to_string(&remote_root.join("small.txt")).expect("small remote file should exist"),
        "retry tree payload\n"
    );
    assert_files_equal(
        &source_root.join("large.bin"),
        &remote_root.join("large.bin"),
    );
    assert_checkpoint_dir_empty(harness.app_checkpoint_dir("threaded-recursive-retry"));
}

#[tokio::test]
async fn openssh_end_to_end_supports_saved_local_tcp_forward_run() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let ssh = RusshClient::new();
    let app = harness.app_with_profile("forward", AuthMode::StoredOnly, true);
    let remote_port = allocate_port();
    let local_port = allocate_port();

    app.save_forward(
        connect::forward::spec::ForwardSpec::parse_local(&format!(
            "127.0.0.1:{local_port}:127.0.0.1:{remote_port}"
        ))
        .expect("forward spec should parse")
        .into_definition("forward", "echo", None),
    )
    .expect("forward should save");

    let remote_listener = TokioTcpListener::bind(("127.0.0.1", remote_port))
        .await
        .expect("remote listener should bind");
    let remote_task = tokio::spawn(async move {
        let (mut socket, _) = remote_listener
            .accept()
            .await
            .expect("remote listener should accept");
        let mut request = [0_u8; 4];
        socket
            .read_exact(&mut request)
            .await
            .expect("request should arrive through SSH");
        assert_eq!(&request, b"ping");
        socket
            .write_all(b"pong")
            .await
            .expect("response should travel through SSH");
    });

    run_saved_forward_until(&app, &ssh, &prompt, "forward", "echo", async move {
        wait_for_tokio_port(local_port).await;
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", local_port))
            .await
            .expect("local forwarded listener should accept");
        client
            .write_all(b"ping")
            .await
            .expect("request should be sent");
        let mut response = [0_u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("response should be readable");
        assert_eq!(&response, b"pong");
    })
    .await
    .unwrap();
    remote_task.await.unwrap();
}

#[tokio::test]
async fn openssh_end_to_end_supports_saved_socks5_forward_run() {
    let harness = OpenSshHarness::start();
    let prompt = AcceptPrompt;
    let ssh = RusshClient::new();
    let app = harness.app_with_profile("socks-forward", AuthMode::StoredOnly, true);
    let remote_port = allocate_port();
    let local_port = allocate_port();

    app.save_forward(
        connect::forward::spec::ForwardSpec::parse_socks(&format!("127.0.0.1:{local_port}"))
            .expect("SOCKS forward spec should parse")
            .into_definition("socks-forward", "proxy", None),
    )
    .expect("SOCKS forward should save");

    let remote_listener = TokioTcpListener::bind(("127.0.0.1", remote_port))
        .await
        .expect("remote listener should bind");
    let remote_task = tokio::spawn(async move {
        let (mut socket, _) = remote_listener
            .accept()
            .await
            .expect("remote listener should accept");
        let mut request = [0_u8; 4];
        socket
            .read_exact(&mut request)
            .await
            .expect("request should arrive through SOCKS over SSH");
        assert_eq!(&request, b"ping");
        socket
            .write_all(b"pong")
            .await
            .expect("response should travel through SOCKS over SSH");
    });

    run_saved_forward_until(&app, &ssh, &prompt, "socks-forward", "proxy", async move {
        wait_for_tokio_port(local_port).await;
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", local_port))
            .await
            .expect("local SOCKS listener should accept");
        socks5_greet(&mut client).await;
        socks5_connect_ipv4(&mut client, [127, 0, 0, 1], remote_port).await;
        client
            .write_all(b"ping")
            .await
            .expect("request should be sent through SOCKS");
        let mut response = [0_u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("response should be readable through SOCKS");
        assert_eq!(&response, b"pong");
    })
    .await
    .unwrap();
    remote_task.await.unwrap();
}

struct PassingDoctorEnvironment;

impl DoctorEnvironment for PassingDoctorEnvironment {
    fn resolve_app_paths(&self) -> connect::error::Result<connect::app::AppPaths> {
        Ok(connect::app::AppPaths {
            config_dir: PathBuf::from("/tmp/connect-doctor-config"),
            data_dir: PathBuf::from("/tmp/connect-doctor-data"),
            database_path: PathBuf::from("/tmp/connect-doctor-data/connect.db"),
        })
    }

    fn check_database(&self, _paths: &connect::app::AppPaths) -> connect::error::Result<()> {
        Ok(())
    }

    fn initialize_secret_backend(&self) -> connect::error::Result<()> {
        Ok(())
    }

    fn ssh_agent_available(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn doctor_profile_succeeds_for_a_live_ssh_profile() {
    let harness = OpenSshHarness::start();
    let app = harness.app_with_profile("doctor", AuthMode::StoredOnly, true);
    let env = PassingDoctorEnvironment;
    let ssh = RusshClient::new();

    let report = collect_profile_checks(&env, &app, "doctor", &ssh).await;

    assert!(report.is_success(), "{report:?}");
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "hostname resolution"
            && check.status == LocalDoctorCheckStatus::Pass));
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "TCP reachability"
            && check.status == LocalDoctorCheckStatus::Pass));
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "SSH handshake"
                && check.status == LocalDoctorCheckStatus::Pass)
    );
}

#[tokio::test]
async fn doctor_profile_rejects_saved_host_key_mismatch() {
    let harness = OpenSshHarness::start();
    let app = harness.app_with_profile("doctor-mismatch", AuthMode::StoredOnly, true);
    let env = PassingDoctorEnvironment;
    app.save_host_key(
        "127.0.0.1",
        harness.port(),
        "ssh-ed25519",
        "wrong-fingerprint",
        "wrong-public-key",
    )
    .expect("host key should be saved");
    let ssh = RusshClient::new();

    let report = collect_profile_checks(&env, &app, "doctor-mismatch", &ssh).await;

    assert!(!report.is_success());
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "host key verification"
            && check.status == LocalDoctorCheckStatus::Fail));
}

#[tokio::test]
async fn doctor_profile_rejects_an_unusable_auth_mode() {
    let _guard = EnvVarGuard::set("SSH_AUTH_SOCK", "/tmp/connect-doctor-missing-agent.sock");
    let harness = OpenSshHarness::start();
    let app = harness.app_with_profile("doctor-agent", AuthMode::AgentOnly, false);
    let env = PassingDoctorEnvironment;
    let ssh = RusshClient::new();

    let report = collect_profile_checks(&env, &app, "doctor-agent", &ssh).await;

    assert!(!report.is_success());
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "SSH auth usability"
            && check.status == LocalDoctorCheckStatus::Fail));
}

struct OpenSshHarness {
    root: TempDir,
    port: u16,
    username: String,
    user_key_path: PathBuf,
    private_key_contents: String,
    sshd: Child,
}

impl OpenSshHarness {
    fn start() -> Self {
        let root = TempDir::new().expect("tempdir should be created");
        let sshd_root = root.path().join("sshd");
        let home_root = root.path().join("home");
        fs::create_dir_all(&sshd_root).expect("sshd root should exist");
        fs::create_dir_all(home_root.join(".ssh")).expect("ssh home should exist");

        let host_key = sshd_root.join("ssh_host_ed25519_key");
        let user_key = root.path().join("id_ed25519");
        run_command(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&host_key),
        )
        .expect("host key should be generated");
        run_command(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&user_key),
        )
        .expect("user key should be generated");

        let authorized_keys = home_root.join(".ssh").join("authorized_keys");
        fs::copy(user_key.with_extension("pub"), &authorized_keys)
            .expect("authorized keys should be populated");

        let username = current_username();
        let port = allocate_port();
        let log_path = root.path().join("sshd.log");
        let config_path = root.path().join("sshd_config");
        fs::write(
            &config_path,
            format!(
                "\
Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {pid_file}
AuthorizedKeysFile {authorized_keys}
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
StrictModes no
AllowUsers {username}
LogLevel VERBOSE
PrintMotd no
UseDNS no
Subsystem sftp internal-sftp
",
                port = port,
                host_key = host_key.display(),
                pid_file = root.path().join("sshd.pid").display(),
                authorized_keys = authorized_keys.display(),
                username = username,
            ),
        )
        .expect("sshd config should be written");

        run_command(
            Command::new("/usr/sbin/sshd")
                .args(["-t", "-f"])
                .arg(&config_path),
        )
        .unwrap_or_else(|error| {
            panic!(
                "sshd config validation failed: {error}\n{}",
                read_optional(&log_path)
            )
        });

        let sshd = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-f")
            .arg(&config_path)
            .arg("-E")
            .arg(&log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sshd should start");

        wait_for_port(port, &log_path);

        Self {
            private_key_contents: fs::read_to_string(&user_key)
                .expect("private key should be readable"),
            root,
            port,
            username,
            user_key_path: user_key,
            sshd,
        }
    }

    fn app_with_profile(&self, name: &str, auth_mode: AuthMode, include_private_key: bool) -> App {
        let app_root = self.root.path().join(format!("app-{name}"));
        let app = App::new(
            AppPaths::from_root(&app_root),
            Arc::new(MemorySecretStore::default()),
        )
        .expect("app should initialize");
        let profile = ProfileInput::new(name, "127.0.0.1", &self.username)
            .with_port(self.port)
            .with_auth_mode(auth_mode);
        let secrets = if include_private_key {
            ProfileSecretsInput {
                private_key: Some(self.private_key_contents.clone()),
                ..Default::default()
            }
        } else {
            ProfileSecretsInput::default()
        };
        app.save_profile_with_secrets(profile, secrets)
            .expect("profile should be saved");
        app
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn user_key_path(&self) -> &Path {
        &self.user_key_path
    }

    fn app_checkpoint_dir(&self, name: &str) -> PathBuf {
        let payload = format!(
            "v1\0{}\0{}\0{}\0{}",
            name, "127.0.0.1", self.port, self.username
        );
        self.root
            .path()
            .join(format!("app-{name}"))
            .join("data")
            .join("copy-checkpoints")
            .join(format!("{:016x}", fnv1a64(payload.as_bytes())))
    }
}

#[derive(Clone)]
struct LimitedConnectSshClient {
    inner: RusshClient,
    limit: usize,
    attempts: Arc<Mutex<usize>>,
}

#[derive(Clone)]
struct FaultInjectingSshClient {
    inner: RusshClient,
    failure: Arc<Mutex<RangeFailureSpec>>,
}

impl FaultInjectingSshClient {
    fn new(inner: RusshClient, failure: RangeFailureSpec) -> Self {
        Self {
            inner,
            failure: Arc::new(Mutex::new(failure)),
        }
    }
}

impl SshClient for FaultInjectingSshClient {
    fn connect<'a>(
        &'a self,
        profile: &'a Profile,
        expected_host_key: Option<&'a HostKeyRecord>,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<Box<dyn SshSession + Send>>> + Send + 'a>>
    {
        let failure = Arc::clone(&self.failure);
        Box::pin(async move {
            let session = self.inner.connect(profile, expected_host_key).await?;
            Ok(Box::new(FaultInjectingSshSession {
                inner: session,
                failure,
            }) as Box<dyn SshSession + Send>)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFailureKind {
    Fatal,
    Transient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFailureDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone)]
struct RangeFailureSpec {
    direction: InjectedFailureDirection,
    target_path: String,
    kind: InjectedFailureKind,
    remaining_failures: usize,
}

impl RangeFailureSpec {
    fn fatal_upload_once(target_path: String) -> Self {
        Self {
            direction: InjectedFailureDirection::Upload,
            target_path,
            kind: InjectedFailureKind::Fatal,
            remaining_failures: 1,
        }
    }

    fn fatal_download_once(target_path: String) -> Self {
        Self {
            direction: InjectedFailureDirection::Download,
            target_path,
            kind: InjectedFailureKind::Fatal,
            remaining_failures: 1,
        }
    }

    fn transient_upload_once(target_path: String) -> Self {
        Self {
            direction: InjectedFailureDirection::Upload,
            target_path,
            kind: InjectedFailureKind::Transient,
            remaining_failures: 1,
        }
    }

    fn should_fail(
        &mut self,
        direction: InjectedFailureDirection,
        target_path: &str,
    ) -> Option<InjectedFailureKind> {
        if self.remaining_failures == 0
            || self.direction != direction
            || self.target_path != target_path
        {
            return None;
        }

        self.remaining_failures = self.remaining_failures.saturating_sub(1);
        Some(self.kind)
    }
}

struct FaultInjectingSshSession {
    inner: Box<dyn SshSession + Send>,
    failure: Arc<Mutex<RangeFailureSpec>>,
}

impl FaultInjectingSshSession {
    fn maybe_fail(
        &self,
        direction: InjectedFailureDirection,
        target_path: &str,
    ) -> Option<InjectedFailureKind> {
        self.failure
            .lock()
            .expect("failure spec should lock")
            .should_fail(direction, target_path)
    }
}

impl SshSession for FaultInjectingSshSession {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<
        Box<dyn Future<Output = connect::error::Result<connect::ssh::ObservedHostKey>> + Send + 'a>,
    > {
        self.inner.observe_host_key()
    }

    fn authenticate_agent<'a>(
        &'a mut self,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        self.inner.authenticate_agent(username)
    }

    fn authenticate_public_key<'a>(
        &'a mut self,
        username: &'a str,
        private_key: &'a str,
        passphrase: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        self.inner
            .authenticate_public_key(username, private_key, passphrase)
    }

    fn authenticate_password<'a>(
        &'a mut self,
        username: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        self.inner.authenticate_password(username, password)
    }

    fn open_shell<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u32>> + Send + 'a>> {
        self.inner.open_shell()
    }

    fn execute_command<'a>(
        &'a mut self,
        spec: &'a ExecSpec,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u32>> + Send + 'a>> {
        self.inner.execute_command(spec)
    }

    fn open_direct_tcpip<'a>(
        &'a mut self,
        target_host: &'a str,
        target_port: u16,
        originator_host: &'a str,
        originator_port: u16,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = connect::error::Result<
                        Box<dyn connect::ssh::DirectTcpipStream + Send + Unpin + 'static>,
                    >,
                > + Send
                + 'a,
        >,
    > {
        self.inner
            .open_direct_tcpip(target_host, target_port, originator_host, originator_port)
    }

    fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    fn disconnect<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        self.inner.disconnect()
    }

    fn resolve_remote_path<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<String>> + Send + 'a>> {
        self.inner.resolve_remote_path(path)
    }

    fn finish_progress_line<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        self.inner.finish_progress_line()
    }

    fn supports_parallel_random_access<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        self.inner.supports_parallel_random_access()
    }

    fn remote_file_type<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<Option<connect::ssh::RemoteFileType>>>
                + Send
                + 'a,
        >,
    > {
        self.inner.remote_file_type(path)
    }

    fn remote_file_metadata<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<Option<connect::ssh::CopyFileMetadata>>>
                + Send
                + 'a,
        >,
    > {
        self.inner.remote_file_metadata(path)
    }

    fn read_remote_dir<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<Vec<connect::ssh::RemoteDirectoryEntry>>>
                + Send
                + 'a,
        >,
    > {
        self.inner.read_remote_dir(path)
    }

    fn create_remote_dir_all<'a>(
        &'a mut self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        self.inner.create_remote_dir_all(path)
    }

    fn prepare_remote_file_destination<'a>(
        &'a mut self,
        path: &'a str,
        truncate: bool,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        self.inner.prepare_remote_file_destination(path, truncate)
    }

    fn upload_file<'a>(
        &'a mut self,
        local_path: &'a Path,
        remote_path: &'a str,
        options: connect::ssh::CopyTransferOptions,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<connect::ssh::CopyTransferResult>>
                + Send
                + 'a,
        >,
    > {
        self.inner.upload_file(local_path, remote_path, options)
    }

    fn download_file<'a>(
        &'a mut self,
        remote_path: &'a str,
        local_path: &'a Path,
        options: connect::ssh::CopyTransferOptions,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<connect::ssh::CopyTransferResult>>
                + Send
                + 'a,
        >,
    > {
        self.inner.download_file(remote_path, local_path, options)
    }

    fn upload_file_range<'a>(
        &'a mut self,
        local_path: &'a Path,
        remote_path: &'a str,
        range: connect::ssh::ChunkRange,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u64>> + Send + 'a>> {
        if let Some(kind) = self.maybe_fail(InjectedFailureDirection::Upload, remote_path) {
            return Box::pin(async move {
                match kind {
                    InjectedFailureKind::Fatal => Err(Error::new(format!(
                        "injected fatal threaded upload failure for range {}..{}",
                        range.start, range.end
                    ))),
                    InjectedFailureKind::Transient => Err(Error::new(format!(
                        "transient injected threaded upload failure for range {}..{}",
                        range.start, range.end
                    ))),
                }
            });
        }

        self.inner.upload_file_range(local_path, remote_path, range)
    }

    fn download_file_range<'a>(
        &'a mut self,
        remote_path: &'a str,
        local_path: &'a Path,
        range: connect::ssh::ChunkRange,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<u64>> + Send + 'a>> {
        if let Some(kind) = self.maybe_fail(InjectedFailureDirection::Download, remote_path) {
            return Box::pin(async move {
                match kind {
                    InjectedFailureKind::Fatal => Err(Error::new(format!(
                        "injected fatal threaded download failure for range {}..{}",
                        range.start, range.end
                    ))),
                    InjectedFailureKind::Transient => Err(Error::new(format!(
                        "transient injected threaded download failure for range {}..{}",
                        range.start, range.end
                    ))),
                }
            });
        }

        self.inner
            .download_file_range(remote_path, local_path, range)
    }

    fn apply_uploaded_file_metadata<'a>(
        &'a mut self,
        local_path: &'a Path,
        remote_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        self.inner
            .apply_uploaded_file_metadata(local_path, remote_path)
    }

    fn apply_downloaded_file_metadata<'a>(
        &'a mut self,
        remote_path: &'a str,
        local_path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<()>> + Send + 'a>> {
        self.inner
            .apply_downloaded_file_metadata(remote_path, local_path)
    }
}

impl LimitedConnectSshClient {
    fn new(inner: RusshClient, limit: usize) -> Self {
        Self {
            inner,
            limit,
            attempts: Arc::new(Mutex::new(0)),
        }
    }
}

impl SshClient for LimitedConnectSshClient {
    fn connect<'a>(
        &'a self,
        profile: &'a Profile,
        expected_host_key: Option<&'a HostKeyRecord>,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<Box<dyn SshSession + Send>>> + Send + 'a>>
    {
        let attempt = {
            let mut attempts = self.attempts.lock().expect("attempt counter should lock");
            *attempts += 1;
            *attempts
        };

        if attempt > self.limit {
            return Box::pin(async {
                Err(Error::new(
                    "ssh error: too many concurrent sessions (controlled test limit)",
                ))
            });
        }

        self.inner.connect(profile, expected_host_key)
    }
}

impl Drop for OpenSshHarness {
    fn drop(&mut self) {
        let _ = self.sshd.kill();
        let _ = self.sshd.wait();
    }
}

struct SshAgentGuard {
    child_pid: String,
    previous_sock: Option<std::ffi::OsString>,
    previous_pid: Option<std::ffi::OsString>,
}

impl SshAgentGuard {
    fn start(key_path: &Path) -> Self {
        let output = Command::new("ssh-agent")
            .arg("-s")
            .output()
            .expect("ssh-agent should start");
        if !output.status.success() {
            panic!(
                "ssh-agent failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8(output.stdout).expect("ssh-agent output should be utf-8");
        let sock = parse_agent_value(&stdout, "SSH_AUTH_SOCK");
        let pid = parse_agent_value(&stdout, "SSH_AGENT_PID");

        let previous_sock = env::var_os("SSH_AUTH_SOCK");
        let previous_pid = env::var_os("SSH_AGENT_PID");
        env::set_var("SSH_AUTH_SOCK", &sock);
        env::set_var("SSH_AGENT_PID", &pid);

        run_command(Command::new("ssh-add").arg(key_path)).expect("ssh-add should load the key");

        Self {
            child_pid: pid,
            previous_sock,
            previous_pid,
        }
    }
}

struct EnvVarGuard {
    key: &'static str,
    original: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

impl Drop for SshAgentGuard {
    fn drop(&mut self) {
        let _ = Command::new("ssh-agent")
            .arg("-k")
            .env("SSH_AGENT_PID", &self.child_pid)
            .env(
                "SSH_AUTH_SOCK",
                env::var("SSH_AUTH_SOCK").unwrap_or_default(),
            )
            .output();

        match &self.previous_sock {
            Some(value) => env::set_var("SSH_AUTH_SOCK", value),
            None => env::remove_var("SSH_AUTH_SOCK"),
        }

        match &self.previous_pid {
            Some(value) => env::set_var("SSH_AGENT_PID", value),
            None => env::remove_var("SSH_AGENT_PID"),
        }
    }
}

struct AcceptPrompt;

impl Prompt for AcceptPrompt {
    fn prompt(
        &self,
        _key: &str,
        _message: &str,
        _default: Option<&str>,
    ) -> connect::error::Result<String> {
        Err(Error::new(
            "text prompts are not expected in OpenSSH e2e tests",
        ))
    }

    fn prompt_secret(&self, _key: &str, _message: &str) -> connect::error::Result<Option<String>> {
        Err(Error::new(
            "secret prompts are not expected in OpenSSH e2e tests",
        ))
    }

    fn confirm(&self, _key: &str, _message: &str, _default: bool) -> connect::error::Result<bool> {
        Ok(true)
    }
}

struct RejectPrompt;

impl Prompt for RejectPrompt {
    fn prompt(
        &self,
        _key: &str,
        _message: &str,
        _default: Option<&str>,
    ) -> connect::error::Result<String> {
        Err(Error::new(
            "text prompts are not expected in OpenSSH e2e tests",
        ))
    }

    fn prompt_secret(&self, _key: &str, _message: &str) -> connect::error::Result<Option<String>> {
        Err(Error::new(
            "secret prompts are not expected in OpenSSH e2e tests",
        ))
    }

    fn confirm(&self, _key: &str, _message: &str, _default: bool) -> connect::error::Result<bool> {
        Err(Error::new(
            "host key prompt should not repeat after TOFU trust",
        ))
    }
}

fn run_command(command: &mut Command) -> io::Result<Output> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "command {:?} failed with status {}: {}",
                command,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        ))
    }
}

fn run_remote_command(port: u16, key_path: &Path, script: &str) -> io::Result<Output> {
    run_command(
        Command::new("ssh")
            .arg("-i")
            .arg(key_path)
            .arg("-p")
            .arg(port.to_string())
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("127.0.0.1")
            .arg(script),
    )
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn parse_agent_value(output: &str, key: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .and_then(|line| line.split(';').next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("ssh-agent output missing {key}: {output}"))
}

fn current_username() -> String {
    env::var("USER")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let output = run_command(Command::new("id").arg("-un"))
                .expect("current username should be discoverable");
            String::from_utf8(output.stdout)
                .expect("username should be utf-8")
                .trim()
                .to_string()
        })
}

fn allocate_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("ephemeral port should allocate")
        .local_addr()
        .expect("local addr should resolve")
        .port()
}

fn wait_for_port(port: u16, log_path: &Path) {
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }

    panic!(
        "sshd did not start listening on port {port}\n{}",
        read_optional(log_path)
    );
}

async fn wait_for_tokio_port(port: u16) {
    for _ in 0..100 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("port {port} did not start listening in time");
}

async fn run_saved_forward_until<F>(
    app: &App,
    ssh: &RusshClient,
    prompt: &dyn Prompt,
    profile: &str,
    forward_name: &str,
    checks: F,
) -> connect::error::Result<()>
where
    F: std::future::Future<Output = ()>,
{
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let run = app.run_saved_forward(
        profile,
        connect::forward::runtime::SavedForwardSelection::Named(forward_name.into()),
        ssh,
        prompt,
        {
            let shutdown = Arc::clone(&shutdown);
            async move {
                while !shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        },
    );
    tokio::pin!(run);
    tokio::pin!(checks);

    tokio::select! {
        result = &mut run => result,
        _ = &mut checks => {
            shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
            run.await
        }
    }
}

async fn socks5_greet(stream: &mut tokio::net::TcpStream) {
    stream
        .write_all(&[5, 1, 0])
        .await
        .expect("SOCKS greeting should be written");
    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .expect("SOCKS greeting response should be readable");
    assert_eq!(response, [5, 0]);
}

async fn socks5_connect_ipv4(stream: &mut tokio::net::TcpStream, address: [u8; 4], port: u16) {
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&address);
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .expect("SOCKS CONNECT request should be written");
    let mut reply = [0_u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .expect("SOCKS CONNECT reply should be readable");
    assert_eq!(reply[1], 0, "SOCKS CONNECT should succeed");
}

fn read_optional(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|_| String::new())
}

fn write_pattern_file(path: &Path, size_bytes: usize) {
    let mut file = fs::File::create(path).expect("pattern file should be created");
    let pattern = (0..(1024 * 1024))
        .map(|index| u8::try_from(index % 251).expect("pattern byte should fit"))
        .collect::<Vec<_>>();
    let mut remaining = size_bytes;
    while remaining > 0 {
        let chunk = remaining.min(pattern.len());
        file.write_all(&pattern[..chunk])
            .expect("pattern chunk should be written");
        remaining -= chunk;
    }
}

fn assert_files_equal(left: &Path, right: &Path) {
    let left_meta = fs::metadata(left).expect("left metadata should exist");
    let right_meta = fs::metadata(right).expect("right metadata should exist");
    assert_eq!(left_meta.len(), right_meta.len(), "file sizes should match");

    let mut left_file = fs::File::open(left).expect("left file should open");
    let mut right_file = fs::File::open(right).expect("right file should open");
    let mut left_buf = vec![0_u8; 64 * 1024];
    let mut right_buf = vec![0_u8; 64 * 1024];

    loop {
        let left_read = left_file
            .read(&mut left_buf)
            .expect("left file should be readable");
        let right_read = right_file
            .read(&mut right_buf)
            .expect("right file should be readable");
        assert_eq!(left_read, right_read, "read lengths should match");
        if left_read == 0 {
            break;
        }
        assert_eq!(
            &left_buf[..left_read],
            &right_buf[..right_read],
            "file contents should match"
        );
    }
}

fn assert_checkpoint_dir_empty(path: PathBuf) {
    let entries = fs::read_dir(&path)
        .unwrap_or_else(|error| panic!("checkpoint directory should be readable: {error}"));
    assert!(
        entries.into_iter().next().is_none(),
        "checkpoint directory should be empty after successful threaded transfer"
    );
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
