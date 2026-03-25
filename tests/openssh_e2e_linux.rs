#![cfg(target_os = "linux")]

use std::{
    env, fs, io,
    net::TcpListener,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    thread,
    time::{Duration, SystemTime},
};

use connect::{
    app::{App, AppPaths, ProfileSecretsInput},
    doctor::checks::{collect_profile_checks, DoctorEnvironment, LocalDoctorCheckStatus},
    error::Error,
    secrets::MemorySecretStore,
    ssh::{parse_copy_spec, ExecSpec, RusshClient},
    store::{AuthMode, ProfileInput},
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

fn read_optional(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|_| String::new())
}
