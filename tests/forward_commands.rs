use std::{
    fs,
    future::Future,
    net::TcpListener as StdTcpListener,
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use connect::{
    app::{App, AppPaths, ProfileSecretsInput},
    cli::{
        commands::forward,
        ForwardAddArgs, ForwardArgs, ForwardCommand, ForwardListArgs, ForwardRemoveArgs,
        ForwardRunArgs,
    },
    secrets::MemorySecretStore,
    ssh::{DirectTcpipStream, ObservedHostKey, SshClient, SshSession},
    store::ProfileInput,
    terminal::prompt::Prompt,
};
use tokio::{
    io::{duplex, AsyncWriteExt},
    net::TcpStream,
};

struct TestHarness {
    root: PathBuf,
    app: Arc<App>,
}

impl TestHarness {
    fn new() -> Self {
        let root = unique_temp_path("connect-forward-tests");
        let paths = AppPaths::from_root(&root);
        let app = Arc::new(
            App::new(paths, Arc::new(MemorySecretStore::default()))
                .expect("app should initialize"),
        );

        Self { root, app }
    }

    fn with_profile(name: &str) -> Self {
        let harness = Self::new();
        harness
            .app
            .save_profile_with_secrets(
                ProfileInput::new(name, format!("{name}.example.com"), "deploy"),
                ProfileSecretsInput {
                    password: Some("secret".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        harness
    }

    fn app(&self) -> &App {
        self.app.as_ref()
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn forward_add_list_and_remove_are_persistent() {
    let harness = TestHarness::with_profile("prod");
    let prompt = AcceptPrompt;
    let mut output = Vec::new();

    forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "db".into(),
                local: Some("127.0.0.1:15432:db.internal:5432".into()),
                socks: None,
                description: Some("postgres".into()),
            }),
        },
        &mut output,
    )
    .unwrap();

    forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "proxy".into(),
                local: None,
                socks: Some("127.0.0.1:1080".into()),
                description: None,
            }),
        },
        &mut output,
    )
    .unwrap();

    let list_output = run_forward(
        harness.app(),
        &ForwardArgs {
            command: ForwardCommand::List(ForwardListArgs {
                profile: "prod".into(),
            }),
        },
    )
    .unwrap();
    assert_eq!(
        list_output,
        "db\tlocal\t127.0.0.1:15432\tdb.internal:5432\nproxy\tsocks\t127.0.0.1:1080\n"
    );

    let remove_output = run_forward(
        harness.app(),
        &ForwardArgs {
            command: ForwardCommand::Remove(ForwardRemoveArgs {
                profile: "prod".into(),
                name: "db".into(),
                yes: true,
            }),
        },
    )
    .unwrap();
    assert_eq!(remove_output, "Removed forward 'db' from profile 'prod'.\n");

    let saved = harness.app().list_forwards("prod").unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "proxy");
}

#[test]
fn forward_add_rejects_duplicate_names_per_profile() {
    let harness = TestHarness::with_profile("prod");
    let prompt = AcceptPrompt;
    let mut output = Vec::new();

    forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "db".into(),
                local: Some("127.0.0.1:15432:db.internal:5432".into()),
                socks: None,
                description: None,
            }),
        },
        &mut output,
    )
    .unwrap();

    let error = forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "db".into(),
                local: None,
                socks: Some("127.0.0.1:1080".into()),
                description: None,
            }),
        },
        &mut output,
    )
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "forward 'db' already exists for profile 'prod'"
    );
}

#[test]
fn forward_add_rejects_malformed_specs_and_impossible_ports() {
    let harness = TestHarness::with_profile("prod");
    let prompt = AcceptPrompt;
    let mut output = Vec::new();

    let malformed_local = forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "db".into(),
                local: Some("127.0.0.1:15432:db.internal".into()),
                socks: None,
                description: None,
            }),
        },
        &mut output,
    )
    .unwrap_err();
    assert_eq!(
        malformed_local.to_string(),
        "target_port is required"
    );

    let impossible_port = forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "proxy".into(),
                local: None,
                socks: Some("127.0.0.1:0".into()),
                description: None,
            }),
        },
        &mut output,
    )
    .unwrap_err();
    assert_eq!(
        impossible_port.to_string(),
        "bind_port must be between 1 and 65535"
    );
}

#[test]
fn forward_run_rejects_missing_or_conflicting_selector_arguments() {
    let harness = TestHarness::with_profile("prod");
    let prompt = AcceptPrompt;
    let mut output = Vec::new();

    let missing_selector = forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Run(ForwardRunArgs {
                profile: "prod".into(),
                name: None,
                all: false,
            }),
        },
        &mut output,
    )
    .unwrap_err();
    assert_eq!(missing_selector.to_string(), "forward run requires a name or --all");

    let conflicting_selector = forward::run(
        harness.app(),
        &prompt,
        &ForwardArgs {
            command: ForwardCommand::Run(ForwardRunArgs {
                profile: "prod".into(),
                name: Some("db".into()),
                all: true,
            }),
        },
        &mut output,
    )
    .unwrap_err();
    assert_eq!(
        conflicting_selector.to_string(),
        "forward run cannot accept both a name and --all"
    );
}

#[tokio::test]
async fn forward_run_starts_only_the_named_saved_forward() {
    let harness = TestHarness::with_profile("prod");
    let ssh = FakeForwardSshClient::always_alive();
    let db_port = allocate_port();
    let metrics_port = allocate_port();

    forward::run(
        harness.app(),
        &AcceptPrompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "db".into(),
                local: Some(format!("127.0.0.1:{db_port}:db.internal:5432")),
                socks: None,
                description: None,
            }),
        },
        &mut Vec::new(),
    )
    .unwrap();

    forward::run(
        harness.app(),
        &AcceptPrompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "metrics".into(),
                local: Some(format!("127.0.0.1:{metrics_port}:metrics.internal:9100")),
                socks: None,
                description: None,
            }),
        },
        &mut Vec::new(),
    )
    .unwrap();

    run_forward_until(
        harness.app(),
        ssh.clone(),
        ForwardRunArgs {
            profile: "prod".into(),
            name: Some("db".into()),
            all: false,
        },
        async move {
            wait_for_port(db_port).await;
            assert!(TcpStream::connect(("127.0.0.1", db_port)).await.is_ok());
            assert!(TcpStream::connect(("127.0.0.1", metrics_port)).await.is_err());
        },
    )
    .await
    .unwrap();
    assert_eq!(ssh.open_count(), 1);
    assert_eq!(ssh.last_target(), Some(("db.internal".into(), 5432)));
}

#[tokio::test]
async fn forward_run_with_all_binds_each_saved_local_forward() {
    let harness = TestHarness::with_profile("prod");
    let ssh = FakeForwardSshClient::always_alive();
    let db_port = allocate_port();
    let metrics_port = allocate_port();

    for (name, port, host, target_port) in [
        ("db", db_port, "db.internal", 5432_u16),
        ("metrics", metrics_port, "metrics.internal", 9100_u16),
    ] {
        forward::run(
            harness.app(),
            &AcceptPrompt,
            &ForwardArgs {
                command: ForwardCommand::Add(ForwardAddArgs {
                    profile: "prod".into(),
                    name: name.into(),
                    local: Some(format!("127.0.0.1:{port}:{host}:{target_port}")),
                    socks: None,
                    description: None,
                }),
            },
            &mut Vec::new(),
        )
        .unwrap();
    }

    run_forward_until(
        harness.app(),
        ssh.clone(),
        ForwardRunArgs {
            profile: "prod".into(),
            name: None,
            all: true,
        },
        async move {
            wait_for_port(db_port).await;
            wait_for_port(metrics_port).await;
            assert!(TcpStream::connect(("127.0.0.1", db_port)).await.is_ok());
            assert!(TcpStream::connect(("127.0.0.1", metrics_port)).await.is_ok());
        },
    )
    .await
    .unwrap();
    assert_eq!(ssh.open_count(), 2);
}

#[tokio::test]
async fn forward_run_fails_startup_without_leaving_partial_listeners() {
    let harness = TestHarness::with_profile("prod");
    let first_port = allocate_port();
    let blocked_port = allocate_port();
    let blocker = StdTcpListener::bind(("127.0.0.1", blocked_port)).expect("port should bind");

    for (name, port, host, target_port) in [
        ("db", first_port, "db.internal", 5432_u16),
        ("metrics", blocked_port, "metrics.internal", 9100_u16),
    ] {
        forward::run(
            harness.app(),
            &AcceptPrompt,
            &ForwardArgs {
                command: ForwardCommand::Add(ForwardAddArgs {
                    profile: "prod".into(),
                    name: name.into(),
                    local: Some(format!("127.0.0.1:{port}:{host}:{target_port}")),
                    socks: None,
                    description: None,
                }),
            },
            &mut Vec::new(),
        )
        .unwrap();
    }

    let error = forward::run_with_ssh_and_shutdown(
        harness.app(),
        &AcceptPrompt,
        &ForwardRunArgs {
            profile: "prod".into(),
            name: None,
            all: true,
        },
        &FakeForwardSshClient::always_alive(),
        async {},
    )
    .await
    .unwrap_err();

    assert!(error
        .to_string()
        .contains(&format!("failed to bind local forward 'metrics' on 127.0.0.1:{blocked_port}")));
    drop(blocker);
    assert!(
        StdTcpListener::bind(("127.0.0.1", first_port)).is_ok(),
        "successful listeners should be dropped on startup failure"
    );
}

#[tokio::test]
async fn forward_run_returns_a_useful_error_when_the_ssh_session_dies() {
    let harness = TestHarness::with_profile("prod");
    let port = allocate_port();
    let ssh = FakeForwardSshClient::with_session_lifecycle(1);

    forward::run(
        harness.app(),
        &AcceptPrompt,
        &ForwardArgs {
            command: ForwardCommand::Add(ForwardAddArgs {
                profile: "prod".into(),
                name: "db".into(),
                local: Some(format!("127.0.0.1:{port}:db.internal:5432")),
                socks: None,
                description: None,
            }),
        },
        &mut Vec::new(),
    )
    .unwrap();

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        forward::run_with_ssh_and_shutdown(
            harness.app(),
            &AcceptPrompt,
            &ForwardRunArgs {
                profile: "prod".into(),
                name: Some("db".into()),
                all: false,
            },
            &ssh,
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
            },
        ),
    )
    .await
    .expect("runtime should finish once the session dies")
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "ssh session for forward 'db' disconnected"
    );
}

async fn run_forward_until<F>(
    app: &App,
    ssh: FakeForwardSshClient,
    args: ForwardRunArgs,
    checks: F,
) -> connect::error::Result<()>
where
    F: Future<Output = ()>,
{
    let shutdown = Arc::new(AtomicBool::new(false));
    let run = forward::run_with_ssh_and_shutdown(app, &AcceptPrompt, &args, &ssh, {
        let shutdown = Arc::clone(&shutdown);
        async move {
            while !shutdown.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    });
    tokio::pin!(run);
    tokio::pin!(checks);

    tokio::select! {
        result = &mut run => result,
        _ = &mut checks => {
            shutdown.store(true, Ordering::SeqCst);
            run.await
        }
    }
}

async fn wait_for_port(port: u16) {
    for _ in 0..80 {
        if StdTcpListener::bind(("127.0.0.1", port)).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("port {port} did not start listening in time");
}

#[derive(Default)]
struct AcceptPrompt;

impl Prompt for AcceptPrompt {
    fn prompt(
        &self,
        _key: &str,
        _message: &str,
        default: Option<&str>,
    ) -> connect::error::Result<String> {
        default
            .map(|value| value.to_string())
            .ok_or_else(|| connect::error::Error::new("prompt not expected"))
    }

    fn prompt_secret(
        &self,
        _key: &str,
        _message: &str,
    ) -> connect::error::Result<Option<String>> {
        Ok(None)
    }

    fn confirm(
        &self,
        _key: &str,
        _message: &str,
        _default: bool,
    ) -> connect::error::Result<bool> {
        Ok(true)
    }
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()))
}

fn run_forward(harness: &App, args: &ForwardArgs) -> Result<String, connect::error::Error> {
    let prompt = AcceptPrompt;
    let mut output = Vec::new();
    forward::run(harness, &prompt, args, &mut output)?;
    Ok(String::from_utf8(output).expect("output should be utf8"))
}

fn allocate_port() -> u16 {
    StdTcpListener::bind(("127.0.0.1", 0))
        .expect("ephemeral port should allocate")
        .local_addr()
        .expect("local addr should exist")
        .port()
}

#[derive(Clone)]
struct FakeForwardSshClient {
    state: Arc<FakeForwardState>,
}

struct FakeForwardState {
    open_count: AtomicUsize,
    alive_polls_remaining: AtomicUsize,
    last_target: std::sync::Mutex<Option<(String, u16)>>,
}

impl FakeForwardSshClient {
    fn always_alive() -> Self {
        Self::with_session_lifecycle(usize::MAX)
    }

    fn with_session_lifecycle(alive_polls: usize) -> Self {
        Self {
            state: Arc::new(FakeForwardState {
                open_count: AtomicUsize::new(0),
                alive_polls_remaining: AtomicUsize::new(alive_polls),
                last_target: std::sync::Mutex::new(None),
            }),
        }
    }

    fn open_count(&self) -> usize {
        self.state.open_count.load(Ordering::SeqCst)
    }

    fn last_target(&self) -> Option<(String, u16)> {
        self.state.last_target.lock().unwrap().clone()
    }
}

impl SshClient for FakeForwardSshClient {
    fn connect<'a>(
        &'a self,
        profile: &'a connect::store::Profile,
        _expected_host_key: Option<&'a connect::store::HostKeyRecord>,
    ) -> Pin<
        Box<
            dyn Future<Output = connect::error::Result<Box<dyn SshSession + Send + 'static>>>
                + Send
                + 'a,
        >,
    > {
        let state = Arc::clone(&self.state);
        let profile = profile.clone();
        Box::pin(async move {
            Ok(Box::new(FakeForwardSession { state, profile }) as Box<dyn SshSession + Send>)
        })
    }
}

struct FakeForwardSession {
    state: Arc<FakeForwardState>,
    profile: connect::store::Profile,
}

impl SshSession for FakeForwardSession {
    fn observe_host_key<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<ObservedHostKey>> + Send + 'a>> {
        let observed = ObservedHostKey {
            host: self.profile.host.clone(),
            port: self.profile.port,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "forward-fp".into(),
            public_key: "forward-public-key".into(),
        };
        Box::pin(async move { Ok(observed) })
    }

    fn authenticate_public_key<'a>(
        &'a mut self,
        _username: &'a str,
        _private_key: &'a str,
        _passphrase: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = connect::error::Result<bool>> + Send + 'a>> {
        Box::pin(async move { Ok(true) })
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

    fn open_direct_tcpip<'a>(
        &'a mut self,
        target_host: &'a str,
        target_port: u16,
        _originator_host: &'a str,
        _originator_port: u16,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = connect::error::Result<
                        Box<dyn DirectTcpipStream + Send + Unpin + 'static>,
                    >,
                > + Send
                + 'a,
        >,
    > {
        self.state.open_count.fetch_add(1, Ordering::SeqCst);
        *self.state.last_target.lock().unwrap() = Some((target_host.to_string(), target_port));
        Box::pin(async move {
            let (client, mut remote) = duplex(1024);
            tokio::spawn(async move {
                let _ = remote.shutdown().await;
            });
            Ok(Box::new(client) as Box<dyn DirectTcpipStream + Send + Unpin + 'static>)
        })
    }

    fn is_alive(&self) -> bool {
        let remaining = self.state.alive_polls_remaining.load(Ordering::SeqCst);
        if remaining == 0 {
            return false;
        }
        self.state
            .alive_polls_remaining
            .fetch_sub(1, Ordering::SeqCst);
        true
    }
}
