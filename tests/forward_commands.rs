use std::{fs, path::PathBuf, sync::Arc};

use connect::{
    app::{App, AppPaths},
    cli::{
        commands::forward,
        ForwardAddArgs, ForwardArgs, ForwardCommand, ForwardListArgs, ForwardRemoveArgs,
        ForwardRunArgs,
    },
    secrets::MemorySecretStore,
    store::ProfileInput,
    terminal::prompt::Prompt,
};

struct TestHarness {
    root: PathBuf,
    app: App,
}

impl TestHarness {
    fn new() -> Self {
        let root = unique_temp_path("connect-forward-tests");
        let paths = AppPaths::from_root(&root);
        let app = App::new(paths, Arc::new(MemorySecretStore::default()))
            .expect("app should initialize");

        Self { root, app }
    }

    fn with_profile(name: &str) -> Self {
        let harness = Self::new();
        harness
            .app
            .save_profile(ProfileInput::new(
                name,
                format!("{name}.example.com"),
                "deploy",
            ))
            .unwrap();
        harness
    }

    fn app(&self) -> &App {
        &self.app
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

#[test]
fn forward_run_accepts_named_forward_and_all_for_existing_profile() {
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

    let named_output = run_forward(
        harness.app(),
        &ForwardArgs {
            command: ForwardCommand::Run(ForwardRunArgs {
                profile: "prod".into(),
                name: Some("db".into()),
                all: false,
            }),
        },
    )
    .unwrap();
    assert_eq!(named_output, "Validated forward 'db' for profile 'prod'.\n");

    let all_output = run_forward(
        harness.app(),
        &ForwardArgs {
            command: ForwardCommand::Run(ForwardRunArgs {
                profile: "prod".into(),
                name: None,
                all: true,
            }),
        },
    )
    .unwrap();
    assert_eq!(all_output, "Validated 1 saved forward(s) for profile 'prod'.\n");
}

fn run_forward(harness: &App, args: &ForwardArgs) -> Result<String, connect::error::Error> {
    let prompt = AcceptPrompt;
    let mut output = Vec::new();
    forward::run(harness, &prompt, args, &mut output)?;
    Ok(String::from_utf8(output).expect("output should be utf8"))
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
