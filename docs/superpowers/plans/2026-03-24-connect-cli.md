# Connect CLI Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a cross-platform Rust CLI named `connect` that securely manages SSH profiles, opens SSH sessions with embedded Rust SSH support, transfers files, and ships with standalone installers/packages for Windows, macOS, and Linux.

**Architecture:** The tool is a single Rust binary with clear module boundaries for CLI parsing, profile persistence, OS-native secret storage, SSH/session logic, host key verification, and copy operations. Non-sensitive metadata lives in SQLite under per-user app directories, while passwords and imported private keys live only in the OS keychain. Host key trust is TOFU per `host:port`, persisted locally and enforced by both connect and copy flows.

**Tech Stack:** Rust stable, `clap`, `russh`, `russh-keys`, `tokio`, `rusqlite`, `keyring`, `serde`, `directories`, `thiserror`, `assert_cmd`, `predicates`, `tempfile`, installer tooling for Windows/macOS/Linux release artifacts

---

## File Structure

### Core crate

- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`
- Create: `src/error.rs`
- Create: `src/app.rs`

### CLI layer

- Create: `src/cli/mod.rs`
- Create: `src/cli/types.rs`
- Create: `src/cli/commands/add.rs`
- Create: `src/cli/commands/edit.rs`
- Create: `src/cli/commands/remove.rs`
- Create: `src/cli/commands/list.rs`
- Create: `src/cli/commands/show.rs`
- Create: `src/cli/commands/connect.rs`
- Create: `src/cli/commands/copy.rs`
- Create: `src/cli/commands/hostkeys.rs`
- Create: `src/cli/commands/completion.rs`

### Persistence and secrets

- Create: `src/store/mod.rs`
- Create: `src/store/db.rs`
- Create: `src/store/models.rs`
- Create: `src/store/profile_store.rs`
- Create: `src/store/hostkey_store.rs`
- Create: `src/secrets/mod.rs`
- Create: `src/secrets/keyring.rs`

### SSH and terminal

- Create: `src/ssh/mod.rs`
- Create: `src/ssh/client.rs`
- Create: `src/ssh/auth.rs`
- Create: `src/ssh/hostkeys.rs`
- Create: `src/ssh/copy.rs`
- Create: `src/terminal/mod.rs`
- Create: `src/terminal/interactive.rs`
- Create: `src/terminal/prompt.rs`

### Tests

- Create: `tests/cli_help.rs`
- Create: `tests/profile_commands.rs`
- Create: `tests/copy_path_parsing.rs`
- Create: `tests/hostkey_commands.rs`
- Create: `tests/configuration_dirs.rs`
- Create: `tests/support/mod.rs`

### Packaging

- Create: `packaging/install.sh`
- Create: `packaging/macos/postinstall`
- Create: `packaging/windows/connect.wxs`
- Create: `.github/workflows/release.yml`
- Create: `README.md`

## Execution Notes

- Work in the main repository because the user explicitly requested no worktree.
- Create a feature branch before implementation to avoid building directly on `main`.
- Follow TDD strictly: each behavior starts with a failing test and verified failure.
- Keep SSH crate integration behind thin traits where possible so tests can use fakes instead of real network sessions.
- Do not implement extra SSH features beyond the approved spec.

### Task 1: Bootstrap The Rust Project And CLI Skeleton

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`
- Create: `src/error.rs`
- Create: `src/app.rs`
- Create: `src/cli/mod.rs`
- Create: `src/cli/types.rs`
- Create: `src/cli/commands/completion.rs`
- Create: `src/cli/commands/version.rs`
- Test: `tests/cli_help.rs`

- [ ] **Step 1: Write the failing CLI help tests**

```rust
#[test]
fn root_help_lists_core_commands() {
    let mut cmd = connect_test_bin();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("add"))
        .stdout(predicates::str::contains("copy"))
        .stdout(predicates::str::contains("hostkeys"));
}

#[test]
fn version_command_prints_binary_version() {
    let mut cmd = connect_test_bin();
    cmd.arg("version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test cli_help root_help_lists_core_commands -- --exact`
Expected: FAIL because the crate and command tree do not exist yet.

- [ ] **Step 3: Create the crate and command definitions**

```rust
#[derive(clap::Parser)]
#[command(name = "connect", version, about = "Manage SSH connections securely")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}
```

- [ ] **Step 4: Add the default command surface and help text**

Implement subcommands for `add`, `edit`, `remove`, `list`, `show`, `copy`, `hostkeys`, `completion`, `version`, and a positional profile name for the default connect action.

- [ ] **Step 5: Run the targeted test and full test suite**

Run: `cargo test --test cli_help`
Expected: PASS

Run: `cargo test`
Expected: PASS with only the initial CLI help coverage.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src tests
git commit -m "feat: scaffold connect cli"
```

### Task 2: Build Config Paths, SQLite Storage, And Secret Abstractions

**Files:**
- Modify: `Cargo.toml`
- Create: `src/store/mod.rs`
- Create: `src/store/db.rs`
- Create: `src/store/models.rs`
- Create: `src/store/profile_store.rs`
- Create: `src/store/hostkey_store.rs`
- Create: `src/secrets/mod.rs`
- Create: `src/secrets/keyring.rs`
- Modify: `src/app.rs`
- Modify: `src/error.rs`
- Test: `tests/configuration_dirs.rs`
- Test: `tests/profile_commands.rs`

- [ ] **Step 1: Write failing tests for app paths and profile CRUD**

```rust
#[test]
fn profile_insert_round_trip_preserves_metadata() {
    let harness = TestHarness::new();
    let profile = ProfileInput::new("prod", "prod.example.com", "deploy");
    harness.app().save_profile(profile.clone()).unwrap();

    let loaded = harness.app().get_profile("prod").unwrap();
    assert_eq!(loaded.host, "prod.example.com");
    assert_eq!(loaded.username, "deploy");
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test --test configuration_dirs`
Expected: FAIL because app path resolution is not implemented.

Run: `cargo test --test profile_commands profile_insert_round_trip_preserves_metadata -- --exact`
Expected: FAIL because persistence and secret abstractions do not exist.

- [ ] **Step 3: Implement app directory resolution and SQLite bootstrap**

Use `directories` for per-user paths and `rusqlite` for schema creation. Create tables for `profiles` and `host_keys`.

- [ ] **Step 4: Implement secret storage abstraction**

```rust
pub trait SecretStore {
    fn set_password(&self, profile_name: &str, password: &str) -> Result<()>;
    fn get_password(&self, profile_name: &str) -> Result<Option<String>>;
    fn set_private_key(&self, profile_name: &str, pem: &str) -> Result<()>;
    fn get_private_key(&self, profile_name: &str) -> Result<Option<String>>;
    fn set_key_passphrase(&self, profile_name: &str, passphrase: &str) -> Result<()>;
    fn get_key_passphrase(&self, profile_name: &str) -> Result<Option<String>>;
    fn delete_profile_secrets(&self, profile_name: &str) -> Result<()>;
}
```

Back it with `keyring` in production and an in-memory fake in tests.

- [ ] **Step 5: Implement profile store operations**

Support insert, update, fetch, list, and delete for non-sensitive profile metadata.

- [ ] **Step 6: Run targeted tests and full suite**

Run: `cargo test --test configuration_dirs`
Expected: PASS

Run: `cargo test --test profile_commands`
Expected: PASS for storage and secret abstraction coverage.

Run: `cargo test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml src tests
git commit -m "feat: add profile storage and secret abstractions"
```

### Task 3: Implement Profile Management Commands

**Files:**
- Modify: `src/cli/mod.rs`
- Modify: `src/cli/types.rs`
- Create: `src/cli/commands/add.rs`
- Create: `src/cli/commands/edit.rs`
- Create: `src/cli/commands/remove.rs`
- Create: `src/cli/commands/list.rs`
- Create: `src/cli/commands/show.rs`
- Modify: `src/app.rs`
- Modify: `src/terminal/prompt.rs`
- Test: `tests/profile_commands.rs`

- [ ] **Step 1: Write failing command tests**

```rust
#[test]
fn add_command_imports_private_key_and_persists_profile() {
    let temp_key = TestKey::write_temp_pem();
    connect_test_bin()
        .args([
            "add", "prod",
            "--host", "prod.example.com",
            "--user", "deploy",
            "--private-key", temp_key.path(),
        ])
        .assert()
        .success();

    assert_profile_exists("prod");
    assert_private_key_saved("prod");
}

#[test]
fn add_command_prompts_for_missing_required_fields() {
    let prompt = FakePrompt::new()
        .with_text("host", "prod.example.com")
        .with_text("user", "deploy");

    connect_test_bin()
        .args(["add", "prod"])
        .with_prompt(prompt)
        .assert()
        .success();
}
```

- [ ] **Step 2: Run the profile command tests to verify they fail**

Run: `cargo test --test profile_commands`
Expected: FAIL because command handlers are not implemented.

- [ ] **Step 3: Implement `add` and `edit`**

Behaviors:
- validate name, host, username, and port
- interactively prompt for missing required non-secret fields when flags are omitted
- import private key content immediately if `--private-key` is provided
- store password via secret store if `--password` or interactive prompt is used
- allow partial updates on edit

- [ ] **Step 4: Implement `remove`, `list`, and `show`**

Behaviors:
- `remove` deletes profile metadata and associated secrets, with `--yes` to skip confirmation
- `list` prints concise rows
- `show` prints metadata and redacted credential availability only

- [ ] **Step 5: Run targeted tests and full suite**

Run: `cargo test --test profile_commands`
Expected: PASS

Run: `cargo test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: add profile management commands"
```

### Task 4: Implement Host Key Trust And Management Commands

**Files:**
- Modify: `src/store/hostkey_store.rs`
- Create: `src/ssh/hostkeys.rs`
- Create: `src/cli/commands/hostkeys.rs`
- Modify: `src/app.rs`
- Modify: `src/terminal/prompt.rs`
- Test: `tests/hostkey_commands.rs`

- [ ] **Step 1: Write failing tests for host key CRUD and TOFU prompts**

```rust
#[test]
fn hostkey_delete_removes_saved_record() {
    let harness = TestHarness::with_saved_hostkey("prod.example.com", 22);
    connect_test_bin()
        .args(["hostkeys", "delete", "prod.example.com:22", "--yes"])
        .assert()
        .success();

    assert!(!harness.hostkey_exists("prod.example.com", 22));
}

#[tokio::test]
async fn first_connect_prompts_accepts_and_reuses_saved_hostkey() {
    let harness = TestHarness::with_profile("prod");
    let prompt = FakePrompt::accepting();
    let ssh = FakeSshClient::with_hostkey("ssh-ed25519", "fp-123");

    harness.app().connect_profile("prod", ssh.clone(), prompt).await.unwrap();
    assert!(harness.hostkey_exists("prod.example.com", 22));

    harness
        .app()
        .connect_profile("prod", ssh, FakePrompt::unused())
        .await
        .unwrap();
}
```

- [ ] **Step 2: Run the host key tests to verify they fail**

Run: `cargo test --test hostkey_commands`
Expected: FAIL because host key commands and TOFU acceptance and reuse logic do not exist.

- [ ] **Step 3: Implement host key store and prompt flow**

Support:
- insert accepted host key
- fetch by host and port
- list saved host keys
- delete by `host:port`
- display host, port, key algorithm, and fingerprint before trust confirmation
- prompt on first seen host key fingerprint
- persist accepted host key after confirmation
- skip prompting on subsequent connections when the stored host key matches

- [ ] **Step 4: Implement CLI commands**

`connect hostkeys list` and `connect hostkeys delete <host:port>` should route through the app layer and print deterministic output.

- [ ] **Step 5: Run targeted tests and full suite**

Run: `cargo test --test hostkey_commands`
Expected: PASS

Run: `cargo test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: add host key management"
```

### Task 5: Implement Embedded SSH Sessions And Default `connect <name>`

**Files:**
- Create: `src/ssh/mod.rs`
- Create: `src/ssh/client.rs`
- Create: `src/ssh/auth.rs`
- Create: `src/terminal/mod.rs`
- Create: `src/terminal/interactive.rs`
- Modify: `src/cli/commands/connect.rs`
- Modify: `src/cli/mod.rs`
- Modify: `src/app.rs`
- Test: `tests/profile_commands.rs`

- [ ] **Step 1: Write a failing integration-oriented test around connection orchestration**

```rust
#[tokio::test]
async fn connect_uses_profile_and_rejects_host_key_mismatch() {
    let harness = TestHarness::with_profile("prod");
    harness.save_hostkey("prod.example.com", 22, "expected-fingerprint");

    let result = harness
        .app()
        .connect_profile("prod", FakeSshClient::with_hostkey("different-fingerprint"))
        .await;

    assert!(matches!(result, Err(AppError::HostKeyMismatch { .. })));
}

#[tokio::test]
async fn connect_tries_private_key_before_password() {
    let harness = TestHarness::with_profile("prod");
    let ssh = FakeSshClient::key_rejected_then_password_succeeds();

    harness.app().connect_profile("prod", ssh.clone(), FakePrompt::unused()).await.unwrap();
    assert_eq!(ssh.auth_attempts(), vec!["key", "password"]);
}
```

- [ ] **Step 2: Run the targeted test to verify it fails**

Run: `cargo test connect_uses_profile_and_rejects_host_key_mismatch -- --exact`
Expected: FAIL because the SSH orchestration layer does not exist.

- [ ] **Step 3: Implement SSH orchestration behind a trait**

Define a thin client abstraction for:
- loading profile auth material from the secret store
- retrieving the remote host key
- verifying or prompting to trust
- opening an interactive session with attached stdin/stdout/stderr

- [ ] **Step 4: Implement the real `russh` client path**

Use `tokio` runtime and PTY/session handling appropriate for the current platform. Keep terminal attachment code isolated from SSH protocol code.

- [ ] **Step 5: Wire the positional `connect <name>` flow**

Behavior:
- resolve profile
- perform host key verification
- authenticate with key first, password fallback second
- attach the interactive session to the terminal

- [ ] **Step 6: Run targeted tests, build, and full suite**

Run: `cargo test connect_uses_profile_and_rejects_host_key_mismatch -- --exact`
Expected: PASS

Run: `cargo build`
Expected: PASS

Run: `cargo test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src tests
git commit -m "feat: add embedded ssh connect flow"
```

### Task 6: Implement `connect copy` For File And Directory Transfers

**Files:**
- Create: `src/ssh/copy.rs`
- Modify: `src/cli/commands/copy.rs`
- Modify: `src/app.rs`
- Modify: `src/ssh/client.rs`
- Test: `tests/copy_path_parsing.rs`
- Test: `tests/profile_commands.rs`

- [ ] **Step 1: Write failing tests for remote path parsing and recursive validation**

```rust
#[test]
fn copy_rejects_directory_without_recursive_flag() {
    connect_test_bin()
        .args(["copy", "fixtures/tree", "prod:/tmp/tree"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--recursive"));
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test --test copy_path_parsing`
Expected: FAIL because path parsing and copy validation do not exist.

- [ ] **Step 3: Implement copy path parsing**

Support exactly one remote side using `profile:/path` syntax. Reject remote-to-remote and local-to-local invocations.

- [ ] **Step 4: Implement file and directory transfer operations**

Use the SSH layer to:
- upload files
- download files
- recursively walk directories when `--recursive` is set

- [ ] **Step 5: Wire `connect copy` to shared host key and auth flows**

The command should reuse profile lookup, host key verification, and auth resolution from the connect flow.

- [ ] **Step 6: Run targeted tests, build, and full suite**

Run: `cargo test --test copy_path_parsing`
Expected: PASS

Run: `cargo build`
Expected: PASS

Run: `cargo test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src tests
git commit -m "feat: add scp-style copy command"
```

### Task 7: Package The Binary And Document Installation

**Files:**
- Create: `packaging/install.sh`
- Create: `packaging/macos/postinstall`
- Create: `packaging/windows/connect.wxs`
- Create: `.github/workflows/release.yml`
- Create: `README.md`
- Modify: `Cargo.toml`
- Test: `tests/packaging_assets.rs`

- [ ] **Step 1: Write failing tests or lint-style assertions for release assets**

Add lightweight tests or script checks that verify the packaging files exist and contain the expected install target path references.

- [ ] **Step 2: Run the packaging verification to confirm it fails**

Run: `cargo test packaging_assets_exist -- --exact`
Expected: FAIL because packaging artifacts do not exist yet.

- [ ] **Step 3: Implement Linux and macOS install assets**

The install script should:
- place the binary into a standard per-system location
- add or document `PATH` updates where needed
- avoid creating runtime state eagerly

- [ ] **Step 4: Implement Windows installer definition**

Create a WiX definition or equivalent asset that installs `connect.exe` and updates `PATH` according to the installer model.

- [ ] **Step 5: Implement release workflow and README**

The workflow should:
- build release binaries on Windows, macOS, and Linux
- package platform artifacts
- publish or upload artifacts

`README.md` should document profile management, connect usage, copy syntax, and installer expectations.

- [ ] **Step 6: Run verification, build, and full suite**

Run: `cargo test packaging_assets_exist -- --exact`
Expected: PASS

Run: `cargo build --release`
Expected: PASS

Run: `cargo test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml packaging .github README.md tests
git commit -m "feat: add packaging and install assets"
```

## Final Verification Checklist

- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo build --release`
- [ ] Re-read `docs/superpowers/specs/2026-03-24-connect-design.md` and verify each acceptance criterion is covered
- [ ] Request final code review against the implementation range
