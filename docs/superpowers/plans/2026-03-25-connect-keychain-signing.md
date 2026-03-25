# Connect Keychain Bundling And macOS Signing Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce repeated keychain prompts by bundling per-profile secrets into one keychain record with process-local caching, while adding optional macOS release signing in GitHub Actions.

**Architecture:** Keep the public `SecretStore` trait field-oriented and move the bundling, legacy migration, and caching logic into the keyring-backed implementation. Preserve current add/edit/delete behavior by merge-updating one serialized secret bundle per profile, then add a signing branch to the macOS release workflow that activates only when the configured GitHub secrets are present.

**Tech Stack:** Rust stable, `keyring`, `keyring-core`, `serde`, `serde_json`, `tokio`, `clap`, `russh`, `russh-sftp`, GitHub Actions, macOS `codesign`, macOS `productsign`, `assert_cmd`, `predicates`, `tempfile`

---

## File Structure

### Secret storage and app integration

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src/secrets/mod.rs`
- Modify: `src/secrets/keyring.rs`
- Modify: `src/app.rs`

### Tests

- Create: `tests/keyring_secret_store.rs`
- Modify: `tests/profile_commands.rs`
- Modify: `tests/doctor_commands.rs`
- Modify: `tests/hostkey_commands.rs`

### Release workflow and docs

- Modify: `.github/workflows/release.yml`
- Modify: `tests/packaging_assets.rs`
- Modify: `README.md`

## Execution Notes

- Work on `codex/connect-cli`; do not create a worktree because the user explicitly asked to work in the main repo.
- Follow TDD for each behavior change: write the failing test first, run it to confirm the expected failure, then implement the smallest code needed to pass.
- Keep the public `SecretStore` API stable so the rest of the app does not need a broad refactor.
- Preserve lazy migration: existing per-field secrets must remain readable until a bundled record is written successfully.
- Keep unsigned local builds working. macOS signing in CI must be conditional on secrets being present.
- Do not add notarization in this plan.

### Task 1: Add Bundle Types And Test Surface For Bundled Secret Storage

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src/secrets/mod.rs`
- Create: `tests/keyring_secret_store.rs`

- [ ] **Step 1: Add failing tests for bundle serialization and merge semantics**

Add tests in `tests/keyring_secret_store.rs` for:

```rust
#[test]
fn secret_bundle_round_trips_through_json() {
    let bundle = SecretBundle {
        version: 1,
        password: Some("pw".into()),
        private_key: Some("pem".into()),
        key_passphrase: Some("phrase".into()),
    };

    let encoded = encode_bundle(&bundle).unwrap();
    let decoded = decode_bundle(&encoded).unwrap();
    assert_eq!(decoded, bundle);
}

#[test]
fn merge_updates_only_requested_secret_field() {
    let bundle = SecretBundle {
        version: 1,
        password: Some("old".into()),
        private_key: Some("pem".into()),
        key_passphrase: None,
    };

    let merged = bundle.with_password(Some("new".into()));
    assert_eq!(merged.password.as_deref(), Some("new"));
    assert_eq!(merged.private_key.as_deref(), Some("pem"));
    assert_eq!(merged.key_passphrase, None);
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `cargo test --test keyring_secret_store secret_bundle_round_trips_through_json -- --exact`
Expected: FAIL because the bundle types and helpers do not exist.

Run: `cargo test --test keyring_secret_store merge_updates_only_requested_secret_field -- --exact`
Expected: FAIL because merge helpers do not exist.

- [ ] **Step 3: Add serialization dependencies and bundle types**

Add `serde` and `serde_json` to `Cargo.toml`.

Create a focused bundle type in `src/secrets/mod.rs` or `src/secrets/keyring.rs`:

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SecretBundle {
    version: u8,
    password: Option<String>,
    private_key: Option<String>,
    key_passphrase: Option<String>,
}
```

Add helper functions for:

- `encode_bundle`
- `decode_bundle`
- merge helpers for field-specific updates
- checking whether the bundle is empty

- [ ] **Step 4: Re-run the targeted tests to verify they pass**

Run: `cargo test --test keyring_secret_store secret_bundle_round_trips_through_json -- --exact`
Expected: PASS

Run: `cargo test --test keyring_secret_store merge_updates_only_requested_secret_field -- --exact`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/secrets/mod.rs src/secrets/keyring.rs tests/keyring_secret_store.rs
git commit -m "test: add bundled secret storage primitives"
```

### Task 2: Implement Bundled Keyring Storage, Process Cache, And Legacy Migration

**Files:**
- Modify: `src/secrets/keyring.rs`
- Create: `tests/keyring_secret_store.rs`

- [ ] **Step 1: Add failing tests for legacy migration and process-local caching**

Add tests covering:

```rust
#[test]
fn legacy_field_entries_migrate_into_a_single_profile_bundle() {
    let store = TestSecretStore::with_legacy_entries("prod", Some("pw"), Some("pem"), None);

    assert_eq!(store.get_password("prod").unwrap().as_deref(), Some("pw"));
    assert_eq!(store.bundle_write_count("prod"), 1);
    assert!(store.legacy_entries_deleted("prod"));
}

#[test]
fn repeated_reads_use_cached_bundle_after_first_load() {
    let store = TestSecretStore::with_bundle("prod", SecretBundle::with_password("pw"));

    assert_eq!(store.get_password("prod").unwrap().as_deref(), Some("pw"));
    assert_eq!(store.get_password("prod").unwrap().as_deref(), Some("pw"));
    assert_eq!(store.bundle_read_count("prod"), 1);
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test --test keyring_secret_store legacy_field_entries_migrate_into_a_single_profile_bundle -- --exact`
Expected: FAIL because migration logic does not exist.

Run: `cargo test --test keyring_secret_store repeated_reads_use_cached_bundle_after_first_load -- --exact`
Expected: FAIL because caching does not exist.

- [ ] **Step 3: Refactor `KeyringSecretStore` to read and write one bundled entry per profile**

Implement in `src/secrets/keyring.rs`:

- one account suffix such as `profile`
- cache map keyed by profile name
- bundled read path:
  - check cache
  - try bundled entry
  - fall back to legacy entries
  - write bundled migration entry on successful legacy load
  - delete legacy entries only after a successful migration write
- bundled write path:
  - load current bundle
  - merge field update
  - write or delete bundled entry depending on emptiness
  - refresh cache

Keep the `SecretStore` trait unchanged.

- [ ] **Step 4: Add focused regression tests for delete behavior**

Add tests proving:

- `delete_profile_secrets` removes bundled entries
- `delete_profile_secrets` also cleans up legacy entries defensively
- failed migration writes do not delete legacy entries

- [ ] **Step 5: Re-run the targeted test file**

Run: `cargo test --test keyring_secret_store`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/secrets/keyring.rs tests/keyring_secret_store.rs
git commit -m "feat: bundle and cache profile secrets in keyring"
```

### Task 3: Preserve App Edit Behavior Against Bundled Secret Storage

**Files:**
- Modify: `src/app.rs`
- Modify: `tests/profile_commands.rs`
- Modify: `tests/doctor_commands.rs`
- Modify: `tests/hostkey_commands.rs`

- [ ] **Step 1: Add failing app-level tests for partial secret edits**

Add or update tests in `tests/profile_commands.rs` for:

```rust
#[test]
fn edit_command_updates_only_password_without_clobbering_private_key() {
    let harness = TestHarness::with_profile("prod");
    harness.secrets().set_private_key("prod", "pem").unwrap();

    let args = EditArgs {
        name: "prod".into(),
        password: true,
        ..default_edit_args()
    };

    edit::run(harness.app(), &FakePrompt::with_password("new-secret"), &args, &mut Vec::new())
        .unwrap();

    assert_eq!(harness.secrets().get_password("prod").unwrap().as_deref(), Some("new-secret"));
    assert_eq!(harness.secrets().get_private_key("prod").unwrap().as_deref(), Some("pem"));
}
```

Also add a test that metadata-only edits do not rewrite or clear secrets.

- [ ] **Step 2: Run the targeted profile tests to verify they fail**

Run: `cargo test --test profile_commands edit_command_updates_only_password_without_clobbering_private_key -- --exact`
Expected: FAIL if the bundled backend or test harness behavior is not preserving partial updates yet.

- [ ] **Step 3: Adjust app secret snapshot/restore code only where needed**

Review `src/app.rs` for:

- `capture_profile_secrets`
- `apply_profile_secrets`
- rollback helpers

Keep the current external behavior, but remove any assumptions that separate keyring entries must exist independently.

Update test-only secret-store wrappers in:

- `tests/profile_commands.rs`
- `tests/doctor_commands.rs`
- `tests/hostkey_commands.rs`

only as needed to keep them aligned with the unchanged trait.

- [ ] **Step 4: Re-run the focused and full app tests**

Run: `cargo test --test profile_commands`
Expected: PASS

Run: `cargo test --test doctor_commands`
Expected: PASS

Run: `cargo test --test hostkey_commands`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/app.rs tests/profile_commands.rs tests/doctor_commands.rs tests/hostkey_commands.rs
git commit -m "fix: preserve partial secret edits with bundled storage"
```

### Task 4: Add Optional macOS Signing To The Release Workflow

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `tests/packaging_assets.rs`
- Modify: `README.md`

- [ ] **Step 1: Add failing tests for signing-aware release workflow content**

Extend `tests/packaging_assets.rs` with checks for:

```rust
assert_file_contains(
    &repo_root.join(".github/workflows/release.yml"),
    [
        "MACOS_DEVELOPER_ID_APPLICATION_P12",
        "MACOS_DEVELOPER_ID_INSTALLER_P12",
        "codesign",
        "productsign",
        "security create-keychain",
    ],
);
```

Add README expectations documenting the required GitHub secrets for signed releases.

- [ ] **Step 2: Run the packaging-assets test to verify it fails**

Run: `cargo test --test packaging_assets`
Expected: FAIL because signing steps and docs are not present.

- [ ] **Step 3: Implement optional macOS signing in `.github/workflows/release.yml`**

Add macOS-only steps to:

- detect presence of required secrets
- create and unlock a temporary keychain
- import the Developer ID Application and Installer certificates from base64-encoded `.p12` secrets
- set key partition access for `codesign` and `productsign`
- codesign `target/release/connect`
- build the `.pkg`
- sign the `.pkg` when signing is enabled

Keep the workflow functional when secrets are absent by skipping signing and continuing with unsigned packaging.

- [ ] **Step 4: Document the signing inputs in `README.md`**

Add a release-maintainer section describing:

- required GitHub secrets
- that local builds stay unsigned
- that signed tagged releases require the secrets to be configured

- [ ] **Step 5: Re-run the packaging-assets test**

Run: `cargo test --test packaging_assets`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/release.yml tests/packaging_assets.rs README.md
git commit -m "build: add optional macos signing to releases"
```

### Task 5: Final Verification And Release Readiness Check

**Files:**
- Modify: `docs/superpowers/plans/2026-03-25-connect-keychain-signing.md`

- [ ] **Step 1: Run the full verification suite**

Run: `cargo test`
Expected: PASS

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: PASS

Run: `cargo build --release`
Expected: PASS

- [ ] **Step 2: Re-read the approved spec and verify requirement coverage**

Check:

- one keychain item per profile
- merge-safe partial edits
- process-local caching
- legacy migration
- optional macOS release signing
- unchanged local unsigned build behavior

- [ ] **Step 3: Commit any final plan-aligned cleanup**

```bash
git add Cargo.toml Cargo.lock src tests .github/workflows/release.yml README.md
git commit -m "chore: finalize keychain bundling and signing work"
```

