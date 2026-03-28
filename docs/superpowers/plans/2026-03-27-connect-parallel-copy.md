# Connect Parallel Copy Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit multi-session parallel copy to `connect` so `connect copy --threads N` can accelerate both large recursive trees and large single-file transfers, while preserving resume, retry, TOFU/auth behavior, and readable progress output.

**Architecture:** Treat offset-safe random-access SFTP as a prerequisite and land that in the local `russh-sftp` checkout first. Then extend `connect` with a copy planner, a parallel executor with graceful degradation, checkpoint-backed resume/retry, and an aggregate progress renderer that stays coherent in TTY mode.

**Tech Stack:** Rust stable, `tokio`, `clap`, `russh`, local patched `russh-sftp`, `rusqlite`, `keyring`, `directories`, `assert_cmd`, `predicates`, `tempfile`, std/tokio async filesystem and task primitives

---

## File Structure

### `russh-sftp` prerequisite work

- Modify: `/Users/jneerdael/Scripts/russh-sftp/Cargo.toml`
- Modify: `/Users/jneerdael/Scripts/russh-sftp/src/client/rawsession.rs`
- Modify: `/Users/jneerdael/Scripts/russh-sftp/src/client/session.rs`
- Modify: `/Users/jneerdael/Scripts/russh-sftp/src/client/fs/file.rs`
- Create: `/Users/jneerdael/Scripts/russh-sftp/tests/random_access.rs`
- Create: `/Users/jneerdael/Scripts/russh-sftp/examples/random_access_probe.rs`

### CLI and persistence

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src/cli/types.rs`
- Modify: `src/cli/commands/add.rs`
- Modify: `src/cli/commands/edit.rs`
- Modify: `src/cli/commands/show.rs`
- Modify: `src/cli/commands/copy.rs`
- Modify: `src/app.rs`
- Modify: `src/store/db.rs`
- Modify: `src/store/models.rs`
- Modify: `src/store/mod.rs`
- Modify: `src/store/profile_store.rs`

### Copy planning, execution, and checkpoints

- Modify: `src/ssh/mod.rs`
- Modify: `src/ssh/client.rs`
- Modify: `src/ssh/copy.rs`
- Create: `src/ssh/parallel.rs`
- Create: `src/ssh/checkpoint.rs`
- Create: `src/ssh/progress.rs`

### Tests and docs

- Modify: `tests/cli_help.rs`
- Modify: `tests/profile_commands.rs`
- Modify: `tests/openssh_e2e_linux.rs`
- Create: `tests/parallel_copy_planning.rs`
- Create: `tests/parallel_copy_checkpoint.rs`
- Modify: `README.md`

## Execution Notes

- Work on the current branch in the main repo; do not create a worktree because the user explicitly asked to work in the main repo.
- There are already unrelated local changes in the `connect` worktree. Do not revert them. Keep commits narrowly scoped to the plan tasks.
- Follow TDD for every behavior change: write the failing test first, run it to confirm the failure, then implement the minimum code to pass.
- Do not start `connect` parallel-copy implementation until the `russh-sftp` offset-safe primitive work is validated and merged locally.
- Keep `--threads 1` behavior equivalent to the current copy path.
- Do not expose chunk size or stripe-threshold flags in this plan.
- Keep parallel mode opt-in only when the effective configured thread count is greater than `1`.
- Preserve partial transfer state on failure; do not auto-delete partial files or checkpoints.

### Task 1: Validate And Patch `russh-sftp` For Offset-Safe Random Access

**Files:**
- Modify: `/Users/jneerdael/Scripts/russh-sftp/src/client/rawsession.rs`
- Modify: `/Users/jneerdael/Scripts/russh-sftp/src/client/session.rs`
- Modify: `/Users/jneerdael/Scripts/russh-sftp/src/client/fs/file.rs`
- Create: `/Users/jneerdael/Scripts/russh-sftp/tests/random_access.rs`
- Create: `/Users/jneerdael/Scripts/russh-sftp/examples/random_access_probe.rs`

- [ ] **Step 1: Write failing `russh-sftp` tests for offset-addressed read/write primitives and concurrent correctness**

Add tests that model:

```rust
#[tokio::test]
async fn write_at_persists_two_disjoint_ranges() {
    let fixture = test_server().await;
    let sftp = fixture.sftp().await;

    let handle = sftp.open_random_access("/tmp/striped.bin").await.unwrap();
    handle.write_at(0, b"AAAA").await.unwrap();
    handle.write_at(8, b"BBBB").await.unwrap();

    assert_eq!(sftp.read("/tmp/striped.bin").await.unwrap(), b"AAAA\0\0\0\0BBBB");
}

#[tokio::test]
async fn read_at_returns_requested_range_without_mutating_seek_position() {
    let fixture = test_server().await;
    let sftp = fixture.sftp().await;

    let handle = sftp.open_random_access("/tmp/range.txt").await.unwrap();
    let part = handle.read_at(4, 3).await.unwrap();
    assert_eq!(part, b"456");
}

#[tokio::test]
async fn concurrent_handles_can_write_disjoint_ranges_without_corruption() {
    let fixture = test_server().await;
    let sftp = fixture.sftp().await;

    let first = sftp.open_random_access("/tmp/concurrent.bin").await.unwrap();
    let second = sftp.open_random_access("/tmp/concurrent.bin").await.unwrap();

    tokio::join!(
        first.write_at(0, b"AAAA"),
        second.write_at(4, b"BBBB"),
    );

    assert_eq!(sftp.read("/tmp/concurrent.bin").await.unwrap(), b"AAAABBBB");
}

#[tokio::test]
async fn chunked_write_and_read_reassembles_expected_bytes() {
    let fixture = test_server().await;
    let sftp = fixture.sftp().await;

    let handle = sftp.open_random_access("/tmp/assembled.bin").await.unwrap();
    for (offset, chunk) in [(0, b"abc".as_slice()), (3, b"def"), (6, b"ghi")] {
        handle.write_at(offset, chunk).await.unwrap();
    }

    let assembled = handle.read_at(0, 9).await.unwrap();
    assert_eq!(assembled, b"abcdefghi");
}
```

- [ ] **Step 2: Run the new `russh-sftp` tests to verify they fail**

Run: `cargo test --test random_access write_at_persists_two_disjoint_ranges -- --exact`
Expected: FAIL because random-access helpers do not exist yet.

Run: `cargo test --test random_access read_at_returns_requested_range_without_mutating_seek_position -- --exact`
Expected: FAIL because offset-addressed reads are not exposed yet.

Run: `cargo test --test random_access concurrent_handles_can_write_disjoint_ranges_without_corruption -- --exact`
Expected: FAIL because concurrent random-access correctness is not validated yet.

- [ ] **Step 3: Add explicit random-access helpers on top of raw SFTP requests**

Expose offset-addressed APIs from `russh-sftp` that do not rely on shared file seek state. A minimal acceptable shape is:

```rust
pub struct RandomAccessFile { /* ... */ }

impl RandomAccessFile {
    pub async fn read_at(&self, offset: u64, len: u32) -> SftpResult<Vec<u8>>;
    pub async fn write_at(&self, offset: u64, data: &[u8]) -> SftpResult<()>;
}
```

Implementation requirements:

- use raw SFTP `Read`/`Write` with explicit offsets
- do not mutate a shared `pos`
- keep the existing sequential `File` API intact
- allow multiple handles and sessions to work on distinct ranges safely
- document or encode any invariants around partial writes or maximum request sizes

- [ ] **Step 4: Add a small probe example or benchmark harness**

Create `examples/random_access_probe.rs` that opens a file, writes disjoint ranges, reads them back, and logs success. This is only for validation; do not wire it into `connect`.

- [ ] **Step 5: Re-run the `russh-sftp` targeted tests**

Run: `cargo test --test random_access`
Expected: PASS

Run: `cargo test`
Expected: PASS in `/Users/jneerdael/Scripts/russh-sftp`

- [ ] **Step 6: Commit the `russh-sftp` prerequisite**

```bash
cd /Users/jneerdael/Scripts/russh-sftp
git add Cargo.toml src tests examples
git commit -m "feat: add random-access sftp file primitives"
```

### Task 2: Point `connect` At The Patched `russh-sftp` And Add Thread Count Surface

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src/cli/types.rs`
- Modify: `src/cli/commands/add.rs`
- Modify: `src/cli/commands/edit.rs`
- Modify: `src/cli/commands/show.rs`
- Modify: `src/cli/commands/copy.rs`
- Modify: `src/store/db.rs`
- Modify: `src/store/models.rs`
- Modify: `src/store/mod.rs`
- Modify: `src/store/profile_store.rs`
- Modify: `src/app.rs`
- Modify: `tests/cli_help.rs`
- Modify: `tests/profile_commands.rs`

- [ ] **Step 1: Write failing CLI and profile tests for copy thread count and retry flags**

Add tests for:

```rust
#[test]
fn copy_help_lists_threads_and_retry_flags() {
    connect_test_bin()
        .args(["copy", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--threads"))
        .stdout(predicates::str::contains("--retry"));
}

#[tokio::test]
async fn add_and_show_round_trip_copy_thread_count_default() {
    let harness = TestHarness::with_profile("prod");
    harness.app().save_profile(
        ProfileInput::new("prod", "prod.example.com", "deploy").with_copy_threads(4)
    ).unwrap();

    let shown = harness.app().get_profile("prod").unwrap();
    assert_eq!(shown.copy_threads, 4);
}

#[tokio::test]
async fn copy_uses_cli_threads_override_instead_of_profile_default() {
    // save profile with copy_threads = 4, then parse copy args with --threads 2
    // assert effective request becomes 2
}

#[tokio::test]
async fn copy_threads_one_preserves_single_stream_mode() {
    // save profile with copy_threads = 1 and assert planning stays baseline
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test --test cli_help copy_help_lists_threads_and_retry_flags -- --exact`
Expected: FAIL because the flags do not exist yet.

Run: `cargo test --test profile_commands add_and_show_round_trip_copy_thread_count_default -- --exact`
Expected: FAIL because the profile field does not exist yet.

Run: `cargo test --test profile_commands copy_uses_cli_threads_override_instead_of_profile_default -- --exact`
Expected: FAIL because effective thread resolution is not wired yet.

Run: `cargo test --test profile_commands copy_threads_one_preserves_single_stream_mode -- --exact`
Expected: FAIL because the invariant is not expressed yet.

- [ ] **Step 3: Wire a portable patched `russh-sftp` dependency strategy**

During local implementation, it is acceptable to use a temporary local patch override. Before this task is complete, replace it with a portable dependency source that works in CI, packaging, and installer builds, such as:

- a pinned git revision from a maintained fork
- or an upstream release if the patch is merged before finalization

Do not leave a `/Users/...` path dependency in the final `connect` tree.

- [ ] **Step 4: Add `--threads` and `--retry` to the copy CLI**

Extend the copy args to include:

```rust
pub struct CopyArgs {
    pub recursive: bool,
    pub resume: bool,
    pub retry: bool,
    pub threads: Option<usize>,
    pub progress: bool,
    pub source: String,
    pub destination: String,
}
```

Validate:

- `--threads 0` is rejected
- absent means “use profile default or 1”
- CLI override resolution is covered here so later planner/executor tasks can rely on it

- [ ] **Step 5: Add user-facing profile configuration for default copy thread count**

Extend:

- `connect add` with an optional copy-thread setting
- `connect edit` with an optional copy-thread setting
- `connect show` so the saved default is visible

Keep the semantics simple:

- unset means default `1`
- explicit CLI `--threads` always overrides the saved profile value
- `connect show` displays the saved default thread count

- [ ] **Step 6: Add profile persistence for default copy thread count**

Add a nullable/integer `copy_threads` field to profile storage and migration logic, defaulting to `1` for existing profiles.

- [ ] **Step 8: Re-run the targeted tests**

Run: `cargo test --test cli_help copy_help_lists_threads_and_retry_flags -- --exact`
Expected: PASS

Run: `cargo test --test profile_commands add_and_show_round_trip_copy_thread_count_default -- --exact`
Expected: PASS

Run: `cargo test --test profile_commands copy_uses_cli_threads_override_instead_of_profile_default -- --exact`
Expected: PASS

Run: `cargo test --test profile_commands copy_threads_one_preserves_single_stream_mode -- --exact`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock src tests
git commit -m "feat: add threaded copy cli and profile settings"
```

### Task 3: Add A Copy Planner For Single-Session, Queued, And Striped Plans

**Files:**
- Modify: `src/ssh/copy.rs`
- Create: `src/ssh/parallel.rs`
- Create: `tests/parallel_copy_planning.rs`

- [ ] **Step 1: Write failing planner tests**

Add tests for:

```rust
#[test]
fn planner_keeps_single_session_mode_when_effective_threads_is_one() {
    let plan = plan_copy(copy_spec_single_file(), PlannerConfig::new(1)).unwrap();
    assert!(matches!(plan.mode, CopyPlanMode::SingleStream));
}

#[test]
fn planner_stripes_large_single_file_when_threads_exceed_one() {
    let plan = plan_copy(copy_spec_large_file(), PlannerConfig::new(4)).unwrap();
    assert!(matches!(plan.mode, CopyPlanMode::StripedFile { .. }));
}

#[test]
fn planner_mixes_file_queue_and_striped_large_files_for_recursive_trees() {
    let plan = plan_copy(copy_spec_recursive_tree(), PlannerConfig::new(8)).unwrap();
    assert!(plan.jobs.iter().any(|job| matches!(job, CopyJob::StripedFile { .. })));
    assert!(plan.jobs.iter().any(|job| matches!(job, CopyJob::WholeFile { .. })));
}
```

- [ ] **Step 2: Run the planner tests to verify they fail**

Run: `cargo test --test parallel_copy_planning`
Expected: FAIL because the planner types do not exist yet.

- [ ] **Step 3: Add planner types and logic**

Introduce focused planning types in `src/ssh/copy.rs`:

- `CopyPlannerConfig`
- `CopyPlan`
- `CopyPlanMode`
- `CopyJob`
- `ChunkRange`

Planner rules:

- effective threads `<= 1` => current single-stream mode
- threaded single-file => striped plan
- threaded recursive => shared whole-file queue plus striped jobs for large files
- stripe threshold remains internal, not user-configurable
- apply resume/retry policy at planning time
- compute chunk boundaries for striped files
- initialize checkpoint identity inputs for later execution

Ownership split:

- `src/ssh/copy.rs` owns the copy spec, planning logic, and job-model types
- `src/ssh/parallel.rs` owns the threaded runtime/executor only

- [ ] **Step 4: Re-run the planner tests**

Run: `cargo test --test parallel_copy_planning`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ssh/copy.rs src/ssh/parallel.rs tests/parallel_copy_planning.rs
git commit -m "feat: add parallel copy planning"
```

### Task 4: Implement Parallel Session Establishment And Graceful Degradation

**Files:**
- Modify: `src/ssh/client.rs`
- Modify: `src/ssh/mod.rs`
- Modify: `src/ssh/parallel.rs`
- Modify: `tests/profile_commands.rs`
- Modify: `tests/openssh_e2e_linux.rs`

- [ ] **Step 1: Write failing tests for degraded session establishment**

Add tests for:

```rust
#[tokio::test]
async fn threaded_copy_warns_and_degrades_when_only_subset_of_sessions_connect() {
    let ssh = FakeParallelSshClient::with_connect_limit(2);
    let result = run_threaded_copy_with_threads(4, &ssh).await.unwrap();
    assert_eq!(result.effective_threads, 2);
    assert!(result.warnings.iter().any(|w| w.contains("degraded")));
}

#[tokio::test]
async fn threaded_copy_fails_when_requested_parallelism_degrades_to_one_session() {
    let ssh = FakeParallelSshClient::with_connect_limit(1);
    let error = run_threaded_copy_with_threads(4, &ssh).await.unwrap_err();
    assert!(error.to_string().contains("could not establish threaded mode"));
}

#[tokio::test]
async fn threaded_copy_fails_clearly_when_random_access_support_is_unavailable() {
    let ssh = FakeParallelSshClient::without_random_access_support();
    let error = run_threaded_copy_with_threads(4, &ssh).await.unwrap_err();
    assert!(error.to_string().contains("random-access sftp support is unavailable"));
}

#[tokio::test]
async fn single_session_retry_retries_transient_copy_failures() {
    let ssh = FakeParallelSshClient::single_session_with_transient_failure();
    run_copy_with_threads(1, retry: true, &ssh).await.unwrap();
}
```

- [ ] **Step 2: Run the targeted test to verify it fails**

Run: `cargo test --test profile_commands threaded_copy_warns_and_degrades_when_only_subset_of_sessions_connect -- --exact`
Expected: FAIL because parallel session establishment does not exist yet.

- [ ] **Step 3: Add session-pool establishment with degradation**

Implementation requirements:

- request up to `N` authenticated transfer sessions
- verify random-access SFTP support before entering threaded execution
- if some fail due to connection/server limits, continue with the successful subset
- if the successful subset is exactly one session for a `--threads > 1` request, return a clear error instead of silently falling back
- if zero succeed, return an error
- expose effective thread count and warnings to the copy summary/reporting path
- once the real session count is known, re-finalize the execution plan against that effective thread count before scheduling work
- for effective thread count `1`, `--retry` still applies in single-session mode and should retry transient copy failures without invoking threaded execution

- [ ] **Step 4: Add or extend Linux OpenSSH integration coverage**

Add a Linux-only test that requests more sessions than the harness allows and verifies graceful degradation or a controlled warning path.

- [ ] **Step 5: Re-run focused tests**

Run: `cargo test --test profile_commands threaded_copy_warns_and_degrades_when_only_subset_of_sessions_connect -- --exact`
Expected: PASS

Run: `cargo test --test openssh_e2e_linux`
Expected: PASS on Linux hosts; compile-only elsewhere if gated

- [ ] **Step 6: Commit**

```bash
git add src/ssh/client.rs src/ssh/mod.rs src/ssh/parallel.rs tests
git commit -m "feat: add degraded parallel ssh session pool"
```

### Task 5: Implement Threaded Single-File Upload And Download With Checkpoints

**Files:**
- Modify: `src/app.rs`
- Modify: `src/ssh/client.rs`
- Modify: `src/ssh/copy.rs`
- Create: `src/ssh/checkpoint.rs`
- Create: `tests/parallel_copy_checkpoint.rs`
- Modify: `tests/openssh_e2e_linux.rs`

- [ ] **Step 1: Write failing checkpoint and threaded single-file tests**

Add tests for:

```rust
#[test]
fn checkpoint_tracks_non_contiguous_completed_ranges() {
    let mut checkpoint = TransferCheckpoint::new(total_len: 100);
    checkpoint.mark_complete(0..25);
    checkpoint.mark_complete(50..75);
    assert_eq!(checkpoint.remaining_ranges(), vec![25..50, 75..100]);
}

#[tokio::test]
async fn threaded_upload_resumes_only_missing_ranges() {
    // simulate completed chunks and verify only missing ranges are scheduled
}

#[test]
fn incompatible_checkpoint_state_is_rejected() {
    let checkpoint = fixture_checkpoint_for("old-source-hash", total_len: 100);
    let error = checkpoint.validate_against("new-source-hash", 100).unwrap_err();
    assert!(error.to_string().contains("checkpoint state is incompatible"));
}

#[tokio::test]
async fn retry_requeues_transient_chunk_failures_but_not_fatal_ones() {
    // simulate one transient chunk failure and one fatal mismatch
    // expect transient work to be requeued and fatal work to abort
}

#[test]
fn checkpoint_path_is_stable_for_source_destination_and_direction() {
    let path = checkpoint_path_fixture();
    assert!(path.ends_with(".json"));
}

#[test]
fn checkpoint_identity_includes_transfer_mode() {
    let upload = checkpoint_identity_fixture("upload-threaded");
    let download = checkpoint_identity_fixture("download-threaded");
    assert_ne!(upload, download);
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test --test parallel_copy_checkpoint`
Expected: FAIL because checkpoint logic does not exist yet.

- [ ] **Step 3: Add checkpoint model and persistence**

Implement:

- per-transfer checkpoint identity
- file identity validation material sufficient to reject incompatible resumes
- transfer-mode scoping so different copy modes do not collide on the same checkpoint key
- explicit checkpoint path plumbing from the app/app-path layer into copy execution
- completed-range tracking
- load/save/delete lifecycle
- removal on successful completion

Use client-local storage only in this task.

- [ ] **Step 4: Add checkpoint path plumbing through the app/copy boundary**

Make the copy path receive an explicit checkpoint root/path provider from `src/app.rs` using the existing `AppPaths` support. Do not let `src/ssh/checkpoint.rs` guess global paths internally.

- [ ] **Step 5: Add striped chunk scheduling without resume/retry first**

Implement:

- striped chunk scheduling
- offset-based upload/download through multiple transfer sessions
- partial-file preservation on failure

- [ ] **Step 6: Add checkpoint-backed resume validation and missing-range scheduling**

Implement:

- `--resume` support via checkpoint state
- incompatible checkpoint state must fail clearly before transfer starts
- scheduling of only incomplete ranges

- [ ] **Step 7: Add transient retry requeue for single-file threaded copy**

Implement:

- `--retry` requeue of transient failures
- fatal retry cases still abort clearly

- [ ] **Step 8: Add Linux OpenSSH end-to-end tests for threaded single-file copy**

Add upload/download tests that:

- use `--threads > 1`
- verify final content
- inject interruption and verify `--resume` completes successfully
- inject a transient failure path and verify `--retry` completes successfully

- [ ] **Step 9: Re-run focused tests**

Run: `cargo test --test parallel_copy_checkpoint`
Expected: PASS

Run: `cargo test --test openssh_e2e_linux threaded`
Expected: PASS on Linux

- [ ] **Step 10: Commit**

```bash
git add src/ssh/client.rs src/ssh/copy.rs src/ssh/checkpoint.rs tests
git commit -m "feat: add threaded single-file copy with checkpoints"
```

### Task 6: Implement Recursive Queue Scheduling, Large-File Striping, And `--retry`

**Files:**
- Modify: `src/ssh/copy.rs`
- Modify: `src/ssh/parallel.rs`
- Modify: `src/ssh/checkpoint.rs`
- Modify: `tests/profile_commands.rs`
- Modify: `tests/openssh_e2e_linux.rs`

- [ ] **Step 1: Write failing recursive threaded copy tests**

Add tests for:

```rust
#[tokio::test]
async fn recursive_threaded_copy_processes_multiple_files_and_large_file_chunks() {
    // assert mixed queue behavior and final summary accounting
}

#[tokio::test]
async fn recursive_retry_requeues_failed_files_without_recopying_completed_ones() {
    // inject one transient failure and verify retry resumes useful work only
}

#[tokio::test]
async fn recursive_retry_reports_fatal_failures_without_looping_forever() {
    // inject a non-retryable failure and verify the run exits with a clear summary
}

#[tokio::test]
async fn recursive_resume_skips_completed_files_and_resumes_partial_striped_files() {
    // seed completed files plus checkpointed large-file chunks
    // assert completed files are skipped and only missing striped ranges are scheduled
}

#[tokio::test]
async fn recursive_threaded_copy_creates_parent_directories_before_child_writes() {
    // assert directory creation jobs/writes preserve parent-before-child ordering
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test --test profile_commands recursive_threaded_copy_processes_multiple_files_and_large_file_chunks -- --exact`
Expected: FAIL because recursive threaded execution does not exist yet.

- [ ] **Step 3: Implement recursive whole-file queueing first**

Requirements:

- shared file queue for whole-file jobs
- completed files remain completed

- [ ] **Step 4: Add striped large-file jobs inside recursive trees**

Requirements:

- striped jobs for large files inside the tree
- total worker count remains capped by the effective thread count

- [ ] **Step 5: Add recursive `--resume` behavior**

Requirements:

- remove the old recursive `--resume` parse-time rejection in `src/ssh/copy.rs` and `tests/copy_path_parsing.rs`
- completed files are skipped
- partially copied striped files resume from checkpoint state where safe

- [ ] **Step 6: Add parent-directory ordering guarantees**

Requirements:

- parent directories are created before child file writes are scheduled/executed
- ordering is covered by targeted tests, not only e2e runs

- [ ] **Step 7: Add recursive `--retry` behavior and final failure accounting**

Requirements:

- transient file/chunk failures retry in-run
- fatal failures surface clearly
- failed files accumulate in the final summary

- [ ] **Step 8: Add Linux OpenSSH end-to-end coverage for recursive threaded copy**

Add tests for:

- threaded recursive upload
- threaded recursive download
- interrupted recursive copy followed by `--resume`
- transient recursive failures recovered by `--retry`

- [ ] **Step 9: Re-run focused tests**

Run: `cargo test --test profile_commands recursive_threaded_copy_processes_multiple_files_and_large_file_chunks -- --exact`
Expected: PASS

Run: `cargo test --test openssh_e2e_linux`
Expected: PASS on Linux hosts

- [ ] **Step 10: Commit**

```bash
git add src/ssh/copy.rs src/ssh/parallel.rs src/ssh/checkpoint.rs tests
git commit -m "feat: add threaded recursive copy"
```

### Task 7: Add Aggregate Progress Reporting And Final Summaries

**Files:**
- Create: `src/ssh/progress.rs`
- Modify: `src/ssh/client.rs`
- Modify: `src/ssh/copy.rs`
- Modify: `tests/profile_commands.rs`
- Modify: `README.md`

- [ ] **Step 1: Write failing progress and summary tests**

Add tests for:

```rust
#[test]
fn threaded_interactive_progress_renders_one_aggregate_line() {
    let output = render_threaded_progress_fixture();
    assert!(output.contains("\\r"));
    assert_eq!(output.matches('\n').count(), 1);
}

#[test]
fn threaded_summary_reports_effective_thread_count_and_failures() {
    let summary = threaded_summary_fixture();
    assert!(summary.contains("threads: 3"));
    assert!(summary.contains("failed files: 1"));
}

#[test]
fn threaded_summary_reports_resumed_bytes_and_degradation_warning() {
    let summary = threaded_summary_fixture();
    assert!(summary.contains("resumed"));
    assert!(summary.contains("degraded"));
}

#[tokio::test]
async fn explicit_non_interactive_progress_uses_snapshots_only_when_requested() {
    let output = render_non_interactive_progress_fixture(explicit_progress: true).await;
    assert!(output.contains('\n'));

    let hidden = render_non_interactive_progress_fixture(explicit_progress: false).await;
    assert_eq!(hidden, "");
}

#[tokio::test]
async fn threaded_recursive_progress_does_not_emit_per_file_lines() {
    let output = render_recursive_progress_fixture().await;
    assert_eq!(output.matches('\n').count(), 1);
}

#[tokio::test]
async fn real_threaded_copy_path_emits_one_aggregate_tty_line() {
    // run a threaded copy through the real copy path with a fake tty sink
    // assert one final newline and no per-worker/per-file line spam
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test threaded_interactive_progress_renders_one_aggregate_line --lib`
Expected: FAIL because the aggregate reporter does not exist yet.

- [ ] **Step 3: Move threaded progress aggregation into its own focused module**

Requirements:

- one aggregate interactive line
- no per-worker line spam
- no per-file line spam during threaded recursive copy
- newline-delimited snapshots only in non-interactive progress mode
- resumed byte counts and degradation warnings wired into the final summary

- [ ] **Step 4: Update final summaries and docs**

Summaries must include:

- bytes copied
- resumed bytes
- effective thread count
- degradation warning when applicable
- failed-file count for recursive partial failure

Document `--threads` and `--retry` in `README.md`.

- [ ] **Step 5: Re-run focused tests**

Run: `cargo test threaded_interactive_progress_renders_one_aggregate_line --lib`
Expected: PASS

Run: `cargo test --test profile_commands`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/ssh/progress.rs src/ssh/client.rs src/ssh/copy.rs tests README.md
git commit -m "feat: add aggregate threaded copy progress"
```

### Task 8: Final Verification And Cleanup Of Copy Command Surface

**Files:**
- Modify: `tests/cli_help.rs`
- Modify: `tests/openssh_e2e_linux.rs`
- Modify: `README.md`

- [ ] **Step 1: Add final CLI/help and integration expectations**

Ensure tests cover:

- `copy --threads`
- `copy --retry`
- profile-default thread count overridden by CLI
- `--threads 1` preserving current behavior

- [ ] **Step 2: Run the complete verification suite**

Run: `cargo fmt -- --check`
Expected: PASS

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: PASS

Run: `cargo test`
Expected: PASS

Run: `cargo build --release`
Expected: PASS

If running on Linux:

Run: `cargo test --test openssh_e2e_linux`
Expected: PASS

- [ ] **Step 3: Update docs for any final behavior adjustments**

Make sure `README.md` documents:

- `--threads`
- `--retry`
- interaction with `--resume`
- degradation behavior
- the fact that threaded mode is opt-in only

- [ ] **Step 4: Commit**

```bash
git add README.md tests src Cargo.toml Cargo.lock
git commit -m "docs: finalize threaded copy support"
```
