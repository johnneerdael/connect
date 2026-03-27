# `connect` Design: Parallel Copy Over Multiple SSH/SFTP Sessions

## Summary

This design adds explicit multi-session parallel copy to `connect` so users can accelerate both:

- large recursive file-tree transfers
- large single-file transfers

The feature is opt-in through `connect copy --threads <N>`. Threaded mode is never enabled automatically unless the effective configured thread count is greater than `1`. This keeps current behavior unchanged for normal copies and avoids surprising failures against servers that do not tolerate multiple concurrent SSH connections.

The design follows the mechanism described in the PEARC 2023 paper _Multi-threaded scp: Easy and Fast File Transfer over SSH_, which uses multiple SSH/SFTP connections and offset-based reads/writes to transfer different file regions concurrently. In `connect`, the parallel feature will be built on standard `sshd` and SFTP only, preserving the existing profile, TOFU host-key, auth-mode, keychain, and installer model.

## Goals

- Add `--threads <N>` to `connect copy`
- Support faster recursive tree copy by processing multiple files concurrently
- Support faster large single-file upload and download by striping file ranges across workers
- Keep `--threads 1` behavior equivalent to current copy behavior
- Preserve partial results on failure so `--resume` and retry flows remain useful
- Add `--retry` so the current command can automatically retry transient failures and resume unfinished work where safe
- Degrade gracefully when the requested number of parallel SSH/SFTP sessions cannot be established
- Keep progress output coherent and compact in TTY mode

## Non-goals

- Remote-to-remote copy
- Background transfer daemons
- Auto-enabling threaded mode without an explicit thread count above `1`
- Exposing chunk-size or stripe-threshold tuning flags in the first version
- Parallelizing interactive shell or `exec`
- Remote-side agent processes or custom server software

## User-Facing Behavior

### CLI changes

`connect copy` gains:

- `--threads <N>`
- `--retry`

Examples:

- `connect copy --threads 8 large.iso prod:/data/large.iso`
- `connect copy -r --threads 12 repo/ prod:~/repo`
- `connect copy --threads 6 --resume --retry prod:/data/db.dump ./db.dump`

### Thread-count semantics

- `--threads 1` means current single-session copy behavior
- `--threads > 1` enables parallel transfer planning and execution
- Profiles may store a default copy thread count
- CLI `--threads` overrides the profile default
- Effective runtime concurrency may be lower than requested if the server or network cannot sustain the requested number of sessions

If degradation happens, `connect` continues with the reduced effective concurrency and emits a clear warning.

### Retry and resume semantics

- `--resume`
  - reuse existing partial state and continue unfinished work where safe
- `--retry`
  - retry transient failures during the current invocation
  - for threaded transfers, retries resume unfinished chunks/files instead of restarting from scratch when possible

For single-file threaded transfers, partial destination files are preserved on failure.

For recursive tree transfers:

- completed files remain completed
- failed files are summarized at the end
- `--retry` retries failed files during the same run
- `--resume` skips already complete files and resumes partially copied large files where safe

## Architecture

The feature is split into three layers.

### 1. `russh-sftp` capability validation and patching

This is a prerequisite workstream.

The current high-level file API in `russh-sftp` is sequential and position-based. Threaded single-file striping requires explicit offset-stable random access that does not depend on shared seek state.

Before implementing parallel copy in `connect`, validate whether `russh-sftp` already supports robust concurrent offset-based transfer primitives. If it does not, patch the library first.

Preferred outcome:

- explicit `read_at` / `write_at` style primitives, or equivalent offset-addressed helpers
- safe use across multiple handles and/or multiple SFTP sessions
- tests that verify correctness under concurrent chunked upload/download

`connect` should depend on the patched `russh-sftp` implementation rather than building a fragile workaround around the current sequential `File` abstraction.

### 2. Copy planner

The planner inspects the copy request and builds an execution plan.

Plan shapes:

- single-file, single-session
- single-file, striped
- recursive tree with queued file jobs
- recursive tree with mixed queued file jobs and striped large-file jobs

Planner responsibilities:

- determine effective thread count
- account for connection degradation
- decide whether a file is striped or assigned to one worker
- apply resume/retry policy
- compute chunk boundaries for striped files
- initialize checkpoint state for resumable threaded transfers

### 3. Parallel executor

The executor owns:

- up to `N` authenticated SSH/SFTP transfer sessions
- a shared work queue
- worker tasks
- centralized progress aggregation

Worker model:

- file workers process whole-file jobs from the shared queue
- chunk workers process disjoint byte-range jobs for striped files
- the total number of active transfer workers never exceeds the effective thread budget

## Transfer Model

### Recursive trees

For recursive trees, the fastest model is hybrid:

- breadth across many files using a shared file queue
- internal striping for large files inside the tree

Rules:

- small and medium files transfer as one file per worker
- large files above an internal stripe threshold are split into chunk jobs
- stripe threshold is internal only in the first version
- total concurrency is still capped by the effective thread count

Directory creation remains ordered enough to ensure parent directories exist before child files are written.

### Large single files

For a large single file in threaded mode:

- create or open the destination file
- divide the file into disjoint chunk ranges
- assign chunk ranges to workers
- perform offset-based reads/writes through multiple SSH/SFTP sessions
- finalize metadata only after the whole file completes successfully

The current implementation should not expose chunk tuning knobs. Chunk size and striping threshold remain internal heuristics.

## Session Management

Threaded mode uses multiple SSH/SFTP sessions, not one session with multiplexed copy only.

Rules:

- session establishment reuses the same profile resolution, auth precedence, TOFU host-key verification, and keepalive behavior as current copy
- requested session count equals requested thread count
- actual active session count may be reduced if the server refuses additional connections or connection attempts repeatedly fail
- degradation must be visible to the user but non-fatal unless no transfer session can be established at all

The user-visible meaning of `--threads N` is therefore:

- try up to `N` parallel transfer sessions/workers
- continue with fewer if necessary

## Checkpointing and Resume

Plain destination file size is not sufficient for reliable threaded single-file resume because chunk completion is not guaranteed to be contiguous.

Therefore, threaded resume requires checkpoint state.

First-version checkpoint model:

- store checkpoint state locally on the client
- upload:
  - local checkpoint records completed remote chunk ranges
- download:
  - local checkpoint records completed local chunk ranges

Checkpoint state should be:

- scoped to a source/destination pair plus transfer mode
- removed on successful completion
- left intact on failure for later `--resume`

Recursive-copy resume rules:

- whole files already copied successfully are skipped
- partially copied striped files use checkpoint state
- failed files are resumable when checkpoint state exists and file identity is still compatible

## Failure Handling

### Single-file threaded copy

- keep partial destination file on failure
- keep checkpoint state on failure
- `--retry` requeues unfinished chunks after transient worker/session errors
- fatal incompatibility errors still abort the transfer

### Recursive copy

- do not delete already successful files if later files fail
- accumulate per-file failures
- present a final partial-failure summary
- `--retry` retries failed work during the same invocation

### Unsupported cases

If a required prerequisite for safe threaded behavior is unavailable, `connect` must fail clearly rather than silently falling back to unsafe logic.

Examples:

- patched random-access `russh-sftp` capability not available
- checkpoint state incompatible with current source or destination
- server allows only one session and no effective threaded mode can be established above baseline

## Progress Reporting

TTY progress must remain compact and coherent.

Rules:

- one aggregate progress line in interactive mode
- no per-worker line spam
- no per-file line spam during threaded recursive copy
- final summary includes:
  - bytes transferred
  - resumed bytes
  - effective thread count
  - any degraded session warning
  - failed-file count for recursive partial failures

Non-interactive output may emit stable newline-delimited progress snapshots when explicitly requested.

## Data Model Changes

Profiles gain an optional default copy thread count.

Requirements:

- default absent or `1` means current behavior
- command-line `--threads` overrides the saved default
- migration for existing profiles defaults to `1`

No secret-storage changes are required for this feature.

## Proposed Module Boundaries

`connect` changes:

- `src/cli/`
  - parse `--threads` and `--retry`
- `src/store/`
  - persist default copy thread count
- `src/ssh/copy.rs`
  - planner and job model
- `src/ssh/client.rs`
  - session capabilities used by the executor
- new internal executor/checkpoint modules as needed

`russh-sftp` changes:

- explicit random-access transfer primitives
- correctness tests for offset-based concurrent operations
- optional benchmark/prototype code to validate large-file striping

## Testing Plan

### `russh-sftp`

- unit/integration tests for offset-based `read_at` / `write_at` behavior
- concurrent correctness tests across multiple handles/sessions
- regression tests for chunked write/read assembly

### `connect`

- CLI parsing tests:
  - `copy --threads`
  - `copy --retry`
  - profile default thread count override behavior
- planner tests:
  - single-file vs striped planning
  - recursive queue plus striping decisions
  - degradation behavior
- checkpoint tests:
  - single-file threaded resume
  - recursive resume with completed and partial files
- progress tests:
  - one aggregate interactive line
  - non-interactive progress snapshots
- Linux end-to-end integration tests with OpenSSH:
  - threaded single-file upload/download
  - threaded recursive upload/download
  - degradation when connection count is limited
  - retry/resume after injected interruption

## Risks and Mitigations

### Risk: `russh-sftp` high-level API is not suitable for striped transfer

Mitigation:

- validate and patch the library first
- do not proceed with `connect` threaded single-file support until offset-safe primitives are available

### Risk: too many sessions overwhelm the server

Mitigation:

- explicit opt-in only
- graceful degradation
- clear warning with effective concurrency

### Risk: broken resume for sparse or non-contiguous completion

Mitigation:

- use checkpoint state instead of file-size-only logic for threaded single-file resume

### Risk: progress output becomes unreadable

Mitigation:

- one centralized aggregate renderer
- no per-worker interactive lines

## Acceptance Criteria

- `connect copy --threads N` works for both recursive trees and large single files
- `--threads 1` matches current single-session behavior
- threaded mode is only used when the effective requested thread count is greater than `1`
- server connection limits degrade concurrency with a warning instead of immediately failing
- threaded failures preserve partial data and support `--resume`
- `--retry` retries unfinished work automatically where safe
- interactive progress remains compact and does not emit line spam
- `russh-sftp` random-access support is validated or patched before `connect` depends on it
