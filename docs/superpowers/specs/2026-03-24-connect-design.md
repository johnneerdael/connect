# Connect Design

**Date:** 2026-03-24

## Goal

Build a simple cross-platform Rust CLI named `connect` that manages SSH connection profiles securely, opens SSH sessions using stored settings, and supports file transfers without depending on external `ssh` or `scp` binaries at runtime.

## Non-Goals

- Replacing the user's global OpenSSH configuration model
- Multi-user shared profile storage
- Agent forwarding, port forwarding, or SSH config parity in the first release
- Background daemon processes or GUI configuration tooling

## Product Summary

`connect` is a single-user CLI for Windows, macOS, and Linux. It stores connection metadata locally, stores secrets and imported private keys in the OS-native secret store, and embeds SSH/SCP support directly in Rust. Users can add, edit, remove, list, inspect, and connect to named profiles. The tool uses trust on first use for host key verification: on the first connection, it displays the remote host fingerprint, asks for confirmation, and stores the accepted host key for future validation. Users can also view and delete saved host keys.

## User Experience

### Primary commands

- `connect <name>`
- `connect add <name>`
- `connect edit <name>`
- `connect remove <name>`
- `connect list`
- `connect show <name>`
- `connect copy [--recursive] <source> <destination>`
- `connect hostkeys list`
- `connect hostkeys delete <id>`
- `connect completion <shell>`
- `connect version`

### Connection model

Each connection profile includes:

- profile name
- host or FQDN
- port, default `22`
- username
- auth mode metadata indicating password, private key, or both are available

Sensitive values are not stored in the profile document. Passwords and private keys are imported once and stored only in the OS secret store. If the user supplies a private key path while adding or editing a profile, `connect` reads the file immediately, stores the key securely, and does not depend on the path afterward. The original file is not modified or deleted.

### File copy model

`connect copy` accepts local paths and remote paths using profile-qualified syntax:

- local path example: `./artifact.tgz`
- remote path example: `prod:/var/tmp/artifact.tgz`

Rules:

- exactly one side must be remote
- `--recursive` is required when copying directories
- single-file transfer should work without `--recursive`
- remote-to-local and local-to-remote are both supported

## Storage Design

### Non-sensitive config

Store application data in platform-appropriate per-user locations, split between config-style metadata and local data where the platform conventions differ:

- Windows: `%APPDATA%\\connect`
- macOS: `~/Library/Application Support/connect`
- Linux config: `$XDG_CONFIG_HOME/connect` or `~/.config/connect`
- Linux data: `$XDG_DATA_HOME/connect` or `~/.local/share/connect`

The profile store should use a readable structured format or embedded database. For the first release, a small embedded database is preferred because it gives stable updates, uniqueness constraints, and cleaner host key indexing. Candidate choice: SQLite via a Rust crate.

Stored metadata:

- profile id
- unique profile name
- host
- port
- username
- booleans or enum describing available auth material
- timestamps for created and updated

### Secrets

Use the OS-native keychain/keyring for:

- profile passwords
- imported private keys
- optional key passphrases

Secret entries should be namespaced so they can be deleted cleanly when a profile is removed.

### Host keys

Persist accepted host keys in the local app data store, separate from secrets. Host key trust is global per `host + port`, not per profile. If multiple profiles target the same `host:port`, they share the same accepted host key record. Each saved host key record should include:

- host
- port
- key algorithm
- fingerprint
- raw public host key representation needed for future verification
- accepted timestamp

Profile removal does not delete host keys automatically, because the trust record is scoped to the remote endpoint rather than a specific profile. Host keys are removed only through explicit host key management commands.

The CLI must allow listing and deleting these records.

## Security Model

### Authentication

- Password authentication is supported when a password secret exists for the profile.
- Private key authentication is supported when an imported private key exists for the profile.
- If both are present, `connect` tries private key authentication first and falls back to password authentication only if key authentication is rejected by the server or the imported key cannot be used successfully.
- The first release does not need per-command auth override flags; deterministic default behavior is sufficient.

### Host key verification

Trust on first use flow:

1. User invokes `connect <name>` or `connect copy ...`.
2. If no host key is stored for the target host and port, the CLI fetches the server host key and displays:
   - host and port
   - key algorithm
   - fingerprint
3. User confirms acceptance interactively.
4. The accepted host key is stored.
5. Future connections verify the received host key against the stored record and fail on mismatch.

The CLI must expose host key management commands so users can inspect and remove stale records.

### Secure handling

- Secrets are never printed in logs or help text.
- `connect show <name>` must redact sensitive presence details rather than printing secret values.
- Removal of a profile deletes all associated secrets for that profile and leaves shared host key records unchanged.

## CLI Design

Use a mature Rust CLI crate to provide:

- hierarchical help text
- shell completions
- validation errors with clear remediation
- consistent subcommand structure

Command behavior:

- `connect add <name>` should support flags plus interactive prompting for missing values.
- `connect edit <name>` should support updating one or more fields without requiring full re-entry.
- `connect remove <name>` should confirm unless `--yes` is supplied.
- `connect list` prints concise summaries.
- `connect show <name>` prints stored metadata and credential availability, not secret contents.
- `connect <name>` opens an interactive SSH session attached to the user's terminal.
- `connect copy` reuses the same profile resolution and host key verification flow.

## Architecture

### Proposed modules

- `src/main.rs`
  - CLI entry point and top-level error reporting
- `src/cli/`
  - command definitions, argument parsing, help text
- `src/app/`
  - orchestrates profile operations, connection startup, copy operations
- `src/store/`
  - profile and host key persistence
- `src/secrets/`
  - OS keychain integration
- `src/ssh/`
  - embedded SSH session management, authentication, host key retrieval and verification
- `src/copy/`
  - file and directory transfer helpers
- `src/terminal/`
  - terminal attachment, prompts, confirmations, and interactive I/O handling
- `tests/`
  - CLI and storage integration coverage

### Key libraries

Expected crate categories:

- CLI parsing and help generation
- OS keyring integration
- embedded database or structured persistence
- SSH client support with host key inspection
- terminal interaction for prompts and attached sessions
- installer/packaging tooling for cross-platform release artifacts

Crate selection needs confirmation during implementation planning based on current maintenance and platform support.

## Error Handling

The first release should provide actionable errors for:

- duplicate profile names
- missing required connection fields
- invalid hostnames or ports
- failed key import
- failed secret store access
- host key mismatch
- unsupported copy mode such as remote-to-remote transfer
- authentication failure
- missing local source path
- recursive flag missing for directory copy

Errors should clearly distinguish between profile lookup problems, local configuration problems, and remote connection problems.

## Testing Strategy

### Unit tests

- profile validation
- secret reference lifecycle behavior
- host key record CRUD
- path parsing for `connect copy`
- command argument validation

### Integration tests

- add, edit, show, list, and remove profile flows
- secret import behavior using a test abstraction around keyring access
- TOFU acceptance and host key mismatch flows
- copy source and destination parsing

### Manual validation

- interactive SSH session on each platform
- password-based authentication
- key-based authentication with imported key material
- local-to-remote and remote-to-local file transfer
- recursive directory transfer
- installer behavior on Windows, macOS, and Linux

## Packaging And Installation

Primary distribution should be standalone installers or packages:

- Windows: installer or `.msi`
- macOS: signed installer package or install script
- Linux: packaged archive and install script, with room for distro packages later

The installer must:

- place the `connect` binary in a standard location
- add that location to `PATH` when needed
- create any required application data directories lazily on first run, not at install time

The first release should also produce release artifacts from CI so users can download per-platform packages directly.

## Open Implementation Decisions

These are implementation-time decisions, not unresolved product requirements:

- final SSH crate choice based on API maturity and interactive session support
- final persistence format choice, likely SQLite unless a simpler store proves sufficient
- exact installer technology per platform
- exact terminal handling crate for attached SSH sessions across Windows and Unix-like systems

## Acceptance Criteria

- Users can add a named SSH profile with host, port, username, and password or imported private key.
- Passwords and private keys are stored in the OS-native secret store, not in plain config files.
- Users can connect with `connect <name>` using embedded Rust SSH support.
- First-time connections prompt for host key trust and save the accepted host key.
- Users can list and delete saved host keys.
- Users can edit and delete saved profiles.
- Users can copy files with `connect copy` in both local-to-remote and remote-to-local directions.
- Recursive copy works when `--recursive` is supplied.
- The CLI exposes clear help output for all commands.
- Release outputs include primary standalone installers or packages for Windows, macOS, and Linux.
