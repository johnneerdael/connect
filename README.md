# connect

`connect` is a cross-platform Rust CLI for managing SSH profiles, opening interactive SSH sessions, and copying files without depending on external `ssh` or `scp` binaries at runtime.

It is built for Windows, macOS, and Linux, stores secrets in the OS-native keychain, and uses trust on first use (TOFU) for SSH host keys.

## Features

- named SSH profiles
- embedded SSH session support
- non-interactive remote command execution with exact exit-code propagation
- local-to-remote and remote-to-local copy support
- recursive directory copy with `--recursive`
- resumable single-file and recursive copy with `--resume`
- opt-in threaded copy with `--threads`
- in-run transient retry support with `--retry`
- optional copy progress reporting with `--progress`
- OS-native secret storage for passwords, imported private keys, and key passphrases
- SSH agent support with configurable auth precedence
- TOFU host key verification with commands to list and delete saved host keys
- local environment and live-profile diagnostics with `connect doctor`
- saved foreground local TCP forwards and local SOCKS5 proxies
- encrypted full backup and restore with runtime PSK protection
- encrypted single-profile export and import with runtime PSK protection
- standalone release artifacts for Linux, macOS, and Windows
- shell completion generation

## Install

### Linux

Download the Linux release archive, unpack it, and run:

```bash
./install.sh
```

The installer copies `connect` into `/usr/local/bin` by default, updates `PATH` automatically when needed, and does not create app data directories during install.

To install somewhere else:

```bash
CONNECT_INSTALL_PREFIX="$HOME/.local" ./install.sh
```

### macOS

Install the `.pkg` release artifact. The package installs `connect` to `/usr/local/bin/connect` and ensures `/usr/local/bin` is available on `PATH` for new shell sessions.

Tagged macOS releases can be signed in GitHub Actions when these repository secrets are configured:

- `MACOS_DEVELOPER_ID_APPLICATION_P12`
- `MACOS_DEVELOPER_ID_INSTALLER_P12`
- `MACOS_DEVELOPER_ID_P12_PASSWORD`
- `MACOS_KEYCHAIN_PASSWORD`
- `MACOS_NOTARY_API_KEY_P8`
- `MACOS_NOTARY_KEY_ID`
- `MACOS_NOTARY_ISSUER_ID` (optional for team keys only)
- `CONNECT_ARCHIVE_APP_KEY_HEX`

The certificate payload secrets should contain base64-encoded `.p12` files for your `Developer ID Application` and `Developer ID Installer` certificates. `MACOS_NOTARY_API_KEY_P8` should contain the base64-encoded contents of your App Store Connect API `.p8` key, and `MACOS_NOTARY_KEY_ID` should be the matching key ID. The workflow stores notarization credentials in a temporary keychain profile before submitting the package, which allows both individual keys without an issuer and team keys with `MACOS_NOTARY_ISSUER_ID`. When notarization secrets are present, the workflow notarizes and staples the generated `.pkg`. When they are absent, the workflow still produces a signed-but-unstapled package so local development and forks do not break.

`CONNECT_ARCHIVE_APP_KEY_HEX` must be a 64-character hex-encoded 256-bit key. Release builds fail when it is absent. Local debug builds use a non-production fallback key so backup/import flows remain testable without access to release secrets.

### Windows

Install the `.msi` release artifact. The installer places `connect.exe` under `Program Files` and updates the machine `PATH`.

## Quick Start

Add a profile with interactive secret entry:

```bash
connect add prod --host prod.example.com --user alice --password --auth-mode auto
```

Import a private key from disk. The key is read once and stored in the OS keychain:

```bash
connect add prod --host prod.example.com --user alice --private-key ~/.ssh/id_ed25519
```

Restrict a profile to password-only authentication:

```bash
connect add legacy --host legacy.example.com --user alice --password --auth-mode password-only
```

Provide a password non-interactively from standard input:

```bash
printf '%s\n' "$CONNECT_PASSWORD" | connect add prod --host prod.example.com --user alice --password-stdin
```

Inspect saved profiles:

```bash
connect list
connect show prod
connect doctor
connect doctor prod
```

Open an interactive SSH session:

```bash
connect open prod
connect prod
```

Run a remote command without allocating a TTY:

```bash
connect exec prod -- uname -a
```

Run a remote command that needs a PTY:

```bash
connect exec prod --pty -- sudo systemctl status nginx
```

Update or remove a profile:

```bash
connect edit prod --host prod-2.example.com --auth-mode agent-only
connect remove prod
```

## Backup And Profile Transfer

Create a full encrypted backup of all profiles, forwards, host keys, and stored secrets:

```bash
connect backup create --output ./connect-state.connectbak
```

Restore a full backup. This replaces all local profiles, forwards, host keys, and stored secrets:

```bash
connect backup restore --input ./connect-state.connectbak
```

Export one profile and its stored secrets:

```bash
connect profile export prod --output ./prod.connectprofile
```

Import one exported profile and its stored secrets:

```bash
connect profile import --input ./prod.connectprofile
```

Notes:

- all four operations prompt for a PSK at runtime
- backup restore is destructive unless you abort at the confirmation prompt
- full backups include host keys
- single-profile exports do not include host keys
- archive files use two encryption layers: your PSK and an additional application-held key embedded into release builds

## File Copy

`connect copy` accepts exactly one remote endpoint. Remote paths use `profile:/absolute/path`.

Examples:

```bash
connect copy ./artifact.tgz prod:/tmp/artifact.tgz
connect copy prod:/tmp/artifact.tgz ./downloads/artifact.tgz
connect copy --recursive ./site prod:/var/www/site
connect copy --recursive prod:/var/www/site ./site-backup
```

Rules:

- exactly one side must be remote
- directory copy requires `--recursive`
- remote paths must use absolute paths
- threaded copy is opt-in and only activates when `--threads` is greater than `1`
- when the server cannot sustain the requested thread count, `connect` degrades to fewer transfer sessions and reports a warning

To force a remote interpretation for ambiguous names, prefix the profile with `@`:

```bash
connect copy @p:/tmp/file.txt ./file.txt
connect copy @@prod:/tmp/file.txt ./file.txt
```

Resume a partial transfer:

```bash
connect copy --resume ./artifact.tgz prod:/tmp/artifact.tgz
connect copy --resume prod:/tmp/artifact.tgz ./downloads/artifact.tgz
connect copy --recursive --resume ./site prod:/var/www/site
```

Force progress output on a TTY-aware copy:

```bash
connect copy --progress ./artifact.tgz prod:/tmp/artifact.tgz
```

Enable threaded copy explicitly:

```bash
connect copy --threads 4 ./artifact.tgz prod:/tmp/artifact.tgz
connect copy --recursive --threads 4 ./site prod:/var/www/site
```

Retry transient threaded copy failures in-run:

```bash
connect copy --threads 4 --retry ./artifact.tgz prod:/tmp/artifact.tgz
connect copy --recursive --threads 4 --retry --resume ./site prod:/var/www/site
```

Threaded copy behavior:

- `--threads 1` preserves the existing single-stream copy path
- `--threads > 1` enables parallel transfer for both large single files and recursive trees
- large files are striped across multiple random-access-capable SFTP sessions
- recursive trees use a shared work queue, and large files inside the tree can also be striped
- `--resume` preserves and reuses partial threaded transfer state where safe
- `--retry` retries transient failures during the current run and cooperates with `--resume`

## Diagnostics

Run local environment checks only:

```bash
connect doctor
```

Run local checks plus profile-specific reachability, handshake, host-key, and auth checks:

```bash
connect doctor prod
```

`connect doctor <profile>` is non-destructive. It does not open an interactive shell.

## Forwarding

Saved forwards stay attached to the foreground process. `connect` does not daemonize or background tunnels.

Create, inspect, and remove forwards:

```bash
connect forward add prod db --local 127.0.0.1:15432:db.internal:5432
connect forward add prod proxy --socks 127.0.0.1:1080
connect forward list prod
connect forward remove prod db
```

Run one saved forward:

```bash
connect forward run prod db
connect forward run prod proxy
```

Run every saved forward for a profile together:

```bash
connect forward run prod --all
```

Forwarding scope in the current release:

- local TCP forwards are supported
- local SOCKS5 proxies support no-auth `CONNECT`
- forwarding stays in the foreground until interrupted
- remote forwards and background tunnel management are not supported

## Host Keys

On the first connection to a host, `connect` shows the observed SSH host key fingerprint and asks whether to trust it. If accepted, the host key is stored and reused for future verification.

Inspect or remove saved host keys:

```bash
connect hostkeys list
connect hostkeys delete 1
```

## Security Model

- passwords are stored in the OS-native secret store
- imported private keys are stored in the OS-native secret store
- key passphrases are stored in the OS-native secret store
- profile metadata and trusted host keys are stored locally in the per-user app data directory
- `connect show` reports whether credentials exist, but never prints secret values

Auth modes:

- `auto`: try SSH agent, then stored private key, then password
- `agent-only`: require SSH agent authentication
- `stored-only`: use only credentials stored by `connect`
- `password-only`: skip key-based authentication

`connect show <profile>` prints the saved auth mode and whether agent auth is currently available on the host system.

## Shell Completions

Generate shell completions with:

```bash
connect completion bash
connect completion zsh
connect completion fish
connect completion powershell
```

## Development

Build:

```bash
cargo build
```

Run tests:

```bash
cargo test
```

Run the full local verification gate:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
cargo test
```

## Release Signing

The GitHub Actions release workflow supports optional macOS signing and notarization for tagged releases.

When signing secrets are present, the macOS job will:

- import the `Developer ID Application` certificate into a temporary keychain
- import the `Developer ID Installer` certificate into a temporary keychain
- codesign the `connect` binary before packaging
- sign the generated `.pkg` with `productsign`
- store notarization credentials in the same temporary keychain with `notarytool store-credentials`
- submit the signed `.pkg` to Apple with `notarytool` when notarization secrets are present
- staple the notarization ticket back onto the `.pkg`
- validate the stapled installer with `stapler` and `spctl`

Notarization uses an App Store Connect API key:

- `MACOS_NOTARY_API_KEY_P8`
- `MACOS_NOTARY_KEY_ID`
- `MACOS_NOTARY_ISSUER_ID` only when the key is a team key

When signing secrets are missing, the workflow falls back to unsigned macOS packaging. When signing secrets are present but notarization secrets are missing, the workflow still produces a signed package without notarization.
