# connect

`connect` is a cross-platform Rust CLI for managing SSH profiles, opening interactive SSH sessions, and copying files without depending on external `ssh` or `scp` binaries at runtime.

It is built for Windows, macOS, and Linux, stores secrets in the OS-native keychain, and uses trust on first use (TOFU) for SSH host keys.

## Features

- named SSH profiles
- embedded SSH session support
- non-interactive remote command execution with exact exit-code propagation
- local-to-remote and remote-to-local copy support
- recursive directory copy with `--recursive`
- resumable single-file copy with `--resume`
- optional copy progress reporting with `--progress`
- OS-native secret storage for passwords, imported private keys, and key passphrases
- SSH agent support with configurable auth precedence
- TOFU host key verification with commands to list and delete saved host keys
- local environment and live-profile diagnostics with `connect doctor`
- saved foreground local TCP forwards and local SOCKS5 proxies
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

The certificate payload secrets should contain base64-encoded `.p12` files for your `Developer ID Application` and `Developer ID Installer` certificates. When the secrets are absent, the workflow still produces an unsigned `.pkg` so local development and forks do not break.

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
- `--resume` is supported for single-file transfers only
- remote paths must use absolute paths

To force a remote interpretation for ambiguous names, prefix the profile with `@`:

```bash
connect copy @p:/tmp/file.txt ./file.txt
connect copy @@prod:/tmp/file.txt ./file.txt
```

Resume a partial single-file transfer:

```bash
connect copy --resume ./artifact.tgz prod:/tmp/artifact.tgz
connect copy --resume prod:/tmp/artifact.tgz ./downloads/artifact.tgz
```

Force progress output on a TTY-aware copy:

```bash
connect copy --progress ./artifact.tgz prod:/tmp/artifact.tgz
```

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

The GitHub Actions release workflow supports optional macOS signing for tagged releases.

When signing secrets are present, the macOS job will:

- import the `Developer ID Application` certificate into a temporary keychain
- import the `Developer ID Installer` certificate into a temporary keychain
- codesign the `connect` binary before packaging
- sign the generated `.pkg` with `productsign`

When the secrets are not configured, the workflow falls back to unsigned macOS packaging automatically.
