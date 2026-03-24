# connect

`connect` is a cross-platform Rust CLI for managing SSH profiles, opening interactive SSH sessions, and copying files without depending on external `ssh` or `scp` binaries at runtime.

It is built for Windows, macOS, and Linux, stores secrets in the OS-native keychain, and uses trust on first use (TOFU) for SSH host keys.

## Features

- named SSH profiles
- embedded SSH session support
- local-to-remote and remote-to-local copy support
- recursive directory copy with `--recursive`
- OS-native secret storage for passwords, imported private keys, and key passphrases
- TOFU host key verification with commands to list and delete saved host keys
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

### Windows

Install the `.msi` release artifact. The installer places `connect.exe` under `Program Files` and updates the machine `PATH`.

## Quick Start

Add a profile with interactive secret entry:

```bash
connect add prod --host prod.example.com --user alice --password
```

Import a private key from disk. The key is read once and stored in the OS keychain:

```bash
connect add prod --host prod.example.com --user alice --private-key ~/.ssh/id_ed25519
```

Provide a password non-interactively from standard input:

```bash
printf '%s\n' "$CONNECT_PASSWORD" | connect add prod --host prod.example.com --user alice --password-stdin
```

Inspect saved profiles:

```bash
connect list
connect show prod
```

Open an interactive SSH session:

```bash
connect prod
```

Update or remove a profile:

```bash
connect edit prod --host prod-2.example.com
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
- remote paths must use absolute paths

To force a remote interpretation for ambiguous names, prefix the profile with `@`:

```bash
connect copy @p:/tmp/file.txt ./file.txt
connect copy @@prod:/tmp/file.txt ./file.txt
```

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

If both a private key and a password are available, `connect` tries private-key authentication first and falls back to password authentication if needed.

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
