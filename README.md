# connect

`connect` is a Rust CLI for managing SSH connection profiles, opening SSH sessions, and copying files without relying on external `ssh` or `scp` binaries at runtime.

## Install

Linux users can unpack the release tarball and run `./install.sh`. The script copies the `connect` binary into `/usr/local/bin` by default, updates `PATH` automatically when needed, and does not create app data directories during install. Set `CONNECT_INSTALL_PREFIX` if you want a different prefix.

macOS users can install the `.pkg` release. The package places `connect` in `/usr/local/bin/connect` and ensures `/usr/local/bin` is available on `PATH` for new shell sessions.

Windows users can install the `.msi` release. The installer puts `connect.exe` under `Program Files` and updates the machine PATH.

## Usage

Add a profile:

```bash
connect add prod --host prod.example.com --user alice
```

Store a password securely without exposing it on the command line:

```bash
connect add prod --host prod.example.com --user alice --password
```

Provision a password non-interactively from standard input:

```bash
printf '%s\n' "$CONNECT_PASSWORD" | connect add prod --host prod.example.com --user alice --password-stdin
```

Open an interactive SSH session:

```bash
connect prod
```

Copy files between local and remote locations:

```bash
connect copy ./artifact.tgz prod:/tmp/artifact.tgz
connect copy prod:/tmp/artifact.tgz ./downloads/artifact.tgz
connect copy --recursive ./site prod:/var/www/site
```

Profile management commands:

```bash
connect list
connect show prod
connect edit prod
connect remove prod
```

Host key commands:

```bash
connect hostkeys list
connect hostkeys delete 1
```

Shell completions are available with:

```bash
connect completion bash
```

## Storage

`connect` stores profile metadata and host keys in the user-specific application directories for each platform. Secrets such as passwords and imported private keys live in the OS keychain. Runtime data directories are created lazily on first run, not during installation.
