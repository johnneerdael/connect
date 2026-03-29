use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

use crate::store::AuthMode;

#[derive(Parser, Debug)]
#[command(
    name = "connect",
    version,
    about = "Manage SSH connections securely",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(value_name = "PROFILE")]
    pub profile: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Create or restore complete encrypted backups.
    Backup(BackupArgs),
    /// Open an interactive SSH shell.
    Open(OpenArgs),
    /// Execute a remote command without opening an interactive shell.
    Exec(ExecArgs),
    /// Inspect the local environment.
    Doctor(DoctorArgs),
    /// Add a new SSH profile.
    Add(AddArgs),
    /// Edit an existing SSH profile.
    Edit(EditArgs),
    /// Remove an SSH profile.
    Remove(RemoveArgs),
    /// List stored SSH profiles.
    List(ListArgs),
    /// Show details for an SSH profile.
    Show(ShowArgs),
    /// Export or import a single saved profile.
    Profile(ProfileArgs),
    /// Copy files between the local machine and a remote host.
    Copy(CopyArgs),
    /// Manage saved local SSH forwards.
    Forward(ForwardArgs),
    /// Inspect SSH host keys for a profile.
    Hostkeys(HostkeysArgs),
    /// Generate shell completion scripts.
    Completion(CompletionArgs),
    /// Print the application version.
    Version,
}

#[derive(Args, Debug, Clone)]
pub struct AddArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long, short = 'H')]
    pub host: Option<String>,
    #[arg(long = "user", short = 'u')]
    pub user: Option<String>,
    #[arg(long, short = 'p')]
    pub port: Option<u16>,
    #[arg(long, short = 'a', default_value_t = AuthMode::Auto, value_parser = parse_auth_mode)]
    pub auth_mode: AuthMode,
    #[arg(long, conflicts_with = "password_stdin")]
    pub password: bool,
    #[arg(long = "password-stdin", visible_alias = "pw-stdin", conflicts_with = "password")]
    pub password_stdin: bool,
    #[arg(long = "private-key", short = 'i', visible_alias = "pk", value_name = "PATH")]
    pub private_key: Option<PathBuf>,
    #[arg(long = "key-passphrase", visible_alias = "kp", conflicts_with = "key_passphrase_stdin")]
    pub key_passphrase: bool,
    #[arg(long = "key-passphrase-stdin", visible_alias = "kp-stdin", conflicts_with = "key_passphrase")]
    pub key_passphrase_stdin: bool,
    #[arg(long = "copy-threads", short = 't', visible_alias = "ct", value_parser = parse_copy_threads)]
    pub copy_threads: Option<usize>,
}

#[derive(Args, Debug, Clone)]
pub struct EditArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long, short = 'H')]
    pub host: Option<String>,
    #[arg(long = "user", short = 'u')]
    pub user: Option<String>,
    #[arg(long, short = 'p')]
    pub port: Option<u16>,
    #[arg(long, short = 'a', value_parser = parse_auth_mode)]
    pub auth_mode: Option<AuthMode>,
    #[arg(long, conflicts_with = "password_stdin")]
    pub password: bool,
    #[arg(long = "password-stdin", visible_alias = "pw-stdin", conflicts_with = "password")]
    pub password_stdin: bool,
    #[arg(long = "private-key", short = 'i', visible_alias = "pk", value_name = "PATH")]
    pub private_key: Option<PathBuf>,
    #[arg(long = "key-passphrase", visible_alias = "kp", conflicts_with = "key_passphrase_stdin")]
    pub key_passphrase: bool,
    #[arg(long = "key-passphrase-stdin", visible_alias = "kp-stdin", conflicts_with = "key_passphrase")]
    pub key_passphrase_stdin: bool,
    #[arg(long = "copy-threads", short = 't', visible_alias = "ct", value_parser = parse_copy_threads)]
    pub copy_threads: Option<usize>,
}

#[derive(Args, Debug, Clone)]
pub struct RemoveArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ListArgs;

#[derive(Args, Debug, Clone)]
pub struct ShowArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(Args, Debug, Clone)]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub command: BackupCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BackupCommand {
    /// Create a full encrypted backup.
    Create(BackupCreateArgs),
    /// Restore a full encrypted backup.
    Restore(BackupRestoreArgs),
}

#[derive(Args, Debug, Clone)]
pub struct BackupCreateArgs {
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct BackupRestoreArgs {
    #[arg(long, short = 'i', value_name = "PATH")]
    pub input: PathBuf,
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Args, Debug, Clone)]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub command: ProfileCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ProfileCommand {
    /// Export one saved profile and its secrets.
    Export(ProfileExportArgs),
    /// Import one saved profile and its secrets.
    Import(ProfileImportArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ProfileExportArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct ProfileImportArgs {
    #[arg(long, short = 'i', value_name = "PATH")]
    pub input: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct CopyArgs {
    #[arg(long, short = 'r')]
    pub recursive: bool,
    #[arg(long, visible_alias = "rs")]
    pub resume: bool,
    #[arg(long, short = 'p')]
    pub progress: bool,
    #[arg(long, short = 't', value_name = "COUNT", value_parser = parse_copy_threads)]
    pub threads: Option<usize>,
    #[arg(long, visible_alias = "rt")]
    pub retry: bool,
    #[arg(value_name = "SOURCE")]
    pub source: String,
    #[arg(value_name = "DESTINATION")]
    pub destination: String,
}

#[derive(Args, Debug, Clone)]
pub struct OpenArgs {
    #[arg(value_name = "PROFILE")]
    pub profile: String,
}

#[derive(Args, Debug, Clone)]
pub struct ExecArgs {
    #[arg(value_name = "PROFILE")]
    pub profile: String,
    #[arg(long, short = 't')]
    pub pty: bool,
    #[arg(
        value_name = "COMMAND",
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub command: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct DoctorArgs {
    #[arg(value_name = "PROFILE")]
    pub profile: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct ForwardArgs {
    #[command(subcommand)]
    pub command: ForwardCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ForwardCommand {
    /// Add a saved local forward definition.
    Add(ForwardAddArgs),
    /// List saved forwards for a profile.
    List(ForwardListArgs),
    /// Remove a saved forward definition.
    Remove(ForwardRemoveArgs),
    /// Validate and prepare one or more saved forwards.
    Run(ForwardRunArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ForwardAddArgs {
    #[arg(value_name = "PROFILE")]
    pub profile: String,
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long, short = 'l', conflicts_with = "socks")]
    pub local: Option<String>,
    #[arg(long, short = 's', conflicts_with = "local")]
    pub socks: Option<String>,
    #[arg(long, short = 'd')]
    pub description: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ForwardListArgs {
    #[arg(value_name = "PROFILE")]
    pub profile: String,
}

#[derive(Args, Debug, Clone)]
pub struct ForwardRemoveArgs {
    #[arg(value_name = "PROFILE")]
    pub profile: String,
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ForwardRunArgs {
    #[arg(value_name = "PROFILE")]
    pub profile: String,
    #[arg(value_name = "NAME")]
    pub name: Option<String>,
    #[arg(long, short = 'a')]
    pub all: bool,
}

#[derive(Args, Debug, Clone)]
pub struct CompletionArgs {
    #[arg(value_name = "SHELL")]
    pub shell: Shell,
}

#[derive(Args, Debug, Clone, Default)]
pub struct HostkeysArgs {
    #[command(subcommand)]
    pub command: Option<HostkeysCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HostkeysCommand {
    /// List saved SSH host keys.
    List(HostkeysListArgs),
    /// Delete a saved SSH host key by id.
    Delete(HostkeysDeleteArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct HostkeysListArgs;

#[derive(Args, Debug, Clone)]
pub struct HostkeysDeleteArgs {
    #[arg(value_name = "ID")]
    pub target: String,
    #[arg(long, short = 'y')]
    pub yes: bool,
}

fn parse_auth_mode(value: &str) -> Result<AuthMode, String> {
    value.parse()
}

fn parse_copy_threads(value: &str) -> Result<usize, String> {
    let threads = value.parse::<usize>().map_err(|_| {
        format!("invalid copy thread count '{value}' (expected a positive integer)")
    })?;

    if threads == 0 {
        Err("copy thread count must be greater than zero".to_string())
    } else {
        Ok(threads)
    }
}
