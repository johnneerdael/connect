use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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
    /// Copy SSH files to a remote host.
    Copy,
    /// Inspect SSH host keys for a profile.
    Hostkeys,
    /// Generate shell completion scripts.
    Completion,
    /// Print the application version.
    Version,
}

#[derive(Args, Debug, Clone)]
pub struct AddArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long = "user")]
    pub user: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long = "private-key", value_name = "PATH")]
    pub private_key: Option<PathBuf>,
    #[arg(long = "key-passphrase")]
    pub key_passphrase: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct EditArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long = "user")]
    pub user: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long = "private-key", value_name = "PATH")]
    pub private_key: Option<PathBuf>,
    #[arg(long = "key-passphrase")]
    pub key_passphrase: Option<String>,
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
