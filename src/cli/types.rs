use clap::{Parser, Subcommand};

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
    Add,
    /// Edit an existing SSH profile.
    Edit,
    /// Remove an SSH profile.
    Remove,
    /// List stored SSH profiles.
    List,
    /// Show details for an SSH profile.
    Show,
    /// Copy SSH files to a remote host.
    Copy,
    /// Inspect SSH host keys for a profile.
    Hostkeys,
    /// Generate shell completion scripts.
    Completion,
    /// Print the application version.
    Version,
}
