use clap::Parser;

use crate::{
    cli::{
        commands::{completion, version},
        Cli, Command,
    },
    error::Result,
};

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Completion) => completion::run(),
        Some(Command::Version) => version::run(),
        Some(Command::Add)
        | Some(Command::Edit)
        | Some(Command::Remove)
        | Some(Command::List)
        | Some(Command::Show)
        | Some(Command::Copy)
        | Some(Command::Hostkeys) => Ok(()),
        None => {
            let _profile = cli.profile;
            Ok(())
        }
    }
}

