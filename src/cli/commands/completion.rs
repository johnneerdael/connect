use std::io;

use clap::CommandFactory;
use clap_complete::generate;

use crate::{
    cli::{Cli, CompletionArgs},
    error::Result,
};

pub fn run(args: &CompletionArgs) -> Result<()> {
    let mut command = Cli::command();
    generate(args.shell, &mut command, "connect", &mut io::stdout());
    Ok(())
}
