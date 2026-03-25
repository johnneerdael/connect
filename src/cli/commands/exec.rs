use crate::{
    app::App,
    cli::runtime::run_async,
    cli::ExecArgs,
    error::{Error, Result},
    ssh::{ExecSpec, RusshClient},
    terminal::prompt::Prompt,
};

use super::add::validate_non_empty;

pub fn run(app: &App, prompt: &dyn Prompt, args: &ExecArgs) -> Result<()> {
    let profile = validate_non_empty("profile", args.profile.clone())?;
    let ssh = RusshClient::new();
    let spec = ExecSpec::new(args.command.clone(), args.pty);

    match run_async(app.exec(&profile, &spec, &ssh, prompt)) {
        Err(Error::RemoteExitStatus(code)) => {
            std::process::exit(i32::try_from(code).unwrap_or(1));
        }
        result => result,
    }
}
