use crate::{
    app::App,
    error::{Error, Result},
    ssh::RusshClient,
    terminal::prompt::Prompt,
};

use super::add::validate_non_empty;

pub fn run(app: &App, prompt: &dyn Prompt, name: &str) -> Result<()> {
    let name = validate_non_empty("profile", name.to_string())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ssh = RusshClient::new();

    match runtime.block_on(app.open_profile(&name, &ssh, prompt)) {
        Err(Error::RemoteExitStatus(code)) => {
            std::process::exit(i32::try_from(code).unwrap_or(1));
        }
        result => result,
    }
}
