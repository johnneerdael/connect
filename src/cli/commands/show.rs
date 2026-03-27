use std::io::Write;

use crate::{
    app::App,
    cli::ShowArgs,
    error::{Error, Result},
};

use super::add::validate_non_empty;

pub fn run(app: &App, args: &ShowArgs, writer: &mut dyn Write) -> Result<()> {
    let name = validate_non_empty("name", args.name.clone())?;
    let profile = app.get_profile(&name)?;

    writeln!(writer, "Name: {}", profile.name).map_err(Error::from)?;
    writeln!(writer, "Host: {}", profile.host).map_err(Error::from)?;
    writeln!(writer, "Port: {}", profile.port).map_err(Error::from)?;
    writeln!(writer, "Username: {}", profile.username).map_err(Error::from)?;
    writeln!(
        writer,
        "Copy threads: {}",
        profile.copy_threads.unwrap_or(1)
    )
    .map_err(Error::from)?;
    writeln!(writer, "Auth mode: {}", profile.auth_mode).map_err(Error::from)?;
    writeln!(writer, "Agent auth: {}", app.agent_auth_status()).map_err(Error::from)?;
    writeln!(
        writer,
        "Password: {}",
        availability_label(profile.has_password)
    )
    .map_err(Error::from)?;
    writeln!(
        writer,
        "Private key: {}",
        availability_label(profile.has_private_key)
    )
    .map_err(Error::from)?;
    writeln!(
        writer,
        "Key passphrase: {}",
        availability_label(profile.has_key_passphrase)
    )
    .map_err(Error::from)?;

    Ok(())
}

fn availability_label(is_configured: bool) -> &'static str {
    if is_configured {
        "configured"
    } else {
        "not configured"
    }
}
