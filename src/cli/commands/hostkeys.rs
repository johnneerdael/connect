use std::io::Write;

use crate::{
    app::App,
    cli::{HostkeysCommand, HostkeysDeleteArgs},
    error::{Error, Result},
    terminal::prompt::Prompt,
};

pub fn run(
    app: &App,
    prompt: &dyn Prompt,
    command: &HostkeysCommand,
    writer: &mut dyn Write,
) -> Result<()> {
    match command {
        HostkeysCommand::List(_) => list(app, writer),
        HostkeysCommand::Delete(args) => delete(app, prompt, args, writer),
    }
}

fn list(app: &App, writer: &mut dyn Write) -> Result<()> {
    for record in app.list_host_keys()? {
        writeln!(
            writer,
            "{}:{}\t{}\t{}",
            record.host, record.port, record.algorithm, record.fingerprint
        )
        .map_err(Error::from)?;
    }

    Ok(())
}

fn delete(
    app: &App,
    prompt: &dyn Prompt,
    args: &HostkeysDeleteArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    let (host, port) = parse_host_port(&args.target)?;

    if !args.yes
        && !prompt.confirm(
            "hostkeys.delete",
            &format!("Delete saved host key for {host}:{port}?"),
            false,
        )?
    {
        writeln!(writer, "Aborted.").map_err(Error::from)?;
        return Ok(());
    }

    if app.delete_host_key(&host, port)? {
        writeln!(writer, "Removed host key '{host}:{port}'.").map_err(Error::from)
    } else {
        Err(Error::new(format!(
            "host key '{host}:{port}' was not found"
        )))
    }
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| Error::new("host key target must be in host:port format"))?;

    if host.trim().is_empty() {
        return Err(Error::new("host key target must be in host:port format"));
    }

    let port = port
        .parse::<u16>()
        .map_err(|_| Error::new("host key target must be in host:port format"))?;
    if port == 0 {
        return Err(Error::new("host key target must be in host:port format"));
    }

    Ok((host.trim().to_string(), port))
}
