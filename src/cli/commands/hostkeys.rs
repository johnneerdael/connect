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
            "{}\t{}:{}\t{}\t{}",
            record.id, record.host, record.port, record.algorithm, record.fingerprint
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
    let id = parse_host_key_id(&args.target)?;

    if !args.yes
        && !prompt.confirm(
            "hostkeys.delete",
            &format!("Delete saved host key '{id}'?"),
            false,
        )?
    {
        writeln!(writer, "Aborted.").map_err(Error::from)?;
        return Ok(());
    }

    if app.delete_host_key_by_id(id)? {
        writeln!(writer, "Removed host key '{id}'.").map_err(Error::from)
    } else {
        Err(Error::new(format!("host key '{id}' was not found")))
    }
}

fn parse_host_key_id(value: &str) -> Result<i64> {
    let id = value
        .trim()
        .parse::<i64>()
        .map_err(|_| Error::new("host key target must be a numeric id"))?;

    if id <= 0 {
        return Err(Error::new("host key target must be a numeric id"));
    }

    Ok(id)
}
