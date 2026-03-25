use std::io::Write;

use crate::{
    app::App,
    cli::{
        ForwardAddArgs, ForwardArgs, ForwardCommand, ForwardListArgs, ForwardRemoveArgs,
        ForwardRunArgs,
    },
    error::{Error, Result},
    store::{ForwardDefinition, ForwardKind},
    terminal::prompt::Prompt,
};

use super::add::{validate_non_empty, validate_port};

pub fn run(app: &App, prompt: &dyn Prompt, args: &ForwardArgs, writer: &mut dyn Write) -> Result<()> {
    match args.command.as_ref() {
        Some(ForwardCommand::Add(args)) => add(app, args, writer),
        Some(ForwardCommand::List(args)) => list(app, args, writer),
        Some(ForwardCommand::Remove(args)) => remove(app, prompt, args, writer),
        Some(ForwardCommand::Run(args)) => run_forward(app, args, writer),
        None => Err(Error::new("forward requires a subcommand")),
    }
}

fn add(app: &App, args: &ForwardAddArgs, writer: &mut dyn Write) -> Result<()> {
    let profile = validate_non_empty("profile", args.profile.clone())?;
    let name = validate_non_empty("name", args.name.clone())?;
    let description = match &args.description {
        Some(description) => Some(validate_non_empty("description", description.clone())?),
        None => None,
    };
    let (kind, bind_host, bind_port, target_host, target_port) = match (&args.local, &args.socks) {
        (Some(spec), None) => {
            let (bind_host, bind_port, target_host, target_port) = parse_local_spec(spec)?;
            (
                ForwardKind::Local,
                bind_host,
                bind_port,
                Some(target_host),
                Some(target_port),
            )
        }
        (None, Some(spec)) => {
            let (bind_host, bind_port) = parse_socks_spec(spec)?;
            (ForwardKind::Socks, bind_host, bind_port, None, None)
        }
        (None, None) => return Err(Error::new("forward add requires --local or --socks")),
        (Some(_), Some(_)) => unreachable!("clap enforces mutual exclusion"),
    };

    let definition = ForwardDefinition {
        profile_name: profile.clone(),
        name: name.clone(),
        kind,
        bind_host,
        bind_port,
        target_host,
        target_port,
        description,
    };

    let _ = app.save_forward(definition)?;
    writeln!(writer, "Saved forward '{name}' for profile '{profile}'.").map_err(Error::from)
}

fn list(app: &App, args: &ForwardListArgs, writer: &mut dyn Write) -> Result<()> {
    let profile = validate_non_empty("profile", args.profile.clone())?;
    for definition in app.list_forwards(&profile)? {
        writeln!(
            writer,
            "{}\t{}\t{}:{}",
            definition.name, definition.kind, definition.bind_host, definition.bind_port
        )
        .map_err(Error::from)?;
    }

    Ok(())
}

fn remove(
    app: &App,
    prompt: &dyn Prompt,
    args: &ForwardRemoveArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    let profile = validate_non_empty("profile", args.profile.clone())?;
    let name = validate_non_empty("name", args.name.clone())?;

    if !args.yes
        && !prompt.confirm(
            "forward.remove",
            &format!("Remove forward '{name}' from profile '{profile}'?"),
            false,
        )?
    {
        writeln!(writer, "Aborted.").map_err(Error::from)?;
        return Ok(());
    }

    if app.delete_forward(&profile, &name)? {
        writeln!(writer, "Removed forward '{name}' from profile '{profile}'.").map_err(Error::from)
    } else {
        Err(Error::new(format!(
            "forward '{name}' was not found for profile '{profile}'"
        )))
    }
}

fn run_forward(app: &App, args: &ForwardRunArgs, writer: &mut dyn Write) -> Result<()> {
    let profile = validate_non_empty("profile", args.profile.clone())?;
    match (&args.name, args.all) {
        (Some(name), false) => {
            let name = validate_non_empty("name", name.clone())?;
            let _ = app.get_forward(&profile, &name)?;
            writeln!(writer, "Validated forward '{name}' for profile '{profile}'.").map_err(Error::from)
        }
        (None, true) => {
            let forwards = app.list_forwards(&profile)?;
            writeln!(
                writer,
                "Validated {} saved forward(s) for profile '{profile}'.",
                forwards.len()
            )
            .map_err(Error::from)
        }
        (None, false) => Err(Error::new("forward run requires a name or --all")),
        (Some(_), true) => Err(Error::new("forward run cannot accept both a name and --all")),
    }
}

fn parse_local_spec(spec: &str) -> Result<(String, u16, String, u16)> {
    let mut parts = spec.split(':');
    let bind_host = validate_non_empty("bind_host", parts.next().unwrap_or_default().to_string())?;
    let bind_port = parse_port_part("bind_port", parts.next())?;
    let target_host =
        validate_non_empty("target_host", parts.next().unwrap_or_default().to_string())?;
    let target_port = parse_port_part("target_port", parts.next())?;

    if parts.next().is_some() {
        return Err(Error::new(
            "forward specs must be either bind_host:bind_port:target_host:target_port or bind_host:bind_port",
        ));
    }

    Ok((bind_host, bind_port, target_host, target_port))
}

fn parse_socks_spec(spec: &str) -> Result<(String, u16)> {
    let mut parts = spec.split(':');
    let bind_host = validate_non_empty("bind_host", parts.next().unwrap_or_default().to_string())?;
    let bind_port = parse_port_part("bind_port", parts.next())?;

    if parts.next().is_some() {
        return Err(Error::new("socks specs must be bind_host:bind_port"));
    }

    Ok((bind_host, bind_port))
}

fn parse_port_part(field: &str, value: Option<&str>) -> Result<u16> {
    let value = value.ok_or_else(|| Error::new(format!("{field} is required")))?;
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::new(format!("{field} must be between 1 and 65535")))?;
    validate_port(port)
}
