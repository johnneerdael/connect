use std::io::Write;

use crate::{
    app::App,
    cli::{
        ForwardAddArgs, ForwardArgs, ForwardCommand, ForwardListArgs, ForwardRemoveArgs,
        ForwardRunArgs,
    },
    error::{Error, Result},
    forward::spec::ForwardSpec,
    store::ForwardDefinition,
    terminal::prompt::Prompt,
};

use super::add::validate_non_empty;

pub fn run(
    app: &App,
    prompt: &dyn Prompt,
    args: &ForwardArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    match &args.command {
        ForwardCommand::Add(args) => add(app, args, writer),
        ForwardCommand::List(args) => list(app, args, writer),
        ForwardCommand::Remove(args) => remove(app, prompt, args, writer),
        ForwardCommand::Run(args) => run_forward(app, args, writer),
    }
}

fn add(app: &App, args: &ForwardAddArgs, writer: &mut dyn Write) -> Result<()> {
    let profile = validate_non_empty("profile", args.profile.clone())?;
    let name = validate_non_empty("name", args.name.clone())?;
    let description = match &args.description {
        Some(description) => Some(validate_non_empty("description", description.clone())?),
        None => None,
    };
    let spec = match (&args.local, &args.socks) {
        (Some(spec), None) => ForwardSpec::parse_local(spec)?,
        (None, Some(spec)) => ForwardSpec::parse_socks(spec)?,
        (None, None) => return Err(Error::new("forward add requires --local or --socks")),
        (Some(_), Some(_)) => unreachable!("clap enforces mutual exclusion"),
    };
    let definition = spec.into_definition(profile.clone(), name.clone(), description);

    let _ = app.save_forward(definition)?;
    writeln!(writer, "Saved forward '{name}' for profile '{profile}'.").map_err(Error::from)
}

fn list(app: &App, args: &ForwardListArgs, writer: &mut dyn Write) -> Result<()> {
    let profile = validate_non_empty("profile", args.profile.clone())?;
    for definition in app.list_forwards(&profile)? {
        writeln!(writer, "{}", format_forward_definition(&definition)).map_err(Error::from)?;
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
            writeln!(
                writer,
                "Validated forward '{name}' for profile '{profile}'."
            )
            .map_err(Error::from)
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
        (Some(_), true) => Err(Error::new(
            "forward run cannot accept both a name and --all",
        )),
    }
}

fn format_forward_definition(definition: &ForwardDefinition) -> String {
    match definition.kind {
        crate::store::ForwardKind::Local => format!(
            "{}\t{}\t{}:{}\t{}",
            definition.name,
            definition.kind,
            definition.bind_host,
            definition.bind_port,
            match (&definition.target_host, definition.target_port) {
                (Some(host), Some(port)) => format!("{host}:{port}"),
                _ => "-".to_string(),
            }
        ),
        crate::store::ForwardKind::Socks => format!(
            "{}\t{}\t{}:{}",
            definition.name, definition.kind, definition.bind_host, definition.bind_port
        ),
    }
}
