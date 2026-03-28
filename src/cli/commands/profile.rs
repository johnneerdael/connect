use std::{
    fs,
    io::Write,
};

use crate::{
    app::App,
    archive::{decrypt_archive, embedded_app_key, encrypt_archive, ArchiveKind, ProfileExportPayload},
    cli::{ProfileCommand, ProfileExportArgs, ProfileImportArgs},
    error::{Error, Result},
    terminal::prompt::Prompt,
};

use super::backup::{ensure_output_does_not_exist, prompt_psk};

pub fn run(
    app: &App,
    prompt: &dyn Prompt,
    command: &ProfileCommand,
    writer: &mut dyn Write,
) -> Result<()> {
    match command {
        ProfileCommand::Export(args) => export(app, prompt, args, writer),
        ProfileCommand::Import(args) => import(app, prompt, args, writer),
    }
}

fn export(
    app: &App,
    prompt: &dyn Prompt,
    args: &ProfileExportArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    ensure_output_does_not_exist(&args.output)?;
    let psk = prompt_export_psk(prompt)?;
    let payload = app.create_profile_export_snapshot(&args.name)?;
    let archive = encrypt_archive(&payload, ArchiveKind::ProfileExport, &psk, &embedded_app_key()?)?;
    fs::write(&args.output, archive)?;
    writeln!(writer, "Exported profile '{}' to '{}'.", args.name, args.output.display())
        .map_err(Error::from)
}

fn import(
    app: &App,
    prompt: &dyn Prompt,
    args: &ProfileImportArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    let psk = prompt_psk(prompt, "profile.import.psk", "Profile export PSK")?;
    let archive = fs::read(&args.input)?;
    let payload: ProfileExportPayload =
        decrypt_archive(&archive, ArchiveKind::ProfileExport, &psk, &embedded_app_key()?)?;
    let profile = app.import_profile_snapshot(payload)?;
    writeln!(writer, "Imported profile '{}'.", profile.name).map_err(Error::from)
}

fn prompt_export_psk(prompt: &dyn Prompt) -> Result<String> {
    let first = prompt_psk(prompt, "profile.export.psk", "Profile export PSK")?;
    let second = prompt_psk(
        prompt,
        "profile.export.psk.confirm",
        "Confirm profile export PSK",
    )?;
    if first != second {
        return Err(Error::new("PSK entries did not match"));
    }
    Ok(first)
}
