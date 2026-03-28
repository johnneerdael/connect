use std::{
    fs,
    io::Write,
    path::Path,
};

use crate::{
    app::App,
    archive::{decrypt_archive, embedded_app_key, encrypt_archive, ArchiveKind, BackupPayload},
    cli::{BackupCommand, BackupCreateArgs, BackupRestoreArgs},
    error::{Error, Result},
    terminal::prompt::Prompt,
};

pub fn run(
    app: &App,
    prompt: &dyn Prompt,
    command: &BackupCommand,
    writer: &mut dyn Write,
) -> Result<()> {
    match command {
        BackupCommand::Create(args) => create(app, prompt, args, writer),
        BackupCommand::Restore(args) => restore(app, prompt, args, writer),
    }
}

fn create(
    app: &App,
    prompt: &dyn Prompt,
    args: &BackupCreateArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    ensure_output_does_not_exist(&args.output)?;
    let psk = prompt_psk_with_confirmation(prompt, "backup.create.psk")?;
    let payload = app.create_backup_snapshot()?;
    let archive = encrypt_archive(&payload, ArchiveKind::Backup, &psk, &embedded_app_key()?)?;
    fs::write(&args.output, archive)?;
    writeln!(writer, "Wrote backup to '{}'.", args.output.display()).map_err(Error::from)
}

fn restore(
    app: &App,
    prompt: &dyn Prompt,
    args: &BackupRestoreArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    if !args.yes
        && !prompt.confirm(
            "backup.restore.confirm",
            "Restore will replace all profiles, forwards, host keys, and stored secrets. Continue?",
            false,
        )?
    {
        writeln!(writer, "Aborted.").map_err(Error::from)?;
        return Ok(());
    }

    let psk = prompt_psk(prompt, "backup.restore.psk", "Backup PSK")?;
    let archive = fs::read(&args.input)?;
    let payload: BackupPayload =
        decrypt_archive(&archive, ArchiveKind::Backup, &psk, &embedded_app_key()?)?;
    app.restore_backup_snapshot(payload)?;
    writeln!(writer, "Restored backup from '{}'.", args.input.display()).map_err(Error::from)
}

pub(crate) fn prompt_psk(
    prompt: &dyn Prompt,
    key: &str,
    message: &str,
) -> Result<String> {
    prompt
        .prompt_secret(key, message)?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::new("PSK is required"))
}

fn prompt_psk_with_confirmation(prompt: &dyn Prompt, key: &str) -> Result<String> {
    let first = prompt_psk(prompt, key, "Backup PSK")?;
    let second = prompt_psk(prompt, &format!("{key}.confirm"), "Confirm backup PSK")?;
    if first != second {
        return Err(Error::new("PSK entries did not match"));
    }
    Ok(first)
}

pub(crate) fn ensure_output_does_not_exist(path: &Path) -> Result<()> {
    if path.exists() {
        Err(Error::new(format!(
            "refusing to overwrite existing file '{}'",
            path.display()
        )))
    } else {
        Ok(())
    }
}
