use std::{fs, io::Write};

use crate::{
    app::{App, ProfileSecretsInput},
    cli::EditArgs,
    error::{Error, Result},
    store::ProfileInput,
    terminal::prompt::Prompt,
};

use super::add::{
    is_windows_drive_profile_name, validate_host, validate_non_empty, validate_port,
    validate_profile_name,
};

pub fn run(app: &App, prompt: &dyn Prompt, args: &EditArgs, writer: &mut dyn Write) -> Result<()> {
    let existing = app.get_profile(&args.name)?;
    let name = if is_windows_drive_profile_name(&existing.name) {
        existing.name.clone()
    } else {
        validate_profile_name(args.name.clone())?
    };
    let host = match &args.host {
        Some(host) => validate_host(host.clone())?,
        None => existing.host,
    };
    let user = match &args.user {
        Some(user) => validate_non_empty("user", user.clone())?,
        None => existing.username,
    };
    let port = validate_port(args.port.unwrap_or(existing.port))?;
    let auth_mode = args.auth_mode.unwrap_or(existing.auth_mode);

    let secrets = ProfileSecretsInput {
        password: secret_value(
            prompt,
            "password",
            "Password (leave blank to keep current value)",
            args.password,
            args.password_stdin,
        )?,
        private_key: match &args.private_key {
            Some(path) => Some(fs::read_to_string(path)?),
            None => None,
        },
        key_passphrase: secret_value(
            prompt,
            "key_passphrase",
            "Key passphrase (leave blank to keep current value)",
            args.key_passphrase,
            args.key_passphrase_stdin,
        )?,
    };

    let mut profile = ProfileInput::new(name.clone(), host, user)
        .with_port(port)
        .with_auth_mode(auth_mode);
    profile.has_password = existing.has_password;
    profile.has_private_key = existing.has_private_key;
    profile.has_key_passphrase = existing.has_key_passphrase;

    let _ = app.save_profile_with_secrets(profile, secrets)?;
    writeln!(writer, "Updated profile '{name}'.").map_err(Error::from)
}

fn prompt_secret(prompt: &dyn Prompt, key: &str, message: &str) -> Result<Option<String>> {
    prompt
        .prompt_secret(key, message)?
        .map(|value| validate_non_empty(key, value))
        .transpose()
}

fn secret_value(
    prompt: &dyn Prompt,
    key: &str,
    message: &str,
    prompt_flag: bool,
    stdin_flag: bool,
) -> Result<Option<String>> {
    match (prompt_flag, stdin_flag) {
        (true, true) => Err(Error::new(format!(
            "{key} cannot be read from both prompt and stdin"
        ))),
        (true, false) => prompt_secret(prompt, key, message),
        (false, true) => stdin_secret(key),
        (false, false) => Ok(None),
    }
}

fn stdin_secret(key: &str) -> Result<Option<String>> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    match input.trim() {
        "" => Ok(None),
        value => Ok(Some(validate_non_empty(key, value.to_string())?)),
    }
}
