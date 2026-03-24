use std::{fs, io::Write};

use crate::{
    app::{App, ProfileSecretsInput},
    cli::EditArgs,
    error::{Error, Result},
    store::ProfileInput,
    terminal::prompt::Prompt,
};

use super::add::{validate_non_empty, validate_port};

pub fn run(app: &App, _prompt: &dyn Prompt, args: &EditArgs, writer: &mut dyn Write) -> Result<()> {
    let existing = app.get_profile(&args.name)?;
    let name = validate_non_empty("name", args.name.clone())?;
    let host = match &args.host {
        Some(host) => validate_non_empty("host", host.clone())?,
        None => existing.host,
    };
    let user = match &args.user {
        Some(user) => validate_non_empty("user", user.clone())?,
        None => existing.username,
    };
    let port = validate_port(args.port.unwrap_or(existing.port))?;

    let secrets = ProfileSecretsInput {
        password: match &args.password {
            Some(password) => Some(validate_non_empty("password", password.clone())?),
            None => None,
        },
        private_key: match &args.private_key {
            Some(path) => Some(fs::read_to_string(path)?),
            None => None,
        },
        key_passphrase: match &args.key_passphrase {
            Some(passphrase) => Some(validate_non_empty("key passphrase", passphrase.clone())?),
            None => None,
        },
    };

    let mut profile = ProfileInput::new(name.clone(), host, user).with_port(port);
    profile.has_password = existing.has_password;
    profile.has_private_key = existing.has_private_key;
    profile.has_key_passphrase = existing.has_key_passphrase;

    let _ = app.save_profile_with_secrets(profile, secrets)?;
    writeln!(writer, "Updated profile '{name}'.").map_err(Error::from)
}
