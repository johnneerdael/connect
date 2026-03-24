use std::{fs, io::Write};

use crate::{
    app::{App, ProfileSecretsInput},
    cli::AddArgs,
    error::{Error, Result},
    store::ProfileInput,
    terminal::prompt::Prompt,
};

pub fn run(app: &App, prompt: &dyn Prompt, args: &AddArgs, writer: &mut dyn Write) -> Result<()> {
    let name = validate_profile_name(require_value("name", Some(args.name.clone()))?)?;
    match app.get_profile(&name) {
        Ok(_) => return Err(Error::new(format!("profile '{name}' already exists"))),
        Err(Error::ProfileNotFound(_)) => {}
        Err(error) => return Err(error),
    }
    let host = match &args.host {
        Some(host) => validate_non_empty("host", host.clone())?,
        None => require_value("host", Some(prompt.prompt("host", "Host", None)?))?,
    };
    let user = match &args.user {
        Some(user) => validate_non_empty("user", user.clone())?,
        None => require_value("user", Some(prompt.prompt("user", "Username", None)?))?,
    };
    let port = validate_port(args.port.unwrap_or(22))?;

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

    let profile = ProfileInput::new(name.clone(), host, user).with_port(port);
    let _ = app.save_profile_with_secrets(profile, secrets)?;
    writeln!(writer, "Added profile '{name}'.").map_err(Error::from)
}

fn require_value(field: &str, value: Option<String>) -> Result<String> {
    match value {
        Some(value) => validate_non_empty(field, value),
        None => Err(Error::new(format!("{field} is required"))),
    }
}

pub(crate) fn validate_profile_name(value: String) -> Result<String> {
    let name = validate_non_empty("name", value)?;
    if RESERVED_PROFILE_NAMES.contains(&name.as_str()) {
        Err(Error::new(format!("profile name '{name}' is reserved")))
    } else {
        Ok(name)
    }
}

pub(crate) fn validate_non_empty(field: &str, value: String) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(Error::new(format!("{field} cannot be empty")))
    } else {
        Ok(trimmed.to_string())
    }
}

pub(crate) fn validate_port(port: u16) -> Result<u16> {
    if port == 0 {
        Err(Error::new("port must be between 1 and 65535"))
    } else {
        Ok(port)
    }
}

const RESERVED_PROFILE_NAMES: &[&str] = &[
    "add",
    "edit",
    "remove",
    "list",
    "show",
    "copy",
    "hostkeys",
    "completion",
    "version",
    "help",
];
