use std::{
    fs,
    io::{self, Write},
    net::IpAddr,
};

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
        Some(host) => validate_host(host.clone())?,
        None => validate_host(require_value(
            "host",
            Some(prompt.prompt("host", "Host", None)?),
        )?)?,
    };
    let user = match &args.user {
        Some(user) => validate_non_empty("user", user.clone())?,
        None => require_value("user", Some(prompt.prompt("user", "Username", None)?))?,
    };
    let port = validate_port(args.port.unwrap_or(22))?;

    let secrets = ProfileSecretsInput {
        password: secret_value(
            prompt,
            "password",
            "Password (stored securely)",
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
            "Key passphrase (stored securely)",
            args.key_passphrase,
            args.key_passphrase_stdin,
        )?,
    };

    let profile = ProfileInput::new(name.clone(), host, user)
        .with_port(port)
        .with_auth_mode(args.auth_mode);
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
    } else if is_windows_drive_profile_name(&name) {
        Err(Error::new(
            "single-letter profile names are reserved to avoid Windows path ambiguity",
        ))
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

pub(crate) fn validate_host(value: String) -> Result<String> {
    let host = validate_non_empty("host", value)?;
    if host.parse::<IpAddr>().is_ok() || is_valid_hostname(&host) {
        Ok(host)
    } else {
        Err(Error::new(
            "host must be a valid hostname, fqdn, or IP address",
        ))
    }
}

pub(crate) fn validate_port(port: u16) -> Result<u16> {
    if port == 0 {
        Err(Error::new("port must be between 1 and 65535"))
    } else {
        Ok(port)
    }
}

pub(crate) fn is_windows_drive_profile_name(name: &str) -> bool {
    name.len() == 1
        && name
            .chars()
            .next()
            .is_some_and(|value| value.is_ascii_alphabetic())
}

fn is_valid_hostname(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return false;
    }
    if host.len() > 253 {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    })
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
    io::stdin().read_line(&mut input)?;
    match input.trim() {
        "" => Ok(None),
        value => Ok(Some(validate_non_empty(key, value.to_string())?)),
    }
}

const RESERVED_PROFILE_NAMES: &[&str] = &[
    "add",
    "open",
    "exec",
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
