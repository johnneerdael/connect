use std::io::{self, Write};

use crate::error::{Error, Result};
use crate::ssh::ObservedHostKey;

pub trait Prompt {
    fn prompt(&self, key: &str, message: &str, default: Option<&str>) -> Result<String>;
    fn prompt_secret(&self, key: &str, message: &str) -> Result<Option<String>>;
    fn confirm(&self, key: &str, message: &str, default: bool) -> Result<bool>;

    fn confirm_host_key_trust(&self, host_key: &ObservedHostKey) -> Result<bool> {
        self.confirm(
            "hostkey.trust",
            &format!(
                "Trust this host key?\nHost: {}\nPort: {}\nAlgorithm: {}\nFingerprint: {}",
                host_key.host, host_key.port, host_key.algorithm, host_key.fingerprint
            ),
            false,
        )
    }
}

#[derive(Debug, Default)]
pub struct StdioPrompt;

impl StdioPrompt {
    pub fn new() -> Self {
        Self
    }
}

impl Prompt for StdioPrompt {
    fn prompt(&self, _key: &str, message: &str, default: Option<&str>) -> Result<String> {
        let mut stdout = io::stdout().lock();
        if let Some(default) = default {
            write!(stdout, "{message} [{default}]: ")?;
        } else {
            write!(stdout, "{message}: ")?;
        }
        stdout.flush()?;

        let input = read_line()?;
        if input.trim().is_empty() {
            default
                .map(|value| value.to_string())
                .ok_or_else(|| Error::new(format!("{message} is required")))
        } else {
            Ok(input.trim().to_string())
        }
    }

    fn prompt_secret(&self, _key: &str, message: &str) -> Result<Option<String>> {
        let input = rpassword::prompt_password(format!("{message}: "))?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed.to_string()))
        }
    }

    fn confirm(&self, _key: &str, message: &str, default: bool) -> Result<bool> {
        let default_hint = if default { "Y/n" } else { "y/N" };
        let mut stdout = io::stdout().lock();
        write!(stdout, "{message} [{default_hint}]: ")?;
        stdout.flush()?;

        let input = read_line()?;
        let trimmed = input.trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            Ok(default)
        } else if matches!(trimmed.as_str(), "y" | "yes") {
            Ok(true)
        } else if matches!(trimmed.as_str(), "n" | "no") {
            Ok(false)
        } else {
            Err(Error::new("please answer yes or no"))
        }
    }
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}
