use std::fmt;

use crate::{
    error::{Error, Result},
    store::{ForwardDefinition, ForwardKind},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardSpec {
    Local {
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
    Socks {
        bind_host: String,
        bind_port: u16,
    },
}

impl ForwardSpec {
    pub fn parse_local(value: &str) -> Result<Self> {
        let mut parts = value.split(':');
        let bind_host = validate_non_empty("bind_host", parts.next().unwrap_or_default())?;
        let bind_port = parse_port("bind_port", parts.next())?;
        let target_host = validate_non_empty("target_host", parts.next().unwrap_or_default())?;
        let target_port = parse_port("target_port", parts.next())?;

        if parts.next().is_some() {
            return Err(Error::new(
                "local forward specs must be bind_host:bind_port:target_host:target_port",
            ));
        }

        Ok(Self::Local {
            bind_host,
            bind_port,
            target_host,
            target_port,
        })
    }

    pub fn parse_socks(value: &str) -> Result<Self> {
        let mut parts = value.split(':');
        let bind_host = validate_non_empty("bind_host", parts.next().unwrap_or_default())?;
        let bind_port = parse_port("bind_port", parts.next())?;

        if parts.next().is_some() {
            return Err(Error::new("socks specs must be bind_host:bind_port"));
        }

        Ok(Self::Socks {
            bind_host,
            bind_port,
        })
    }

    pub fn into_definition(
        self,
        profile_name: impl Into<String>,
        name: impl Into<String>,
        description: Option<String>,
    ) -> ForwardDefinition {
        match self {
            Self::Local {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => ForwardDefinition {
                profile_name: profile_name.into(),
                name: name.into(),
                kind: ForwardKind::Local,
                bind_host,
                bind_port,
                target_host: Some(target_host),
                target_port: Some(target_port),
                description,
            },
            Self::Socks {
                bind_host,
                bind_port,
            } => ForwardDefinition {
                profile_name: profile_name.into(),
                name: name.into(),
                kind: ForwardKind::Socks,
                bind_host,
                bind_port,
                target_host: None,
                target_port: None,
                description,
            },
        }
    }
}

impl fmt::Display for ForwardSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => write!(f, "local {bind_host}:{bind_port} -> {target_host}:{target_port}"),
            Self::Socks {
                bind_host,
                bind_port,
            } => write!(f, "socks {bind_host}:{bind_port}"),
        }
    }
}

fn validate_non_empty(field: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(Error::new(format!("{field} cannot be empty")))
    } else {
        Ok(trimmed.to_string())
    }
}

fn parse_port(field: &str, value: Option<&str>) -> Result<u16> {
    let value = value.ok_or_else(|| Error::new(format!("{field} is required")))?;
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::new(format!("{field} must be between 1 and 65535")))?;

    if port == 0 {
        Err(Error::new(format!("{field} must be between 1 and 65535")))
    } else {
        Ok(port)
    }
}

