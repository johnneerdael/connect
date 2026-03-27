use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    #[default]
    Auto,
    AgentOnly,
    StoredOnly,
    PasswordOnly,
}

impl AuthMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::AgentOnly => "agent-only",
            Self::StoredOnly => "stored-only",
            Self::PasswordOnly => "password-only",
        }
    }
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "agent-only" => Ok(Self::AgentOnly),
            "stored-only" => Ok(Self::StoredOnly),
            "password-only" => Ok(Self::PasswordOnly),
            _ => Err(format!(
                "invalid auth mode '{value}' (expected auto, agent-only, stored-only, or password-only)"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileInput {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_mode: AuthMode,
    pub copy_threads: Option<usize>,
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_key_passphrase: bool,
}

impl ProfileInput {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port: 22,
            username: username.into(),
            auth_mode: AuthMode::Auto,
            copy_threads: None,
            has_password: false,
            has_private_key: false,
            has_key_passphrase: false,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_auth_mode(mut self, auth_mode: AuthMode) -> Self {
        self.auth_mode = auth_mode;
        self
    }

    pub fn with_copy_threads(mut self, copy_threads: usize) -> Self {
        self.copy_threads = Some(copy_threads);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_mode: AuthMode,
    pub copy_threads: Option<usize>,
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_key_passphrase: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyRecord {
    pub id: i64,
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub accepted_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardKind {
    Local,
    Socks,
}

impl ForwardKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Socks => "socks",
        }
    }
}

impl fmt::Display for ForwardKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ForwardKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local" => Ok(Self::Local),
            "socks" | "socks5" => Ok(Self::Socks),
            _ => Err(format!(
                "invalid forward kind '{value}' (expected local or socks)"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardDefinition {
    pub profile_name: String,
    pub name: String,
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub description: Option<String>,
}
