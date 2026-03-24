#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileInput {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
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
            has_password: false,
            has_private_key: false,
            has_key_passphrase: false,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
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
