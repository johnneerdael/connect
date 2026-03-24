use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("remote session exited with status {0}")]
    RemoteExitStatus(u32),
    #[error("unable to resolve per-user application directories")]
    MissingAppDirectories,
    #[error("profile '{0}' was not found")]
    ProfileNotFound(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Keyring(#[from] keyring_core::Error),
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
