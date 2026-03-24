use std::{fs, path::{Path, PathBuf}, sync::Arc};

use clap::Parser;
use directories::ProjectDirs;

use crate::{
    cli::{
        commands::{completion, version},
        Cli, Command,
    },
    error::{Error, Result},
    secrets::{KeyringSecretStore, SecretStore},
    store::{Database, HostKeyStore, Profile, ProfileInput, ProfileStore},
};

const APP_NAME: &str = "connect";
const DATABASE_FILE: &str = "connect.db";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
}

impl AppPaths {
    pub fn detect() -> Result<Self> {
        let project_dirs = ProjectDirs::from("", "", APP_NAME).ok_or(Error::MissingAppDirectories)?;
        Ok(Self::from_project_dirs(&project_dirs))
    }

    pub fn from_project_dirs(project_dirs: &ProjectDirs) -> Self {
        #[cfg(target_os = "linux")]
        let data_dir = project_dirs.data_dir().to_path_buf();

        #[cfg(not(target_os = "linux"))]
        let data_dir = project_dirs.config_dir().to_path_buf();

        let config_dir = project_dirs.config_dir().to_path_buf();
        let database_path = data_dir.join(DATABASE_FILE);

        Self {
            config_dir,
            data_dir,
            database_path,
        }
    }

    pub fn from_root(root: &Path) -> Self {
        let config_dir = root.join("config");
        let data_dir = root.join("data");
        let database_path = data_dir.join(DATABASE_FILE);

        Self {
            config_dir,
            data_dir,
            database_path,
        }
    }

    fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        fs::create_dir_all(&self.data_dir)?;
        Ok(())
    }
}

pub struct App {
    _paths: AppPaths,
    profile_store: ProfileStore,
    _hostkey_store: HostKeyStore,
    secrets: Arc<dyn SecretStore>,
    secret_backend: SecretBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretBackend {
    Keyring,
    Custom,
}

impl App {
    pub fn new(paths: AppPaths, secrets: Arc<dyn SecretStore>) -> Result<Self> {
        Self::new_with_backend(paths, secrets, SecretBackend::Custom)
    }

    pub fn with_default_secret_store(paths: AppPaths) -> Result<Self> {
        let secrets = Arc::new(KeyringSecretStore::new(APP_NAME)?);
        Self::new_with_backend(paths, secrets, SecretBackend::Keyring)
    }

    pub fn load() -> Result<Self> {
        let paths = AppPaths::detect()?;
        Self::with_default_secret_store(paths)
    }

    pub fn secret_backend(&self) -> SecretBackend {
        self.secret_backend
    }

    fn new_with_backend(
        paths: AppPaths,
        secrets: Arc<dyn SecretStore>,
        secret_backend: SecretBackend,
    ) -> Result<Self> {
        paths.ensure_directories()?;

        let database = Database::new(paths.database_path.clone());
        database.initialize()?;

        Ok(Self {
            _paths: paths,
            profile_store: ProfileStore::new(database.clone()),
            _hostkey_store: HostKeyStore::new(database),
            secrets,
            secret_backend,
        })
    }

    pub fn save_profile(&self, profile: ProfileInput) -> Result<Profile> {
        self.profile_store.save(&profile)?;
        self.get_profile(&profile.name)
    }

    pub fn get_profile(&self, name: &str) -> Result<Profile> {
        self.profile_store
            .get(name)?
            .ok_or_else(|| Error::ProfileNotFound(name.to_string()))
    }

    pub fn list_profiles(&self) -> Result<Vec<Profile>> {
        self.profile_store.list()
    }

    pub fn delete_profile(&self, name: &str) -> Result<()> {
        self.get_profile(name)?;

        self.secrets.delete_profile_secrets(name)?;

        let deleted = self.profile_store.delete(name)?;
        if deleted {
            Ok(())
        } else {
            Err(Error::ProfileNotFound(name.to_string()))
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Completion) => completion::run(),
        Some(Command::Version) => version::run(),
        Some(Command::Add)
        | Some(Command::Edit)
        | Some(Command::Remove)
        | Some(Command::List)
        | Some(Command::Show)
        | Some(Command::Copy)
        | Some(Command::Hostkeys) => {
            let _app = App::load()?;
            Ok(())
        }
        None => {
            let _profile = cli.profile;
            let _app = App::load()?;
            Ok(())
        }
    }
}
