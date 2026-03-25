use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use directories::ProjectDirs;

use crate::{
    cli::{
        commands::{
            add, completion, copy, doctor, edit, exec, forward, hostkeys, list, open, remove, show,
            version,
        },
        Cli, Command, HostkeysCommand,
    },
    error::{Error, Result},
    secrets::{KeyringSecretStore, SecretStore},
    ssh::{
        copy_profile as ssh_copy_profile, exec_profile as ssh_exec_profile,
        open_profile as ssh_open_profile, CopySpec, ExecSpec, ProfileAuth, SshClient,
        SshConnectionContext,
    },
    store::{
        Database, ForwardDefinition, ForwardStore, HostKeyStore, Profile, ProfileInput,
        ProfileStore,
    },
    terminal::prompt::StdioPrompt,
};

const APP_NAME: &str = "connect";
const DATABASE_FILE: &str = "connect.db";
const APP_ROOT_ENV: &str = "CONNECT_APP_ROOT";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
}

impl AppPaths {
    pub fn detect() -> Result<Self> {
        if let Some(root) = env::var_os(APP_ROOT_ENV) {
            return Ok(Self::from_root(Path::new(&root)));
        }

        let project_dirs =
            ProjectDirs::from("", "", APP_NAME).ok_or(Error::MissingAppDirectories)?;
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
    forward_store: ForwardStore,
    hostkey_store: HostKeyStore,
    secrets: Arc<dyn SecretStore>,
    secret_backend: SecretBackend,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileSecretsInput {
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub key_passphrase: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProfileSecretSnapshot {
    password: Option<String>,
    private_key: Option<String>,
    key_passphrase: Option<String>,
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
            forward_store: ForwardStore::new(database.clone()),
            hostkey_store: HostKeyStore::new(database),
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

    pub fn save_forward(&self, definition: ForwardDefinition) -> Result<ForwardDefinition> {
        self.validate_forward_definition(&definition)?;
        self.get_profile(&definition.profile_name)?;
        self.forward_store.save(&definition)?;
        self.get_forward(&definition.profile_name, &definition.name)
    }

    pub fn get_forward(&self, profile_name: &str, name: &str) -> Result<ForwardDefinition> {
        self.get_profile(profile_name)?;
        self.forward_store.get(profile_name, name)?.ok_or_else(|| {
            Error::new(format!(
                "forward '{name}' was not found for profile '{profile_name}'"
            ))
        })
    }

    pub fn list_forwards(&self, profile_name: &str) -> Result<Vec<ForwardDefinition>> {
        self.get_profile(profile_name)?;
        self.forward_store.list(profile_name)
    }

    pub fn delete_forward(&self, profile_name: &str, name: &str) -> Result<bool> {
        self.get_profile(profile_name)?;
        self.forward_store.delete(profile_name, name)
    }

    pub fn save_profile_with_secrets(
        &self,
        mut profile: ProfileInput,
        secrets: ProfileSecretsInput,
    ) -> Result<Profile> {
        let name = profile.name.clone();
        let snapshot = self.capture_profile_secrets(&name)?;

        if let Err(error) = self.apply_profile_secrets(&name, &secrets) {
            return self.finish_with_rollback(&name, &snapshot, error);
        }

        profile.has_password = secrets.password.is_some() || snapshot.password.is_some();
        profile.has_private_key = secrets.private_key.is_some() || snapshot.private_key.is_some();
        profile.has_key_passphrase =
            secrets.key_passphrase.is_some() || snapshot.key_passphrase.is_some();

        match self.save_profile(profile) {
            Ok(saved) => Ok(saved),
            Err(error) => self.finish_with_rollback(&name, &snapshot, error),
        }
    }

    pub fn update_profile_secret_flags(
        &self,
        name: &str,
        has_password: bool,
        has_private_key: bool,
        has_key_passphrase: bool,
    ) -> Result<Profile> {
        let profile = self.get_profile(name)?;
        let mut updated =
            ProfileInput::new(profile.name, profile.host, profile.username).with_port(profile.port);
        updated.auth_mode = profile.auth_mode;
        updated.has_password = has_password;
        updated.has_private_key = has_private_key;
        updated.has_key_passphrase = has_key_passphrase;
        self.save_profile(updated)
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

    pub fn save_host_key(
        &self,
        host: &str,
        port: u16,
        algorithm: &str,
        fingerprint: &str,
        public_key: &str,
    ) -> Result<()> {
        self.hostkey_store
            .save(host, port, algorithm, fingerprint, public_key)
    }

    pub fn list_host_keys(&self) -> Result<Vec<crate::store::HostKeyRecord>> {
        self.hostkey_store.list()
    }

    pub fn delete_host_key_by_id(&self, id: i64) -> Result<bool> {
        self.hostkey_store.delete(id)
    }

    pub fn delete_host_key(&self, host: &str, port: u16) -> Result<bool> {
        self.hostkey_store.delete_host_port(host, port)
    }

    pub async fn open_profile(
        &self,
        name: &str,
        ssh: &dyn SshClient,
        prompt: &dyn crate::terminal::prompt::Prompt,
    ) -> Result<()> {
        let profile = self.get_profile(name)?;
        ssh_open_profile(ssh, &profile, self, prompt).await
    }

    pub async fn connect_profile(
        &self,
        name: &str,
        ssh: &dyn SshClient,
        prompt: &dyn crate::terminal::prompt::Prompt,
    ) -> Result<()> {
        self.open_profile(name, ssh, prompt).await
    }

    pub async fn exec(
        &self,
        name: &str,
        spec: &ExecSpec,
        ssh: &dyn SshClient,
        prompt: &dyn crate::terminal::prompt::Prompt,
    ) -> Result<()> {
        let profile = self.get_profile(name)?;
        ssh_exec_profile(ssh, spec, &profile, self, prompt).await
    }

    pub async fn copy(
        &self,
        spec: &CopySpec,
        ssh: &dyn SshClient,
        prompt: &dyn crate::terminal::prompt::Prompt,
    ) -> Result<crate::ssh::CopySummary> {
        let profile = self.get_profile(spec.remote_profile())?;
        ssh_copy_profile(ssh, spec, &profile, self, prompt).await
    }
}

impl App {
    fn capture_profile_secrets(&self, name: &str) -> Result<ProfileSecretSnapshot> {
        Ok(ProfileSecretSnapshot {
            password: self.secrets.get_password(name)?,
            private_key: self.secrets.get_private_key(name)?,
            key_passphrase: self.secrets.get_key_passphrase(name)?,
        })
    }

    fn apply_profile_secrets(&self, name: &str, secrets: &ProfileSecretsInput) -> Result<()> {
        if let Some(password) = &secrets.password {
            self.secrets.set_password(name, password)?;
        }

        if let Some(private_key) = &secrets.private_key {
            self.secrets.set_private_key(name, private_key)?;
        }

        if let Some(key_passphrase) = &secrets.key_passphrase {
            self.secrets.set_key_passphrase(name, key_passphrase)?;
        }

        Ok(())
    }

    fn restore_profile_secrets(&self, name: &str, snapshot: &ProfileSecretSnapshot) -> Result<()> {
        self.secrets.delete_profile_secrets(name)?;

        if let Some(password) = &snapshot.password {
            self.secrets.set_password(name, password)?;
        }

        if let Some(private_key) = &snapshot.private_key {
            self.secrets.set_private_key(name, private_key)?;
        }

        if let Some(key_passphrase) = &snapshot.key_passphrase {
            self.secrets.set_key_passphrase(name, key_passphrase)?;
        }

        Ok(())
    }

    fn finish_with_rollback<T>(
        &self,
        name: &str,
        snapshot: &ProfileSecretSnapshot,
        primary_error: Error,
    ) -> Result<T> {
        match self.restore_profile_secrets(name, snapshot) {
            Ok(()) => Err(primary_error),
            Err(rollback_error) => Err(Error::new(format!(
                "{} (rollback failed: {})",
                primary_error, rollback_error
            ))),
        }
    }

    fn load_profile_auth(&self, profile: &Profile) -> Result<ProfileAuth> {
        Ok(ProfileAuth {
            auth_mode: profile.auth_mode,
            password: self.secrets.get_password(&profile.name)?,
            private_key: self.secrets.get_private_key(&profile.name)?,
            key_passphrase: self.secrets.get_key_passphrase(&profile.name)?,
        })
    }

    pub fn agent_auth_status(&self) -> &'static str {
        if crate::ssh::agent_auth_available() {
            "available"
        } else {
            "not available"
        }
    }

    fn validate_forward_definition(&self, definition: &ForwardDefinition) -> Result<()> {
        match definition.kind {
            crate::store::ForwardKind::Local => {
                if definition.target_host.is_none() || definition.target_port.is_none() {
                    return Err(Error::new(
                        "local forward requires target_host and target_port",
                    ));
                }
            }
            crate::store::ForwardKind::Socks => {
                if definition.target_host.is_some() || definition.target_port.is_some() {
                    return Err(Error::new(
                        "socks forward must not include target_host or target_port",
                    ));
                }
            }
        }

        Ok(())
    }
}

impl SshConnectionContext for App {
    fn load_profile_auth(&self, profile: &Profile) -> Result<ProfileAuth> {
        App::load_profile_auth(self, profile)
    }

    fn load_host_key(&self, profile: &Profile) -> Result<Option<crate::store::HostKeyRecord>> {
        self.hostkey_store.get(&profile.host, profile.port)
    }

    fn save_host_key(&self, observed: &crate::ssh::ObservedHostKey) -> Result<()> {
        self.hostkey_store.save(
            &observed.host,
            observed.port,
            &observed.algorithm,
            &observed.fingerprint,
            &observed.public_key,
        )
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let prompt = StdioPrompt::new();
    let mut stdout = std::io::stdout();

    match cli.command {
        Some(Command::Add(args)) => {
            let app = App::load()?;
            add::run(&app, &prompt, &args, &mut stdout)
        }
        Some(Command::Doctor(args)) => {
            let report = doctor::run(&args, &mut stdout)?;
            if report.exit_code() == 0 {
                Ok(())
            } else {
                Err(Error::new(format!(
                    "doctor checks failed (exit code {})",
                    report.exit_code()
                )))
            }
        }
        Some(Command::Edit(args)) => {
            let app = App::load()?;
            edit::run(&app, &prompt, &args, &mut stdout)
        }
        Some(Command::Remove(args)) => {
            let app = App::load()?;
            remove::run(&app, &prompt, &args, &mut stdout)
        }
        Some(Command::List(_args)) => {
            let app = App::load()?;
            list::run(&app, &mut stdout)
        }
        Some(Command::Show(args)) => {
            let app = App::load()?;
            show::run(&app, &args, &mut stdout)
        }
        Some(Command::Open(args)) => {
            let app = App::load()?;
            open::run(&app, &prompt, &args.profile)
        }
        Some(Command::Exec(args)) => {
            let app = App::load()?;
            exec::run(&app, &prompt, &args)
        }
        Some(Command::Hostkeys(args)) => {
            let app = App::load()?;
            let command = args
                .command
                .unwrap_or(HostkeysCommand::List(Default::default()));
            hostkeys::run(&app, &prompt, &command, &mut stdout)
        }
        Some(Command::Completion(args)) => completion::run(&args),
        Some(Command::Version) => version::run(),
        Some(Command::Copy(args)) => {
            let app = App::load()?;
            copy::run(&app, &prompt, &args)
        }
        Some(Command::Forward(args)) => {
            let app = App::load()?;
            forward::run(&app, &prompt, &args, &mut stdout)
        }
        None => {
            let app = App::load()?;
            match cli.profile {
                Some(profile) => open::run(&app, &prompt, &profile),
                None => Ok(()),
            }
        }
    }
}
