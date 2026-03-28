use serde::{Deserialize, Serialize};

use crate::secrets::SecretBundle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveKind {
    Backup,
    ProfileExport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPayload {
    pub profiles: Vec<BackupProfileRecord>,
    pub forwards: Vec<BackupForwardRecord>,
    pub host_keys: Vec<BackupHostKeyRecord>,
    pub secret_bundles: Vec<ProfileSecretRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileExportPayload {
    pub profile: BackupProfileRecord,
    pub forwards: Vec<BackupForwardRecord>,
    pub secret_bundle: SecretBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupProfileRecord {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_mode: String,
    pub copy_threads: usize,
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_key_passphrase: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupForwardRecord {
    pub profile_name: String,
    pub name: String,
    pub kind: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupHostKeyRecord {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub accepted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSecretRecord {
    pub profile_name: String,
    pub bundle: SecretBundle,
}
