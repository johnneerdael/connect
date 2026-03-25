pub mod commands {
    pub mod add;
    pub mod completion;
    pub mod copy;
    pub mod doctor;
    pub mod edit;
    pub mod exec;
    pub mod forward;
    pub mod hostkeys;
    pub mod list;
    pub mod open;
    pub mod remove;
    pub mod show;
    pub mod version;
}

mod runtime;
pub mod types;

pub use types::{
    AddArgs, Cli, Command, CompletionArgs, CopyArgs, DoctorArgs, EditArgs, ExecArgs,
    ForwardAddArgs, ForwardArgs, ForwardCommand, ForwardListArgs, ForwardRemoveArgs,
    ForwardRunArgs, HostkeysArgs, HostkeysCommand, HostkeysDeleteArgs, HostkeysListArgs, ListArgs,
    OpenArgs, RemoveArgs, ShowArgs,
};
