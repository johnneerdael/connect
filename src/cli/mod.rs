pub mod commands {
    pub mod add;
    pub mod completion;
    pub mod connect;
    pub mod copy;
    pub mod edit;
    pub mod hostkeys;
    pub mod list;
    pub mod remove;
    pub mod show;
    pub mod version;
}

pub mod types;

pub use types::{
    AddArgs, Cli, Command, CopyArgs, EditArgs, HostkeysArgs, HostkeysCommand,
    HostkeysDeleteArgs, HostkeysListArgs, ListArgs, RemoveArgs, ShowArgs,
};
