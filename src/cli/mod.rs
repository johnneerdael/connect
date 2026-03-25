pub mod commands {
    pub mod add;
    pub mod completion;
    pub mod copy;
    pub mod edit;
    pub mod exec;
    pub mod hostkeys;
    pub mod list;
    pub mod open;
    pub mod remove;
    pub mod show;
    pub mod version;
}

pub mod types;

pub use types::{
    AddArgs, Cli, Command, CompletionArgs, CopyArgs, EditArgs, ExecArgs, HostkeysArgs,
    HostkeysCommand, HostkeysDeleteArgs, HostkeysListArgs, ListArgs, OpenArgs, RemoveArgs,
    ShowArgs,
};
