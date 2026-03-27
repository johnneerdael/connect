mod auth;
mod client;
mod copy;
mod hostkeys;
mod parallel;

pub(crate) use auth::connect_authenticated_session;
pub use auth::{
    authenticate_session, exec_profile, open_profile, ExecSpec, ProfileAuth, SshConnectionContext,
};
pub use client::{
    agent_auth_available, agent_connection_available, DirectTcpipStream, RusshClient, SshClient,
    SshSession,
};
pub use copy::{
    copy_profile, parse_copy_spec, plan_copy, CopyCheckpointIdentity, CopyDirection, CopyEndpoint,
    CopyJob, CopyJobPolicy, CopyPlan, CopyPlanMode, CopyPlannerConfig, CopyResumeStrategy,
    CopyRetryStrategy, CopySpec, CopySummary, CopyTransferOptions, CopyTransferResult,
    PlannedCopySource, PlannedCopyTreeEntry, RemoteDirectoryEntry, RemoteFileType, RemotePath,
};
pub use hostkeys::{
    verify_observed_host_key, HostKeyVerification, ObservedHostKey, ObservedHostKeySource,
};
