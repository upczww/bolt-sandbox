pub(crate) mod compiler;
mod filesystem;
mod network;
mod registry;

use std::{path::PathBuf, time::Duration};

pub use filesystem::FilesystemPolicy;
pub use network::{IpCidr, NetworkAllowList, NetworkPolicy, PortRange};
pub use registry::RegistryPolicy;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SandboxPolicy {
    pub filesystem: FilesystemPolicy,
    pub registry: RegistryPolicy,
    pub network: NetworkPolicy,
    pub child_processes: ChildProcessPolicy,
    pub recovery: RecoveryPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ChildProcessPolicy {
    #[default]
    Inherit,
    Deny,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum RecoveryPolicy {
    #[default]
    Disabled,
    Enabled(RecoveryLimits),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryLimits {
    pub directory: PathBuf,
    pub maximum_bytes: u64,
    pub maximum_items: u32,
    pub retention: Duration,
}
