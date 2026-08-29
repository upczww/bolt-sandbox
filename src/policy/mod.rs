mod filesystem;
mod network;
mod registry;

use std::path::PathBuf;

pub use filesystem::FilesystemPolicy;
pub use network::{NetworkAllowList, NetworkPolicy};
pub use registry::RegistryPolicy;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPolicy {
    pub filesystem: FilesystemPolicy,
    pub registry: RegistryPolicy,
    pub network: NetworkPolicy,
    pub child_processes: ChildProcessPolicy,
    pub recovery: RecoveryPolicy,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            filesystem: FilesystemPolicy::default(),
            registry: RegistryPolicy::default(),
            network: NetworkPolicy::default(),
            child_processes: ChildProcessPolicy::default(),
            recovery: RecoveryPolicy::default(),
        }
    }
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
}
