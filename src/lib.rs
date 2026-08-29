//! Public Rust integration boundary for Bolt Sandbox.

mod error;
mod event;
mod ipc;
mod policy;
mod request;
mod runtime;

pub use error::{InvalidRequestReason, RequestField, SandboxError};
pub use event::{
    ChildInjectionFailure, ChildInjectionFailureReason, FilesystemOperation, FilesystemViolation,
    NetworkOperation, NetworkTarget, NetworkViolation, ProcessExit, ProcessExitReason,
    RecoveryArtifact, RegistryOperation, RegistryViolation, SandboxEvent,
};
pub use policy::{
    ChildProcessPolicy, FilesystemPolicy, IpCidr, NetworkAllowList, NetworkPolicy, PortRange,
    RecoveryLimits, RecoveryPolicy, RegistryPolicy, SandboxPolicy,
};
pub use request::{MAX_TIMEOUT, MIN_TIMEOUT, SandboxRequest};
