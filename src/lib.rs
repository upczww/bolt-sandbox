//! Public Rust integration boundary for Bolt Sandbox.

mod error;
mod event;
mod execution;
mod ipc;
mod policy;
mod request;
mod runtime;

pub use error::{InvalidRequestReason, RequestField, SandboxError};
pub use event::{
    ChildInjectionFailure, ChildInjectionFailureReason, EventsDropped, FilesystemOperation,
    FilesystemViolation, NetworkOperation, NetworkTarget, NetworkViolation, ProcessExit,
    ProcessExitReason, ProcessOperation, ProcessViolation, RecoveryArtifact, RecoveryFailure,
    RecoveryFailureReason, RegistryOperation, RegistryViolation, SandboxEvent,
};
pub use execution::{
    ByteStream, ConfigurationErrorReason, ConfigurationField, DEFAULT_STREAM_CAPACITY, EventStream,
    ExecutionControlError, ExecutionHandle, ExecutionResult, ExecutionTerminal,
    InfrastructureFailure, InitializationStage, ReceiverLoss, Sandbox, SandboxConfig,
};
pub use policy::{
    ChildProcessPolicy, FilesystemPolicy, IpCidr, NetworkAllowList, NetworkPolicy, PortRange,
    RecoveryLimits, RecoveryPolicy, RegistryPolicy, SandboxPolicy,
};
pub use request::{MAX_TIMEOUT, MIN_TIMEOUT, SandboxRequest};
