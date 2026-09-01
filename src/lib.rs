//! Public Rust integration boundary for Bolt Sandbox.

mod attribution;
mod error;
mod event;
mod execution;
mod ipc;
mod policy;
mod request;
mod runtime;

#[cfg(test)]
mod test_support;

pub use attribution::CommandId;
pub use error::{InvalidRequestReason, RequestField, SandboxError};
pub use event::{
    ChildInjectionFailure, ChildInjectionFailureReason, EventsDropped, FilesystemOperation,
    FilesystemViolation, NetworkOperation, NetworkTarget, NetworkViolation, ProcessExit,
    ProcessExitReason, ProcessOperation, ProcessViolation, RecoveryArtifact, RecoveryFailure,
    RecoveryFailureReason, RegistryOperation, RegistryViolation, SandboxEvent, ViolationAggregate,
};
pub use execution::{
    ByteStream, ConfigurationErrorReason, ConfigurationField, DEFAULT_STREAM_CAPACITY,
    DEFAULT_VIOLATION_AGGREGATE_CAPACITY, EventStream, ExecutionControlError, ExecutionHandle,
    ExecutionResult, ExecutionTerminal, InfrastructureFailure, InitializationStage,
    MAX_VIOLATION_AGGREGATE_CAPACITY, ReceiverLoss, Sandbox, SandboxConfig,
};
pub use policy::{
    ChildProcessPolicy, FilesystemPolicy, IpCidr, NetworkAllowList, NetworkPolicy, PortRange,
    RecoveryLimits, RecoveryPolicy, RegistryPolicy, SandboxPolicy,
};
pub use request::{MAX_TIMEOUT, MIN_TIMEOUT, SandboxRequest};
