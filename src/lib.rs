//! Public Rust integration boundary for Bolt Sandbox.

mod attribution;
mod compatibility;
mod error;
mod event;
mod execution;
mod ipc;
mod policy;
mod request;
mod runtime;
mod workspace;

#[cfg(test)]
mod test_support;

pub use attribution::{
    AttributedSandboxEvent, CommandId, ExecutionAttribution, ExecutionId, PolicyGeneration,
};
pub use compatibility::{
    CompatibilityCapability, CompatibilityCommandOutcome, CompatibilityContextError,
    CompatibilityGrant, CompatibilityGrantContext, CompatibilityGrantProposal,
    CompatibilityGrantResolver, CompatibilityNoPromptReason, CompatibilityResolution,
    CompatibilityUnavailable,
};
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
    ExecutionOptions, ExecutionResult, ExecutionTerminal, InfrastructureFailure,
    InitializationStage, MAX_VIOLATION_AGGREGATE_CAPACITY, PseudoConsoleSize, ReceiverLoss,
    Sandbox, SandboxConfig, TerminalMode, WorkspaceBackend, WorkspaceCapabilities, WorkspaceMode,
};
pub use policy::{
    ChildProcessPolicy, FilesystemPolicy, IpCidr, NamedPipePolicy, NetworkAllowList, NetworkPolicy,
    PortRange, RecoveryLimits, RecoveryPolicy, RegistryPolicy, SandboxPolicy,
};
pub use request::{MAX_TIMEOUT, MIN_TIMEOUT, SandboxRequest};
pub use workspace::{
    WorkspaceChange, WorkspaceChangeKind, WorkspaceControlError, WorkspaceLimits,
    WorkspaceTransactionId,
};
