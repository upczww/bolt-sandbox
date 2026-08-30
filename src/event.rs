use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SandboxEvent {
    Ready,
    FilesystemViolation(FilesystemViolation),
    RegistryViolation(RegistryViolation),
    NetworkViolation(NetworkViolation),
    RecoveryArtifactCreated(RecoveryArtifact),
    ChildInjectionFailed(ChildInjectionFailure),
    ProcessViolation(ProcessViolation),
    ProcessExited(ProcessExit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemViolation {
    pub process_id: u32,
    pub operation: FilesystemOperation,
    pub path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FilesystemOperation {
    Read,
    Write,
    Metadata,
    Create,
    Delete,
    Rename,
    Enumerate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryViolation {
    pub process_id: u32,
    pub operation: RegistryOperation,
    pub key: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RegistryOperation {
    Open,
    Query,
    Enumerate,
    Create,
    SetValue,
    Delete,
    Rename,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkViolation {
    pub process_id: u32,
    pub operation: NetworkOperation,
    pub target: NetworkTarget,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum NetworkOperation {
    Resolve,
    Connect,
    Send,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum NetworkTarget {
    Domain(String),
    Socket(SocketAddr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryArtifact {
    pub process_id: u32,
    pub artifact_id: u64,
    pub original_path: PathBuf,
    pub byte_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildInjectionFailure {
    pub parent_process_id: u32,
    pub child_process_id: u32,
    pub reason: ChildInjectionFailureReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChildInjectionFailureReason {
    UnsupportedArchitecture,
    PolicyUnavailable,
    InjectionFailed,
    HandshakeFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessViolation {
    pub process_id: u32,
    pub operation: ProcessOperation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProcessOperation {
    CreateWithToken,
    CreateWithLogon,
    Elevation,
    Breakaway,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessExit {
    pub process_id: u32,
    pub exit_code: Option<u32>,
    pub reason: ProcessExitReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessExitReason {
    Exited,
    Terminated,
    TimedOut,
    Crashed,
}
