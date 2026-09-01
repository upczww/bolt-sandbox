use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, Sender},
};

use crate::{ProcessExit, SandboxError, SandboxEvent, SandboxRequest, ViolationAggregate, runtime};

pub const DEFAULT_STREAM_CAPACITY: usize = 1_048_576;
const MAX_STREAM_CAPACITY: usize = 64 * 1_048_576;
pub const DEFAULT_VIOLATION_AGGREGATE_CAPACITY: usize = 1_024;
pub const MAX_VIOLATION_AGGREGATE_CAPACITY: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxConfig {
    pub component_root: PathBuf,
    pub credential_environment_variables: Vec<OsString>,
    pub stream_capacity: usize,
    pub violation_aggregate_capacity: usize,
    pub mandatory_filesystem_denies: Vec<PathBuf>,
    pub mandatory_registry_denies: Vec<String>,
    pub component_manifest_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    /// Creates a reusable sandbox runtime configuration.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error before opening any runtime
    /// component when the component root or stream capacity is invalid.
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let mut config = config;
        if !config.component_root.is_absolute() || !config.component_root.is_dir() {
            return Err(SandboxError::InvalidConfiguration {
                field: ConfigurationField::ComponentRoot,
                reason: ConfigurationErrorReason::InvalidDirectory,
            });
        }
        if !(1..=MAX_STREAM_CAPACITY).contains(&config.stream_capacity) {
            return Err(SandboxError::InvalidConfiguration {
                field: ConfigurationField::StreamCapacity,
                reason: ConfigurationErrorReason::OutOfRange,
            });
        }
        if !(1..=MAX_VIOLATION_AGGREGATE_CAPACITY).contains(&config.violation_aggregate_capacity) {
            return Err(SandboxError::InvalidConfiguration {
                field: ConfigurationField::ViolationAggregateCapacity,
                reason: ConfigurationErrorReason::OutOfRange,
            });
        }
        config
            .mandatory_filesystem_denies
            .extend(default_sensitive_filesystem_paths());
        config
            .mandatory_registry_denies
            .extend(default_sensitive_registry_keys().map(str::to_owned));
        Ok(Self { config })
    }

    /// Validates, prepares, and starts one sandboxed execution.
    ///
    /// # Errors
    ///
    /// Invalid requests fail before runtime component access. Native startup
    /// failures are returned as typed initialization stages; this function
    /// never falls back to an unsandboxed process.
    pub fn start(&self, request: SandboxRequest) -> Result<ExecutionHandle, SandboxError> {
        let mut request = request;
        request
            .policy
            .filesystem
            .read_only
            .extend(default_compatibility_filesystem_paths(
                &request.program,
                &request.cwd,
            ));
        request.validate()?;
        runtime::start_execution(request, &self.config)
    }
}

fn default_compatibility_filesystem_paths(
    program: &Path,
    cwd: &Path,
) -> impl Iterator<Item = PathBuf> {
    let windows = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .into_iter()
        .map(PathBuf::from);
    let node_openssl_config = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .into_iter()
        .map(PathBuf::from)
        .map(|root| root.join(r"Common Files\SSL\openssl.cnf"));
    let program_directory = program
        .parent()
        .filter(|parent| {
            parent.is_absolute() && parent.parent().is_some() && !parent.starts_with(cwd)
        })
        .map(Path::to_path_buf);
    windows
        .chain(node_openssl_config)
        .chain(program_directory)
        .filter(|path| path.is_absolute())
}

fn default_sensitive_filesystem_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        for relative in [
            ".ssh",
            ".gnupg",
            ".aws",
            ".azure",
            ".kube",
            ".docker",
            ".config\\gh",
        ] {
            paths.push(profile.join(relative));
        }
    }
    if let Some(roaming) = std::env::var_os("APPDATA").map(PathBuf::from) {
        paths.push(roaming.join("gnupg"));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        paths.push(local.join("Google\\Chrome\\User Data"));
        paths.push(local.join("Microsoft\\Edge\\User Data"));
    }
    paths.retain(|path| path.is_absolute());
    paths
}

fn default_sensitive_registry_keys() -> impl Iterator<Item = &'static str> {
    [
        r"HKCU\SOFTWARE\Microsoft\Credentials",
        r"HKCU\SOFTWARE\Microsoft\IdentityCRL",
        r"HKCU\SOFTWARE\Microsoft\OneDrive\Accounts",
    ]
    .into_iter()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationField {
    ComponentRoot,
    StreamCapacity,
    ViolationAggregateCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationErrorReason {
    InvalidDirectory,
    OutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationStage {
    Program,
    Components,
    Policy,
    Identity,
    LauncherAdapter,
    RecoveryCoordinator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfrastructureFailure {
    EventChannelLost,
    ProtocolIntegrity,
    LauncherExited,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiverLoss {
    pub stdout: bool,
    pub stderr: bool,
    pub events: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionTerminal {
    Process(ProcessExit),
    Infrastructure(InfrastructureFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    pub terminal: ExecutionTerminal,
    pub receiver_loss: ReceiverLoss,
    pub violation_aggregates: Vec<ViolationAggregate>,
    pub dropped_distinct_violations: u64,
}

pub struct ByteStream {
    receiver: Receiver<Vec<u8>>,
}

impl Iterator for ByteStream {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

pub struct EventStream {
    receiver: Receiver<SandboxEvent>,
}

impl Iterator for EventStream {
    type Item = SandboxEvent;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionControlError {
    AlreadyTaken,
    ControlChannelClosed,
    CompletionChannelClosed,
}

pub struct ExecutionHandle {
    process_id: u32,
    stdout: Option<ByteStream>,
    stderr: Option<ByteStream>,
    events: Option<EventStream>,
    cancel: Sender<()>,
    completion: Receiver<Result<ExecutionResult, SandboxError>>,
}

impl ExecutionHandle {
    pub(crate) fn new(
        process_id: u32,
        stdout: Receiver<Vec<u8>>,
        stderr: Receiver<Vec<u8>>,
        events: Receiver<SandboxEvent>,
        cancel: Sender<()>,
        completion: Receiver<Result<ExecutionResult, SandboxError>>,
    ) -> Self {
        Self {
            process_id,
            stdout: Some(ByteStream { receiver: stdout }),
            stderr: Some(ByteStream { receiver: stderr }),
            events: Some(EventStream { receiver: events }),
            cancel,
            completion,
        }
    }

    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Takes the stdout byte stream exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionControlError::AlreadyTaken`] after the stream has
    /// already been taken.
    pub fn take_stdout(&mut self) -> Result<ByteStream, ExecutionControlError> {
        self.stdout
            .take()
            .ok_or(ExecutionControlError::AlreadyTaken)
    }

    /// Takes the stderr byte stream exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionControlError::AlreadyTaken`] after the stream has
    /// already been taken.
    pub fn take_stderr(&mut self) -> Result<ByteStream, ExecutionControlError> {
        self.stderr
            .take()
            .ok_or(ExecutionControlError::AlreadyTaken)
    }

    /// Takes the typed event stream exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionControlError::AlreadyTaken`] after the stream has
    /// already been taken.
    pub fn take_events(&mut self) -> Result<EventStream, ExecutionControlError> {
        self.events
            .take()
            .ok_or(ExecutionControlError::AlreadyTaken)
    }

    /// Requests cancellation without blocking for terminal cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionControlError::ControlChannelClosed`] when execution
    /// has already completed and its control worker has exited.
    pub fn cancel(&self) -> Result<(), ExecutionControlError> {
        self.cancel
            .send(())
            .map_err(|_| ExecutionControlError::ControlChannelClosed)
    }

    /// Waits for the final drained execution result.
    ///
    /// # Errors
    ///
    /// Returns a typed runtime error when startup or lifecycle processing
    /// fails, including an unexpected completion-channel disconnect.
    pub fn wait(self) -> Result<ExecutionResult, SandboxError> {
        self.completion
            .recv()
            .map_err(|_| SandboxError::ControlChannelClosed)?
    }
}
