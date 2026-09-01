use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt::Write as _,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, Sender},
    },
};

use crate::{
    AttributedSandboxEvent, CommandId, ExecutionAttribution, PolicyGeneration, ProcessExit,
    SandboxError, SandboxEvent, SandboxRequest, ViolationAggregate, WorkspaceChange,
    WorkspaceControlError, WorkspaceTransactionId, runtime,
};

use crate::runtime::workspace::{
    CommittedWorkspace, StagedWorkspaceTransaction, WorkspaceError,
    WorkspaceLimits as RuntimeWorkspaceLimits,
};

#[derive(Debug)]
enum WorkspaceTransactionRecord {
    Pending {
        transaction: StagedWorkspaceTransaction,
        recovery_root: PathBuf,
    },
    Committed(CommittedWorkspace),
}

type WorkspaceTransactions =
    Arc<Mutex<BTreeMap<WorkspaceTransactionId, WorkspaceTransactionRecord>>>;

pub const DEFAULT_STREAM_CAPACITY: usize = 1_048_576;
const MAX_STREAM_CAPACITY: usize = 64 * 1_048_576;
pub const DEFAULT_VIOLATION_AGGREGATE_CAPACITY: usize = 1_024;
pub const MAX_VIOLATION_AGGREGATE_CAPACITY: usize = 65_536;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WorkspaceMode {
    #[default]
    Direct,
    Staged,
    Projected,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecutionOptions {
    pub command_id: Option<CommandId>,
    pub workspace: WorkspaceMode,
    pub workspace_limits: crate::WorkspaceLimits,
}

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
    next_policy_generation: Arc<AtomicU64>,
    workspace_transactions: WorkspaceTransactions,
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
        Ok(Self {
            config,
            next_policy_generation: Arc::new(AtomicU64::new(1)),
            workspace_transactions: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Validates, prepares, and starts one sandboxed execution.
    ///
    /// # Errors
    ///
    /// Invalid requests fail before runtime component access. Native startup
    /// failures are returned as typed initialization stages; this function
    /// never falls back to an unsandboxed process.
    pub fn start(&self, request: SandboxRequest) -> Result<ExecutionHandle, SandboxError> {
        self.start_with_options(request, ExecutionOptions::default())
    }

    /// Starts an execution with explicit attribution and workspace selection.
    ///
    /// # Errors
    ///
    /// Projected mode currently returns a typed workspace initialization
    /// failure; it never falls back to direct execution.
    pub fn start_with_options(
        &self,
        request: SandboxRequest,
        options: ExecutionOptions,
    ) -> Result<ExecutionHandle, SandboxError> {
        request.validate()?;
        if options.workspace == WorkspaceMode::Projected {
            return Err(SandboxError::InitializationFailed {
                stage: InitializationStage::Workspace,
            });
        }
        let command_id = options
            .command_id
            .map_or_else(CommandId::generate, Ok)
            .map_err(|()| SandboxError::InitializationFailed {
                stage: InitializationStage::Identity,
            })?;
        if options.workspace == WorkspaceMode::Staged {
            return self.start_staged(request, command_id, options.workspace_limits);
        }
        self.start_validated(request, command_id)
    }

    /// Starts one execution associated with a caller-provided opaque command ID.
    ///
    /// # Errors
    ///
    /// Validation and initialization failures are returned without falling back
    /// to an unattributed or unsandboxed execution.
    pub fn start_with_command_id(
        &self,
        request: SandboxRequest,
        command_id: CommandId,
    ) -> Result<ExecutionHandle, SandboxError> {
        self.start_with_options(
            request,
            ExecutionOptions {
                command_id: Some(command_id),
                workspace: WorkspaceMode::Direct,
                ..ExecutionOptions::default()
            },
        )
    }

    fn start_validated(
        &self,
        request: SandboxRequest,
        command_id: CommandId,
    ) -> Result<ExecutionHandle, SandboxError> {
        let policy_generation = self.allocate_policy_generation()?;
        runtime::start_execution(request, &self.config, command_id, policy_generation)
    }

    fn allocate_policy_generation(&self) -> Result<PolicyGeneration, SandboxError> {
        let generation = self
            .next_policy_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| SandboxError::InitializationFailed {
                stage: InitializationStage::Identity,
            })?;
        PolicyGeneration::new(generation).ok_or(SandboxError::InitializationFailed {
            stage: InitializationStage::Identity,
        })
    }

    fn start_staged(
        &self,
        mut request: SandboxRequest,
        command_id: CommandId,
        limits: crate::WorkspaceLimits,
    ) -> Result<ExecutionHandle, SandboxError> {
        let transaction_id = WorkspaceTransactionId::generate().map_err(|()| {
            SandboxError::InitializationFailed {
                stage: InitializationStage::Identity,
            }
        })?;
        let source_root = request.cwd.clone();
        let parent = source_root
            .parent()
            .ok_or(SandboxError::InitializationFailed {
                stage: InitializationStage::Workspace,
            })?;
        let suffix =
            transaction_id
                .as_bytes()
                .iter()
                .fold(String::with_capacity(32), |mut suffix, byte| {
                    write!(&mut suffix, "{byte:02x}").expect("writing to a String cannot fail");
                    suffix
                });
        let staging_root = parent.join(format!(".bolt-stage-{suffix}"));
        let recovery_root = parent.join(format!(".bolt-recovery-{suffix}"));
        let transaction = StagedWorkspaceTransaction::prepare(
            &source_root,
            &staging_root,
            RuntimeWorkspaceLimits {
                maximum_items: limits.maximum_items,
                maximum_bytes: limits.maximum_bytes,
            },
        )
        .map_err(|_| SandboxError::InitializationFailed {
            stage: InitializationStage::Workspace,
        })?;
        request.cwd = transaction.execution_root().to_path_buf();
        let mut config = self.config.clone();
        config.mandatory_filesystem_denies.push(source_root);
        let policy_generation = self.allocate_policy_generation()?;
        let mut handle = runtime::start_execution(request, &config, command_id, policy_generation)?;
        handle.attach_workspace(
            transaction_id,
            WorkspaceTransactionRecord::Pending {
                transaction,
                recovery_root,
            },
            Arc::clone(&self.workspace_transactions),
        );
        Ok(handle)
    }

    /// Returns the canonical changes for a completed staged transaction.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceControlError::NotFound`] until a matching completed
    /// transaction is owned by this sandbox coordinator.
    pub fn query_workspace_changes(
        &self,
        transaction_id: WorkspaceTransactionId,
    ) -> Result<Vec<WorkspaceChange>, WorkspaceControlError> {
        let transactions = self
            .workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?;
        let record = transactions
            .get(&transaction_id)
            .ok_or(WorkspaceControlError::NotFound)?;
        match record {
            WorkspaceTransactionRecord::Pending { transaction, .. } => transaction
                .query_changes()
                .map(convert_changes)
                .map_err(map_workspace_error),
            WorkspaceTransactionRecord::Committed(committed) => {
                Ok(convert_changes(committed.changes().to_vec()))
            }
        }
    }

    /// Commits a completed staged transaction through trusted Rust.
    ///
    /// # Errors
    ///
    /// Returns a typed workspace error when the transaction is missing,
    /// conflicted, unsupported, or cannot be committed atomically.
    pub fn commit_workspace(
        &self,
        transaction_id: WorkspaceTransactionId,
    ) -> Result<Vec<WorkspaceChange>, WorkspaceControlError> {
        let record = self
            .workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?
            .remove(&transaction_id)
            .ok_or(WorkspaceControlError::NotFound)?;
        let WorkspaceTransactionRecord::Pending {
            transaction,
            recovery_root,
        } = record
        else {
            return Err(WorkspaceControlError::Conflict);
        };
        let committed = transaction
            .commit(&recovery_root)
            .map_err(map_workspace_error)?;
        let changes = convert_changes(committed.changes().to_vec());
        self.workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?
            .insert(
                transaction_id,
                WorkspaceTransactionRecord::Committed(committed),
            );
        Ok(changes)
    }

    /// Discards a completed staged transaction without mutating its source.
    ///
    /// # Errors
    ///
    /// Returns a typed workspace error when the transaction is missing or its
    /// staging root cannot be removed safely.
    pub fn discard_workspace(
        &self,
        transaction_id: WorkspaceTransactionId,
    ) -> Result<(), WorkspaceControlError> {
        let record = self
            .workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?
            .remove(&transaction_id)
            .ok_or(WorkspaceControlError::NotFound)?;
        match record {
            WorkspaceTransactionRecord::Pending { transaction, .. } => {
                transaction.discard().map_err(map_workspace_error)
            }
            WorkspaceTransactionRecord::Committed(_) => Ok(()),
        }
    }
}

fn convert_changes(
    changes: Vec<crate::runtime::workspace::WorkspaceChange>,
) -> Vec<WorkspaceChange> {
    changes
        .into_iter()
        .map(|change| WorkspaceChange {
            relative_path: change.relative_path,
            kind: match change.kind {
                crate::runtime::workspace::WorkspaceChangeKind::Created => {
                    crate::WorkspaceChangeKind::Created
                }
                crate::runtime::workspace::WorkspaceChangeKind::Modified => {
                    crate::WorkspaceChangeKind::Modified
                }
                crate::runtime::workspace::WorkspaceChangeKind::Deleted => {
                    crate::WorkspaceChangeKind::Deleted
                }
            },
        })
        .collect()
}

const fn map_workspace_error(error: WorkspaceError) -> WorkspaceControlError {
    match error {
        WorkspaceError::InvalidRoot | WorkspaceError::UnsupportedObject => {
            WorkspaceControlError::UnsupportedObject
        }
        WorkspaceError::QuotaExceeded => WorkspaceControlError::QuotaExceeded,
        WorkspaceError::Conflict | WorkspaceError::RollbackFailed => {
            WorkspaceControlError::Conflict
        }
        WorkspaceError::Io => WorkspaceControlError::Io,
    }
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
    Workspace,
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
    pub attribution: ExecutionAttribution,
    pub workspace_transaction: Option<WorkspaceTransactionId>,
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
    attribution: ExecutionAttribution,
}

impl Iterator for EventStream {
    type Item = AttributedSandboxEvent;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver
            .recv()
            .ok()
            .map(|event| AttributedSandboxEvent {
                attribution: self.attribution,
                event,
            })
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
    attribution: ExecutionAttribution,
    stdout: Option<ByteStream>,
    stderr: Option<ByteStream>,
    events: Option<EventStream>,
    cancel: Sender<()>,
    completion: Receiver<Result<ExecutionResult, SandboxError>>,
    pending_workspace: Option<PendingWorkspace>,
}

struct PendingWorkspace {
    transaction_id: WorkspaceTransactionId,
    record: WorkspaceTransactionRecord,
    transactions: WorkspaceTransactions,
}

impl ExecutionHandle {
    pub(crate) fn new(
        process_id: u32,
        attribution: ExecutionAttribution,
        stdout: Receiver<Vec<u8>>,
        stderr: Receiver<Vec<u8>>,
        events: Receiver<SandboxEvent>,
        cancel: Sender<()>,
        completion: Receiver<Result<ExecutionResult, SandboxError>>,
    ) -> Self {
        Self {
            process_id,
            attribution,
            stdout: Some(ByteStream { receiver: stdout }),
            stderr: Some(ByteStream { receiver: stderr }),
            events: Some(EventStream {
                receiver: events,
                attribution,
            }),
            cancel,
            completion,
            pending_workspace: None,
        }
    }

    fn attach_workspace(
        &mut self,
        transaction_id: WorkspaceTransactionId,
        record: WorkspaceTransactionRecord,
        transactions: WorkspaceTransactions,
    ) {
        self.pending_workspace = Some(PendingWorkspace {
            transaction_id,
            record,
            transactions,
        });
    }

    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    #[must_use]
    pub const fn command_id(&self) -> CommandId {
        self.attribution.command_id
    }

    #[must_use]
    pub const fn attribution(&self) -> ExecutionAttribution {
        self.attribution
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
    pub fn wait(mut self) -> Result<ExecutionResult, SandboxError> {
        let mut result = self
            .completion
            .recv()
            .map_err(|_| SandboxError::ControlChannelClosed)??;
        if let Some(pending) = self.pending_workspace.take() {
            pending
                .transactions
                .lock()
                .map_err(|_| SandboxError::InitializationFailed {
                    stage: InitializationStage::Workspace,
                })?
                .insert(pending.transaction_id, pending.record);
            result.workspace_transaction = Some(pending.transaction_id);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox_with_generation(next: u64) -> Sandbox {
        Sandbox {
            config: SandboxConfig {
                component_root: PathBuf::from(r"C:\components"),
                credential_environment_variables: Vec::new(),
                stream_capacity: DEFAULT_STREAM_CAPACITY,
                violation_aggregate_capacity: DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
                mandatory_filesystem_denies: Vec::new(),
                mandatory_registry_denies: Vec::new(),
                component_manifest_sha256: None,
            },
            next_policy_generation: Arc::new(AtomicU64::new(next)),
            workspace_transactions: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[test]
    fn attr_003_policy_generations_are_nonzero_monotonic_and_do_not_wrap() {
        let sandbox = sandbox_with_generation(1);
        assert_eq!(
            sandbox.allocate_policy_generation().expect("first").get(),
            1
        );
        assert_eq!(
            sandbox.allocate_policy_generation().expect("second").get(),
            2
        );

        let exhausted = sandbox_with_generation(u64::MAX);
        assert!(matches!(
            exhausted.allocate_policy_generation(),
            Err(SandboxError::InitializationFailed {
                stage: InitializationStage::Identity
            })
        ));
    }
}
