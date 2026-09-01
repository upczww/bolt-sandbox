use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt::Write as _,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError},
    },
    time::{Duration, Instant},
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

#[derive(Debug)]
struct StoredWorkspaceTransaction {
    record: WorkspaceTransactionRecord,
    completed_at: Instant,
    retention: Duration,
}

type WorkspaceTransactions =
    Arc<Mutex<BTreeMap<WorkspaceTransactionId, StoredWorkspaceTransaction>>>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PseudoConsoleSize {
    columns: u16,
    rows: u16,
}

impl PseudoConsoleSize {
    #[must_use]
    pub const fn new(columns: u16, rows: u16) -> Option<Self> {
        if columns == 0 || rows == 0 || columns > i16::MAX as u16 || rows > i16::MAX as u16 {
            None
        } else {
            Some(Self { columns, rows })
        }
    }

    #[must_use]
    pub const fn columns(self) -> u16 {
        self.columns
    }

    #[must_use]
    pub const fn rows(self) -> u16 {
        self.rows
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TerminalMode {
    #[default]
    Pipes,
    PseudoConsole(PseudoConsoleSize),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecutionOptions {
    pub command_id: Option<CommandId>,
    pub workspace: WorkspaceMode,
    pub workspace_limits: crate::WorkspaceLimits,
    pub terminal: TerminalMode,
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
            return self.start_staged(
                request,
                command_id,
                options.workspace_limits,
                options.terminal,
            );
        }
        self.start_validated(request, command_id, options.terminal)
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
        terminal: TerminalMode,
    ) -> Result<ExecutionHandle, SandboxError> {
        let policy_generation = self.allocate_policy_generation()?;
        runtime::start_execution(
            request,
            &self.config,
            command_id,
            policy_generation,
            terminal,
        )
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
        terminal: TerminalMode,
    ) -> Result<ExecutionHandle, SandboxError> {
        if limits.maximum_items == 0
            || limits.maximum_bytes == 0
            || limits.maximum_retained_transactions == 0
            || limits.retention.is_zero()
        {
            return Err(SandboxError::InitializationFailed {
                stage: InitializationStage::Workspace,
            });
        }
        let transaction_id = WorkspaceTransactionId::generate().map_err(|()| {
            SandboxError::InitializationFailed {
                stage: InitializationStage::Identity,
            }
        })?;
        let source_root = request.cwd.clone();
        if workspace_overlaps_mandatory_deny(&source_root, &self.config.mandatory_filesystem_denies)
        {
            return Err(SandboxError::InitializationFailed {
                stage: InitializationStage::Workspace,
            });
        }
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
        let mut handle =
            runtime::start_execution(request, &config, command_id, policy_generation, terminal)?;
        handle.attach_workspace(
            transaction_id,
            WorkspaceTransactionRecord::Pending {
                transaction,
                recovery_root,
            },
            Arc::clone(&self.workspace_transactions),
            limits.maximum_retained_transactions,
            limits.retention,
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
        let mut transactions = self
            .workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?;
        prune_expired_transactions(&mut transactions, Instant::now());
        let stored = transactions
            .get(&transaction_id)
            .ok_or(WorkspaceControlError::NotFound)?;
        match &stored.record {
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
        let mut transactions = self
            .workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?;
        prune_expired_transactions(&mut transactions, Instant::now());
        let stored = transactions
            .get_mut(&transaction_id)
            .ok_or(WorkspaceControlError::NotFound)?;
        let WorkspaceTransactionRecord::Pending {
            transaction,
            recovery_root,
        } = &mut stored.record
        else {
            return Err(WorkspaceControlError::Conflict);
        };
        let committed = transaction
            .commit(recovery_root)
            .map_err(map_workspace_error)?;
        let changes = convert_changes(committed.changes().to_vec());
        stored.record = WorkspaceTransactionRecord::Committed(committed);
        Ok(changes)
    }

    /// Atomically restores the source state retained by a successful commit.
    ///
    /// # Errors
    ///
    /// Returns a typed workspace error when the transaction is missing, has
    /// not been committed, was already reverted, or cannot be restored safely.
    pub fn revert_workspace(
        &self,
        transaction_id: WorkspaceTransactionId,
    ) -> Result<(), WorkspaceControlError> {
        let mut transactions = self
            .workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?;
        prune_expired_transactions(&mut transactions, Instant::now());
        let stored = transactions
            .get(&transaction_id)
            .ok_or(WorkspaceControlError::NotFound)?;
        let WorkspaceTransactionRecord::Committed(committed) = &stored.record else {
            return Err(WorkspaceControlError::Conflict);
        };
        committed.revert().map_err(map_workspace_error)?;
        transactions.remove(&transaction_id);
        Ok(())
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
        let mut transactions = self
            .workspace_transactions
            .lock()
            .map_err(|_| WorkspaceControlError::Io)?;
        prune_expired_transactions(&mut transactions, Instant::now());
        let stored = transactions
            .remove(&transaction_id)
            .ok_or(WorkspaceControlError::NotFound)?;
        match stored.record {
            WorkspaceTransactionRecord::Pending { transaction, .. } => {
                transaction.discard().map_err(map_workspace_error)
            }
            WorkspaceTransactionRecord::Committed(_) => Ok(()),
        }
    }
}

fn prune_expired_transactions(
    transactions: &mut BTreeMap<WorkspaceTransactionId, StoredWorkspaceTransaction>,
    now: Instant,
) {
    transactions.retain(|_, stored| {
        now.checked_duration_since(stored.completed_at)
            .is_some_and(|age| age < stored.retention)
    });
}

fn enforce_transaction_count_limit(
    transactions: &mut BTreeMap<WorkspaceTransactionId, StoredWorkspaceTransaction>,
    maximum: u32,
) {
    let maximum = usize::try_from(maximum).unwrap_or(usize::MAX);
    while transactions.len() >= maximum {
        let Some(oldest) = transactions
            .iter()
            .min_by_key(|(id, stored)| (stored.completed_at, **id))
            .map(|(id, _)| *id)
        else {
            break;
        };
        transactions.remove(&oldest);
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

fn workspace_overlaps_mandatory_deny(source: &std::path::Path, denies: &[PathBuf]) -> bool {
    let Some(source) = safe_windows_path_key(source) else {
        return true;
    };
    denies.iter().any(|deny| {
        let Some(deny) = safe_windows_path_key(deny) else {
            return true;
        };
        is_same_or_ancestor_key(&source, &deny) || is_same_or_ancestor_key(&deny, &source)
    })
}

fn safe_windows_path_key(path: &std::path::Path) -> Option<String> {
    let encoded = path.to_string_lossy();
    if !path.is_absolute()
        || encoded.starts_with(r"\\?\")
        || encoded.starts_with(r"\\.\")
        || encoded.starts_with(r"\Device\")
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return None;
    }
    Some(
        encoded
            .replace('/', r"\")
            .trim_end_matches('\\')
            .to_lowercase(),
    )
}

fn is_same_or_ancestor_key(ancestor: &str, path: &str) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('\\'))
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
    NotPseudoConsole,
    InputTooLarge,
    ControlQueueFull,
}

pub(crate) enum ExecutionControlRequest {
    Cancel,
    Input(Vec<u8>),
    Resize(PseudoConsoleSize),
}

pub struct ExecutionHandle {
    process_id: u32,
    attribution: ExecutionAttribution,
    stdout: Option<ByteStream>,
    stderr: Option<ByteStream>,
    events: Option<EventStream>,
    control: SyncSender<ExecutionControlRequest>,
    completion: Receiver<Result<ExecutionResult, SandboxError>>,
    pending_workspace: Option<PendingWorkspace>,
    terminal: TerminalMode,
}

struct PendingWorkspace {
    transaction_id: WorkspaceTransactionId,
    record: WorkspaceTransactionRecord,
    transactions: WorkspaceTransactions,
    maximum_retained_transactions: u32,
    retention: Duration,
}

impl ExecutionHandle {
    #[allow(
        clippy::too_many_arguments,
        reason = "the handle owns each independent stream and control capability"
    )]
    pub(crate) fn new(
        process_id: u32,
        attribution: ExecutionAttribution,
        stdout: Receiver<Vec<u8>>,
        stderr: Receiver<Vec<u8>>,
        events: Receiver<SandboxEvent>,
        control: SyncSender<ExecutionControlRequest>,
        completion: Receiver<Result<ExecutionResult, SandboxError>>,
        terminal: TerminalMode,
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
            control,
            completion,
            pending_workspace: None,
            terminal,
        }
    }

    fn attach_workspace(
        &mut self,
        transaction_id: WorkspaceTransactionId,
        record: WorkspaceTransactionRecord,
        transactions: WorkspaceTransactions,
        maximum_retained_transactions: u32,
        retention: Duration,
    ) {
        self.pending_workspace = Some(PendingWorkspace {
            transaction_id,
            record,
            transactions,
            maximum_retained_transactions,
            retention,
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
        self.send_control(ExecutionControlRequest::Cancel)
    }

    /// Writes bounded input to an explicitly requested pseudo console.
    ///
    /// # Errors
    ///
    /// Pipe-mode executions reject the operation, and input larger than one
    /// transport frame is rejected before reaching the launcher.
    pub fn write_input(&self, input: &[u8]) -> Result<(), ExecutionControlError> {
        if self.terminal == TerminalMode::Pipes {
            return Err(ExecutionControlError::NotPseudoConsole);
        }
        if input.len() > 64 * 1_024 {
            return Err(ExecutionControlError::InputTooLarge);
        }
        if input.is_empty() {
            return Ok(());
        }
        self.send_control(ExecutionControlRequest::Input(input.to_vec()))
    }

    /// Resizes an explicitly requested pseudo console.
    ///
    /// # Errors
    ///
    /// Pipe-mode executions reject the operation. A closed PTY control
    /// channel reports [`ExecutionControlError::ControlChannelClosed`].
    pub fn resize_pseudo_console(
        &self,
        size: PseudoConsoleSize,
    ) -> Result<(), ExecutionControlError> {
        if self.terminal == TerminalMode::Pipes {
            return Err(ExecutionControlError::NotPseudoConsole);
        }
        self.send_control(ExecutionControlRequest::Resize(size))
    }

    fn send_control(&self, request: ExecutionControlRequest) -> Result<(), ExecutionControlError> {
        self.control.try_send(request).map_err(|error| match error {
            TrySendError::Full(_) => ExecutionControlError::ControlQueueFull,
            TrySendError::Disconnected(_) => ExecutionControlError::ControlChannelClosed,
        })
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
            let mut transactions =
                pending
                    .transactions
                    .lock()
                    .map_err(|_| SandboxError::InitializationFailed {
                        stage: InitializationStage::Workspace,
                    })?;
            let now = Instant::now();
            prune_expired_transactions(&mut transactions, now);
            enforce_transaction_count_limit(
                &mut transactions,
                pending.maximum_retained_transactions,
            );
            transactions.insert(
                pending.transaction_id,
                StoredWorkspaceTransaction {
                    record: pending.record,
                    completed_at: now,
                    retention: pending.retention,
                },
            );
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

    #[test]
    fn ws_021_staged_workspace_rejects_mandatory_deny_overlap_case_insensitively() {
        let source = PathBuf::from(r"C:\Work\Agent");

        assert!(workspace_overlaps_mandatory_deny(
            &source,
            &[PathBuf::from(r"c:\work\agent\.secrets")]
        ));
        assert!(workspace_overlaps_mandatory_deny(
            &source,
            &[PathBuf::from(r"C:\WORK")]
        ));
        assert!(workspace_overlaps_mandatory_deny(
            &source,
            &[PathBuf::from(r"c:\work\agent")]
        ));
        assert!(!workspace_overlaps_mandatory_deny(
            &source,
            &[PathBuf::from(r"C:\Work\Agent-Other\.secrets")]
        ));
    }
}
