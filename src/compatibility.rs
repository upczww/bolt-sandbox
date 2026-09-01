use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{
    FilesystemOperation, NetworkOperation, NetworkTarget, RegistryOperation, SandboxEvent,
    ViolationAggregate,
};

const MAXIMUM_PROPOSAL_GRANTS: usize = 64;
const MAXIMUM_DECISION_CACHE_ENTRIES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityApprovalScope {
    Once,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityPromptAction {
    Prompt,
    UseApproved,
    SuppressRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityDecisionCacheError {
    InvalidCapacity,
    InvalidProposal,
    CapacityExceeded,
}

#[derive(Clone, Debug)]
struct CompatibilityDecisionEntry {
    proposal_id: String,
    executable_path: PathBuf,
    executable_sha256: [u8; 32],
    workspace: PathBuf,
    decision: CompatibilityDecision,
    scope: CompatibilityApprovalScope,
}

#[derive(Clone, Debug)]
pub struct CompatibilityDecisionCache {
    maximum_entries: usize,
    entries: BTreeMap<String, CompatibilityDecisionEntry>,
}

impl CompatibilityDecisionCache {
    /// Creates an in-memory trusted-host decision cache.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessively large capacities.
    pub fn new(maximum_entries: usize) -> Result<Self, CompatibilityDecisionCacheError> {
        if !(1..=MAXIMUM_DECISION_CACHE_ENTRIES).contains(&maximum_entries) {
            return Err(CompatibilityDecisionCacheError::InvalidCapacity);
        }
        Ok(Self {
            maximum_entries,
            entries: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn action(&self, proposal: &CompatibilityGrantProposal) -> CompatibilityPromptAction {
        let Some(entry) = self.entries.get(&proposal.proposal_id) else {
            return CompatibilityPromptAction::Prompt;
        };
        if !entry_matches(entry, proposal) {
            return CompatibilityPromptAction::Prompt;
        }
        match entry.decision {
            CompatibilityDecision::Approved => CompatibilityPromptAction::UseApproved,
            CompatibilityDecision::Rejected => CompatibilityPromptAction::SuppressRejected,
        }
    }

    /// Records one trusted decision without storing command arguments,
    /// environment values, or violation payloads.
    ///
    /// # Errors
    ///
    /// Rejects malformed proposal bindings and new entries beyond capacity.
    pub fn record(
        &mut self,
        proposal: &CompatibilityGrantProposal,
        decision: CompatibilityDecision,
        scope: CompatibilityApprovalScope,
    ) -> Result<(), CompatibilityDecisionCacheError> {
        if !valid_proposal_binding(proposal) {
            return Err(CompatibilityDecisionCacheError::InvalidProposal);
        }
        if !self.entries.contains_key(&proposal.proposal_id)
            && self.entries.len() == self.maximum_entries
        {
            return Err(CompatibilityDecisionCacheError::CapacityExceeded);
        }
        self.entries.insert(
            proposal.proposal_id.clone(),
            CompatibilityDecisionEntry {
                proposal_id: proposal.proposal_id.clone(),
                executable_path: proposal.executable_path.clone(),
                executable_sha256: proposal.executable_sha256,
                workspace: proposal.workspace.clone(),
                decision,
                scope,
            },
        );
        Ok(())
    }

    pub fn consume_approval(&mut self, proposal: &CompatibilityGrantProposal) -> bool {
        let Some(entry) = self.entries.get(&proposal.proposal_id) else {
            return false;
        };
        if !entry_matches(entry, proposal) || entry.decision != CompatibilityDecision::Approved {
            return false;
        }
        if entry.scope == CompatibilityApprovalScope::Once {
            self.entries.remove(&proposal.proposal_id);
        }
        true
    }
}

fn valid_proposal_binding(proposal: &CompatibilityGrantProposal) -> bool {
    proposal.proposal_id.len() == 64
        && proposal
            .proposal_id
            .bytes()
            .all(|value| value.is_ascii_hexdigit())
        && proposal.executable_path.is_absolute()
        && proposal.executable_sha256 != [0; 32]
        && proposal.workspace.is_absolute()
        && !proposal.grants.is_empty()
}

fn entry_matches(
    entry: &CompatibilityDecisionEntry,
    proposal: &CompatibilityGrantProposal,
) -> bool {
    entry.proposal_id == proposal.proposal_id
        && filesystem_key(&entry.executable_path) == filesystem_key(&proposal.executable_path)
        && entry.executable_sha256 == proposal.executable_sha256
        && filesystem_key(&entry.workspace) == filesystem_key(&proposal.workspace)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityCommandOutcome {
    Succeeded,
    Failed,
    InfrastructureFailure,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum CompatibilityCapability {
    MandatorySensitiveResource,
    HostWrite,
    RegistryWrite,
    RegistryEnumeration,
    DirectoryEnumeration,
    KernelObject,
    ProcessAuthority,
    NetworkBindingRequired,
    BroadFilesystemRoot,
    PolicyMismatch,
    IncompleteEvidence,
    TooManyDistinctResources,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum CompatibilityGrant {
    FilesystemMetadata(PathBuf),
    FilesystemReadOnly(PathBuf),
    RegistryExactReadOnly(String),
    NetworkEndpoint(SocketAddr),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityNoPromptReason {
    CommandSucceeded,
    InfrastructureFailure,
    NoEligibleViolations,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityGrantProposal {
    pub proposal_id: String,
    pub executable_path: PathBuf,
    pub executable_sha256: [u8; 32],
    pub workspace: PathBuf,
    pub grants: Vec<CompatibilityGrant>,
    pub duplicate_violations: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityUnavailable {
    pub grants: Vec<CompatibilityGrant>,
    pub capabilities: Vec<CompatibilityCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompatibilityResolution {
    NoPrompt(CompatibilityNoPromptReason),
    NeedsAuthorization(CompatibilityGrantProposal),
    CapabilityUnavailable(CompatibilityUnavailable),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityGrantContext {
    pub executable_path: PathBuf,
    pub executable_sha256: [u8; 32],
    pub workspace: PathBuf,
    pub mandatory_filesystem_denies: Vec<PathBuf>,
    pub mandatory_registry_denies: Vec<String>,
    pub maximum_grants: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityContextError {
    InvalidExecutable,
    InvalidWorkspace,
    InvalidMandatoryDeny,
    InvalidMaximumGrants,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityApplyError {
    InvalidProposal,
    UnsupportedGrant,
    PolicyRejected,
}

#[derive(Clone, Debug)]
pub struct CompatibilityGrantResolver {
    context: CompatibilityGrantContext,
}

impl CompatibilityGrantResolver {
    /// Creates a trusted-host compatibility proposal resolver.
    ///
    /// The resolver is advisory: it cannot update a running sandbox policy or
    /// approve a proposal.
    ///
    /// # Errors
    ///
    /// Returns a bounded context error when identities, mandatory denies, or
    /// proposal limits are invalid.
    pub fn new(context: CompatibilityGrantContext) -> Result<Self, CompatibilityContextError> {
        if !context.executable_path.is_absolute() || context.executable_sha256 == [0; 32] {
            return Err(CompatibilityContextError::InvalidExecutable);
        }
        if !context.workspace.is_absolute() || is_filesystem_root(&context.workspace) {
            return Err(CompatibilityContextError::InvalidWorkspace);
        }
        if context
            .mandatory_filesystem_denies
            .iter()
            .any(|path| !path.is_absolute())
            || context
                .mandatory_registry_denies
                .iter()
                .any(|key| registry_key(key).is_none())
        {
            return Err(CompatibilityContextError::InvalidMandatoryDeny);
        }
        if !(1..=MAXIMUM_PROPOSAL_GRANTS).contains(&context.maximum_grants) {
            return Err(CompatibilityContextError::InvalidMaximumGrants);
        }
        Ok(Self { context })
    }

    #[must_use]
    pub fn resolve(
        &self,
        outcome: CompatibilityCommandOutcome,
        violations: &[ViolationAggregate],
        dropped_distinct_violations: u64,
    ) -> CompatibilityResolution {
        match outcome {
            CompatibilityCommandOutcome::Succeeded => {
                return CompatibilityResolution::NoPrompt(
                    CompatibilityNoPromptReason::CommandSucceeded,
                );
            }
            CompatibilityCommandOutcome::InfrastructureFailure => {
                return CompatibilityResolution::NoPrompt(
                    CompatibilityNoPromptReason::InfrastructureFailure,
                );
            }
            CompatibilityCommandOutcome::Failed => {}
        }
        if dropped_distinct_violations != 0 {
            return unavailable([], [CompatibilityCapability::IncompleteEvidence]);
        }

        let mut grants = BTreeMap::<String, CompatibilityGrant>::new();
        let mut capabilities = Vec::new();
        let mut duplicate_violations = 0_u64;
        for aggregate in violations {
            duplicate_violations = duplicate_violations.saturating_add(aggregate.duplicate_count);
            self.classify(&aggregate.event, &mut grants, &mut capabilities);
        }
        capabilities.sort_unstable();
        capabilities.dedup();
        let grants = grants.into_values().collect::<Vec<_>>();
        if grants.len() > self.context.maximum_grants {
            return unavailable([], [CompatibilityCapability::TooManyDistinctResources]);
        }
        if !capabilities.is_empty() {
            return CompatibilityResolution::CapabilityUnavailable(CompatibilityUnavailable {
                grants,
                capabilities,
            });
        }
        if grants.is_empty() {
            return CompatibilityResolution::NoPrompt(
                CompatibilityNoPromptReason::NoEligibleViolations,
            );
        }
        let proposal_id = proposal_id(&self.context, &grants);
        CompatibilityResolution::NeedsAuthorization(CompatibilityGrantProposal {
            proposal_id,
            executable_path: self.context.executable_path.clone(),
            executable_sha256: self.context.executable_sha256,
            workspace: self.context.workspace.clone(),
            grants,
            duplicate_violations,
        })
    }

    /// Applies one already-approved proposal to a cloned policy after
    /// revalidating every binding and authority boundary.
    ///
    /// # Errors
    ///
    /// Rejects forged/stale proposals, unsupported grant kinds, mandatory
    /// sensitive overlap, and policies that exceed normal compiler bounds.
    pub fn apply_approved(
        &self,
        proposal: &CompatibilityGrantProposal,
        policy: &crate::SandboxPolicy,
    ) -> Result<crate::SandboxPolicy, CompatibilityApplyError> {
        if !valid_proposal_binding(proposal)
            || filesystem_key(&proposal.executable_path)
                != filesystem_key(&self.context.executable_path)
            || proposal.executable_sha256 != self.context.executable_sha256
            || filesystem_key(&proposal.workspace) != filesystem_key(&self.context.workspace)
            || proposal.grants.len() > self.context.maximum_grants
            || proposal_id(&self.context, &proposal.grants) != proposal.proposal_id
        {
            return Err(CompatibilityApplyError::InvalidProposal);
        }

        let mut applied = policy.clone();
        for grant in &proposal.grants {
            match grant {
                CompatibilityGrant::FilesystemMetadata(path) => {
                    self.validate_filesystem_grant(path)?;
                    push_unique_path(&mut applied.filesystem.metadata_read, path);
                }
                CompatibilityGrant::FilesystemReadOnly(path) => {
                    self.validate_filesystem_grant(path)?;
                    push_unique_path(&mut applied.filesystem.read_only, path);
                }
                CompatibilityGrant::RegistryExactReadOnly(key) => {
                    self.validate_registry_grant(key)?;
                    push_unique_registry(&mut applied.registry.exact_read_only, key);
                }
                CompatibilityGrant::NetworkEndpoint(_) => {
                    return Err(CompatibilityApplyError::UnsupportedGrant);
                }
            }
        }
        crate::policy::compiler::compile(&applied, &self.context.workspace)
            .map_err(|_| CompatibilityApplyError::PolicyRejected)?;
        Ok(applied)
    }

    fn validate_filesystem_grant(&self, path: &Path) -> Result<(), CompatibilityApplyError> {
        let Some(key) = filesystem_key(path) else {
            return Err(CompatibilityApplyError::InvalidProposal);
        };
        if is_filesystem_root(path)
            || self
                .context
                .mandatory_filesystem_denies
                .iter()
                .filter_map(|deny| filesystem_key(deny))
                .any(|deny| same_or_ancestor(&deny, &key))
        {
            return Err(CompatibilityApplyError::InvalidProposal);
        }
        Ok(())
    }

    fn validate_registry_grant(&self, key: &str) -> Result<(), CompatibilityApplyError> {
        let Some(normalized) = registry_key(key) else {
            return Err(CompatibilityApplyError::InvalidProposal);
        };
        if self
            .context
            .mandatory_registry_denies
            .iter()
            .filter_map(|deny| registry_key(deny))
            .any(|deny| same_or_ancestor(&deny, &normalized))
        {
            return Err(CompatibilityApplyError::InvalidProposal);
        }
        Ok(())
    }

    fn classify(
        &self,
        event: &SandboxEvent,
        grants: &mut BTreeMap<String, CompatibilityGrant>,
        capabilities: &mut Vec<CompatibilityCapability>,
    ) {
        match event {
            SandboxEvent::FilesystemViolation(violation) => {
                self.classify_filesystem(
                    violation.operation,
                    &violation.path,
                    grants,
                    capabilities,
                );
            }
            SandboxEvent::RegistryViolation(violation) => {
                self.classify_registry(violation.operation, &violation.key, grants, capabilities);
            }
            SandboxEvent::NetworkViolation(violation) => {
                match (violation.operation, &violation.target) {
                    (
                        NetworkOperation::Connect | NetworkOperation::Send,
                        NetworkTarget::Socket(socket),
                    ) => {
                        let grant = CompatibilityGrant::NetworkEndpoint(*socket);
                        grants.entry(format!("network:{socket}")).or_insert(grant);
                    }
                    _ => capabilities.push(CompatibilityCapability::NetworkBindingRequired),
                }
            }
            SandboxEvent::ProcessViolation(_) => {
                capabilities.push(CompatibilityCapability::ProcessAuthority);
            }
            SandboxEvent::EventsDropped(_) => {
                capabilities.push(CompatibilityCapability::IncompleteEvidence);
            }
            SandboxEvent::Ready
            | SandboxEvent::RecoveryArtifactCreated(_)
            | SandboxEvent::RecoveryFailed(_)
            | SandboxEvent::ChildInjectionFailed(_)
            | SandboxEvent::ProcessExited(_) => {}
        }
    }

    fn classify_filesystem(
        &self,
        operation: FilesystemOperation,
        path: &Path,
        grants: &mut BTreeMap<String, CompatibilityGrant>,
        capabilities: &mut Vec<CompatibilityCapability>,
    ) {
        let Some(key) = filesystem_key(path) else {
            capabilities.push(CompatibilityCapability::KernelObject);
            return;
        };
        if self
            .context
            .mandatory_filesystem_denies
            .iter()
            .filter_map(|path| filesystem_key(path))
            .any(|deny| same_or_ancestor(&deny, &key))
        {
            capabilities.push(CompatibilityCapability::MandatorySensitiveResource);
            return;
        }
        let workspace = filesystem_key(&self.context.workspace).expect("validated workspace");
        if same_or_ancestor(&workspace, &key) {
            capabilities.push(CompatibilityCapability::PolicyMismatch);
            return;
        }
        if is_filesystem_root(path) {
            capabilities.push(CompatibilityCapability::BroadFilesystemRoot);
            return;
        }
        match operation {
            FilesystemOperation::Read => {
                grants
                    .entry(format!("fs-read:{key}"))
                    .or_insert_with(|| CompatibilityGrant::FilesystemReadOnly(path.to_path_buf()));
            }
            FilesystemOperation::Metadata => {
                grants
                    .entry(format!("fs-meta:{key}"))
                    .or_insert_with(|| CompatibilityGrant::FilesystemMetadata(path.to_path_buf()));
            }
            FilesystemOperation::Enumerate => {
                capabilities.push(CompatibilityCapability::DirectoryEnumeration);
            }
            FilesystemOperation::Write
            | FilesystemOperation::Create
            | FilesystemOperation::Delete
            | FilesystemOperation::Rename => {
                capabilities.push(CompatibilityCapability::HostWrite);
            }
        }
    }

    fn classify_registry(
        &self,
        operation: RegistryOperation,
        key: &str,
        grants: &mut BTreeMap<String, CompatibilityGrant>,
        capabilities: &mut Vec<CompatibilityCapability>,
    ) {
        let Some(normalized) = registry_key(key) else {
            capabilities.push(CompatibilityCapability::KernelObject);
            return;
        };
        if self
            .context
            .mandatory_registry_denies
            .iter()
            .filter_map(|deny| registry_key(deny))
            .any(|deny| same_or_ancestor(&deny, &normalized))
        {
            capabilities.push(CompatibilityCapability::MandatorySensitiveResource);
            return;
        }
        match operation {
            RegistryOperation::Open | RegistryOperation::Query => {
                grants
                    .entry(format!("reg-read:{normalized}"))
                    .or_insert_with(|| CompatibilityGrant::RegistryExactReadOnly(key.to_owned()));
            }
            RegistryOperation::Enumerate => {
                capabilities.push(CompatibilityCapability::RegistryEnumeration);
            }
            RegistryOperation::Create
            | RegistryOperation::SetValue
            | RegistryOperation::Delete
            | RegistryOperation::Rename
            | RegistryOperation::UnsupportedRemote
            | RegistryOperation::UnsupportedTransactional => {
                capabilities.push(CompatibilityCapability::RegistryWrite);
            }
        }
    }
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: &Path) {
    let key = filesystem_key(path).expect("validated compatibility path");
    if !paths
        .iter()
        .filter_map(|existing| filesystem_key(existing))
        .any(|existing| existing == key)
    {
        paths.push(path.to_path_buf());
    }
}

fn push_unique_registry(keys: &mut Vec<String>, key: &str) {
    let normalized = registry_key(key).expect("validated compatibility registry key");
    if !keys
        .iter()
        .filter_map(|existing| registry_key(existing))
        .any(|existing| existing == normalized)
    {
        keys.push(key.to_owned());
    }
}

fn unavailable<const G: usize, const C: usize>(
    grants: [CompatibilityGrant; G],
    capabilities: [CompatibilityCapability; C],
) -> CompatibilityResolution {
    CompatibilityResolution::CapabilityUnavailable(CompatibilityUnavailable {
        grants: grants.into(),
        capabilities: capabilities.into(),
    })
}

fn filesystem_key(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let encoded = path.to_string_lossy().replace('/', "\\");
    if encoded.starts_with(r"\\.\")
        || encoded.starts_with(r"\\?\GLOBALROOT")
        || encoded.starts_with(r"\Device\")
        || encoded.starts_with(r"\??\")
    {
        return None;
    }
    Some(encoded.trim_end_matches('\\').to_lowercase())
}

fn registry_key(key: &str) -> Option<String> {
    if key.is_empty() || key.contains(['/', '\0', ':', '*', '?']) {
        return None;
    }
    let normalized = key.trim_matches('\\').to_lowercase();
    let valid_root = ["hkcu", "hkey_current_user", "hklm", "hkey_local_machine"]
        .iter()
        .any(|root| normalized == *root || normalized.starts_with(&format!("{root}\\")));
    valid_root.then_some(normalized)
}

fn same_or_ancestor(ancestor: &str, path: &str) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn is_filesystem_root(path: &Path) -> bool {
    path.parent()
        .is_none_or(|parent| parent == path || parent.as_os_str().is_empty())
}

fn proposal_id(context: &CompatibilityGrantContext, grants: &[CompatibilityGrant]) -> String {
    let mut digest = Sha256::new();
    digest.update(context.executable_sha256);
    digest.update(context.executable_path.to_string_lossy().to_lowercase());
    digest.update(context.workspace.to_string_lossy().to_lowercase());
    for grant in grants {
        digest.update(format!("{grant:?}"));
    }
    digest
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write as _;
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        })
}
