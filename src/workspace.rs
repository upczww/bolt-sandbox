use std::{path::PathBuf, time::Duration};

const WORKSPACE_TRANSACTION_ID_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceTransactionId([u8; WORKSPACE_TRANSACTION_ID_LENGTH]);

impl WorkspaceTransactionId {
    #[must_use]
    pub fn new(bytes: [u8; WORKSPACE_TRANSACTION_ID_LENGTH]) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WORKSPACE_TRANSACTION_ID_LENGTH] {
        &self.0
    }

    pub(crate) fn generate() -> Result<Self, ()> {
        let mut bytes = [0_u8; WORKSPACE_TRANSACTION_ID_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| ())?;
        Self::new(bytes).ok_or(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLimits {
    pub maximum_items: u32,
    pub maximum_bytes: u64,
    pub maximum_retained_transactions: u32,
    pub retention: Duration,
}

impl Default for WorkspaceLimits {
    fn default() -> Self {
        Self {
            maximum_items: 100_000,
            maximum_bytes: 4 * 1_024 * 1_024 * 1_024,
            maximum_retained_transactions: 256,
            retention: Duration::from_secs(24 * 60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceChange {
    pub relative_path: PathBuf,
    pub kind: WorkspaceChangeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceControlError {
    NotFound,
    Conflict,
    QuotaExceeded,
    UnsupportedObject,
    Io,
}
