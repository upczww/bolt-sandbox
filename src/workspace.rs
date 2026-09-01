use std::path::PathBuf;

const WORKSPACE_TRANSACTION_ID_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
