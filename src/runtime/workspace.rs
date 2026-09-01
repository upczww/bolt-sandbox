use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceKind {
    Direct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceError {
    InvalidRoot,
}

#[derive(Debug)]
pub(super) struct PreparedWorkspace {
    kind: WorkspaceKind,
    source_root: PathBuf,
    execution_root: PathBuf,
}

impl PreparedWorkspace {
    pub(super) const fn kind(&self) -> WorkspaceKind {
        self.kind
    }

    pub(super) fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub(super) fn execution_root(&self) -> &Path {
        &self.execution_root
    }
}

pub(super) trait WorkspaceBackend {
    fn prepare(&self, source_root: &Path) -> Result<PreparedWorkspace, WorkspaceError>;
}

pub(super) struct DirectWorkspaceBackend;

impl WorkspaceBackend for DirectWorkspaceBackend {
    fn prepare(&self, source_root: &Path) -> Result<PreparedWorkspace, WorkspaceError> {
        if !source_root.is_absolute() || !source_root.is_dir() {
            return Err(WorkspaceError::InvalidRoot);
        }
        Ok(PreparedWorkspace {
            kind: WorkspaceKind::Direct,
            source_root: source_root.to_path_buf(),
            execution_root: source_root.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{DirectWorkspaceBackend, WorkspaceBackend, WorkspaceKind};

    #[test]
    fn ws_001_direct_backend_preserves_source_and_execution_root() {
        let root = std::env::current_dir().expect("test cwd must exist");
        let prepared = DirectWorkspaceBackend
            .prepare(&root)
            .expect("validated direct workspace must prepare");

        assert_eq!(prepared.kind(), WorkspaceKind::Direct);
        assert_eq!(prepared.source_root(), root);
        assert_eq!(prepared.execution_root(), root);
    }
}
