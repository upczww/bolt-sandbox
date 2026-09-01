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
    use std::fs;

    use super::{
        DirectWorkspaceBackend, WorkspaceBackend, WorkspaceChange, WorkspaceChangeKind,
        WorkspaceLimits, WorkspaceSnapshot, WorkspaceKind,
    };

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

    #[test]
    fn ws_014_snapshot_diff_is_canonical_complete_and_bounded() {
        let fixture = std::env::temp_dir().join(format!(
            "bolt-workspace-diff-{}",
            std::process::id()
        ));
        let source = fixture.join("source");
        let staged = fixture.join("staged");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir_all(&source).expect("source must create");
        fs::create_dir_all(&staged).expect("staged must create");
        for (name, contents) in [
            ("deleted.txt", b"deleted".as_slice()),
            ("modified.txt", b"before".as_slice()),
            ("stable.txt", b"stable".as_slice()),
        ] {
            fs::write(source.join(name), contents).expect("source seed must write");
            fs::write(staged.join(name), contents).expect("staged seed must write");
        }
        let snapshot = WorkspaceSnapshot::capture(
            &source,
            WorkspaceLimits {
                maximum_items: 16,
                maximum_bytes: 1_048_576,
            },
        )
        .expect("snapshot must capture");
        fs::remove_file(staged.join("deleted.txt")).expect("delete must apply");
        fs::write(staged.join("modified.txt"), b"after").expect("modify must apply");
        fs::write(staged.join("created.txt"), b"created").expect("create must apply");

        let changes = snapshot.diff(&staged).expect("diff must succeed");

        assert_eq!(
            changes,
            vec![
                WorkspaceChange {
                    relative_path: "created.txt".into(),
                    kind: WorkspaceChangeKind::Created,
                },
                WorkspaceChange {
                    relative_path: "deleted.txt".into(),
                    kind: WorkspaceChangeKind::Deleted,
                },
                WorkspaceChange {
                    relative_path: "modified.txt".into(),
                    kind: WorkspaceChangeKind::Modified,
                },
            ]
        );
        fs::remove_dir_all(fixture).expect("fixture must clean");
    }
}
