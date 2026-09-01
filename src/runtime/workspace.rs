use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceKind {
    Direct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceError {
    InvalidRoot,
    QuotaExceeded,
    UnsupportedObject,
    Io,
    Conflict,
    RollbackFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkspaceLimits {
    pub(super) maximum_items: u32,
    pub(super) maximum_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WorkspaceChange {
    pub(super) relative_path: PathBuf,
    pub(super) kind: WorkspaceChangeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WorkspaceEntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceFingerprint {
    kind: WorkspaceEntryKind,
    length: u64,
    digest: [u8; 32],
}

pub(super) struct WorkspaceSnapshot {
    limits: WorkspaceLimits,
    entries: BTreeMap<PathBuf, WorkspaceFingerprint>,
}

pub(super) struct StagedWorkspaceTransaction {
    snapshot: WorkspaceSnapshot,
    source_root: PathBuf,
    staging_root: PathBuf,
}

pub(super) struct CommittedWorkspace {
    changes: Vec<WorkspaceChange>,
    source_root: PathBuf,
    discarded_root: PathBuf,
    recovery_root: PathBuf,
}

impl CommittedWorkspace {
    pub(super) fn changes(&self) -> &[WorkspaceChange] {
        &self.changes
    }

    pub(super) fn recovery_root(&self) -> &Path {
        &self.recovery_root
    }

    pub(super) fn revert(self) -> Result<(), WorkspaceError> {
        if !self.source_root.is_dir()
            || !self.recovery_root.is_dir()
            || self.discarded_root.exists()
        {
            return Err(WorkspaceError::Conflict);
        }
        fs::rename(&self.source_root, &self.discarded_root).map_err(map_io)?;
        if fs::rename(&self.recovery_root, &self.source_root).is_err() {
            if fs::rename(&self.discarded_root, &self.source_root).is_err() {
                return Err(WorkspaceError::RollbackFailed);
            }
            return Err(WorkspaceError::Io);
        }
        fs::remove_dir_all(&self.discarded_root).map_err(map_io)
    }
}

impl StagedWorkspaceTransaction {
    pub(super) fn prepare(
        source_root: &Path,
        staging_root: &Path,
        limits: WorkspaceLimits,
    ) -> Result<Self, WorkspaceError> {
        validate_staging_root(source_root, staging_root)?;
        let snapshot = WorkspaceSnapshot::capture(source_root, limits)?;
        fs::create_dir(staging_root).map_err(map_io)?;
        if let Err(error) = copy_snapshot(source_root, staging_root, &snapshot) {
            let _ = fs::remove_dir_all(staging_root);
            return Err(error);
        }
        let staged_entries = capture_entries(staging_root, limits)?;
        if staged_entries != snapshot.entries {
            let _ = fs::remove_dir_all(staging_root);
            return Err(WorkspaceError::Conflict);
        }
        Ok(Self {
            snapshot,
            source_root: source_root.to_path_buf(),
            staging_root: staging_root.to_path_buf(),
        })
    }

    pub(super) fn execution_root(&self) -> &Path {
        &self.staging_root
    }

    pub(super) fn query_changes(&self) -> Result<Vec<WorkspaceChange>, WorkspaceError> {
        self.snapshot.diff(&self.staging_root)
    }

    pub(super) fn discard(self) -> Result<(), WorkspaceError> {
        fs::remove_dir_all(&self.staging_root).map_err(map_io)
    }

    pub(super) fn commit(self, recovery_root: &Path) -> Result<CommittedWorkspace, WorkspaceError> {
        validate_recovery_root(&self.source_root, recovery_root)?;
        self.snapshot.validate_source_unchanged(&self.source_root)?;
        let changes = self.query_changes()?;
        fs::rename(&self.source_root, recovery_root).map_err(map_io)?;
        if fs::rename(&self.staging_root, &self.source_root).is_err() {
            if fs::rename(recovery_root, &self.source_root).is_err() {
                return Err(WorkspaceError::RollbackFailed);
            }
            return Err(WorkspaceError::Io);
        }
        Ok(CommittedWorkspace {
            changes,
            source_root: self.source_root,
            discarded_root: self.staging_root,
            recovery_root: recovery_root.to_path_buf(),
        })
    }
}

impl WorkspaceSnapshot {
    pub(super) fn capture(root: &Path, limits: WorkspaceLimits) -> Result<Self, WorkspaceError> {
        Ok(Self {
            limits,
            entries: capture_entries(root, limits)?,
        })
    }

    pub(super) fn diff(&self, root: &Path) -> Result<Vec<WorkspaceChange>, WorkspaceError> {
        let current = capture_entries(root, self.limits)?;
        let paths: BTreeSet<_> = self.entries.keys().chain(current.keys()).cloned().collect();
        let mut changes = Vec::new();
        for path in paths {
            let kind = match (self.entries.get(&path), current.get(&path)) {
                (None, Some(_)) => Some(WorkspaceChangeKind::Created),
                (Some(_), None) => Some(WorkspaceChangeKind::Deleted),
                (Some(before), Some(after)) if before != after => {
                    Some(WorkspaceChangeKind::Modified)
                }
                (Some(_), Some(_)) | (None, None) => None,
            };
            if let Some(kind) = kind {
                changes.push(WorkspaceChange {
                    relative_path: path,
                    kind,
                });
            }
        }
        Ok(changes)
    }

    pub(super) fn validate_source_unchanged(&self, root: &Path) -> Result<(), WorkspaceError> {
        let current = capture_entries(root, self.limits)?;
        (current == self.entries)
            .then_some(())
            .ok_or(WorkspaceError::Conflict)
    }
}

fn capture_entries(
    root: &Path,
    limits: WorkspaceLimits,
) -> Result<BTreeMap<PathBuf, WorkspaceFingerprint>, WorkspaceError> {
    if !root.is_absolute() || !root.is_dir() || limits.maximum_items == 0 {
        return Err(WorkspaceError::InvalidRoot);
    }
    let mut entries = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    let mut byte_count = 0_u64;
    while let Some(directory) = pending.pop() {
        let children = fs::read_dir(&directory).map_err(map_io)?;
        for child in children {
            let child = child.map_err(map_io)?;
            let path = child.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| WorkspaceError::InvalidRoot)?
                .to_path_buf();
            if relative.as_os_str().is_empty()
                || !relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(WorkspaceError::UnsupportedObject);
            }
            let metadata = fs::symlink_metadata(&path).map_err(map_io)?;
            if metadata.file_type().is_symlink()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(WorkspaceError::UnsupportedObject);
            }
            let fingerprint = if metadata.is_dir() {
                pending.push(path);
                WorkspaceFingerprint {
                    kind: WorkspaceEntryKind::Directory,
                    length: 0,
                    digest: [0; 32],
                }
            } else if metadata.is_file() {
                byte_count = byte_count
                    .checked_add(metadata.len())
                    .ok_or(WorkspaceError::QuotaExceeded)?;
                if byte_count > limits.maximum_bytes {
                    return Err(WorkspaceError::QuotaExceeded);
                }
                WorkspaceFingerprint {
                    kind: WorkspaceEntryKind::File,
                    length: metadata.len(),
                    digest: hash_file(&path)?,
                }
            } else {
                return Err(WorkspaceError::UnsupportedObject);
            };
            entries.insert(relative, fingerprint);
            if entries.len()
                > usize::try_from(limits.maximum_items)
                    .map_err(|_| WorkspaceError::QuotaExceeded)?
            {
                return Err(WorkspaceError::QuotaExceeded);
            }
        }
    }
    Ok(entries)
}

fn validate_staging_root(source_root: &Path, staging_root: &Path) -> Result<(), WorkspaceError> {
    if !source_root.is_absolute()
        || !source_root.is_dir()
        || !staging_root.is_absolute()
        || staging_root.exists()
    {
        return Err(WorkspaceError::InvalidRoot);
    }
    let staging_parent = staging_root.parent().ok_or(WorkspaceError::InvalidRoot)?;
    let staging_name = staging_root
        .file_name()
        .ok_or(WorkspaceError::InvalidRoot)?;
    let canonical_source = fs::canonicalize(source_root).map_err(map_io)?;
    let canonical_source_parent = canonical_source
        .parent()
        .ok_or(WorkspaceError::InvalidRoot)?;
    let canonical_staging_parent = fs::canonicalize(staging_parent).map_err(map_io)?;
    if canonical_source_parent != canonical_staging_parent {
        return Err(WorkspaceError::InvalidRoot);
    }
    let canonical_staging = canonical_staging_parent.join(staging_name);
    if canonical_source.starts_with(&canonical_staging)
        || canonical_staging.starts_with(&canonical_source)
    {
        return Err(WorkspaceError::InvalidRoot);
    }
    Ok(())
}

fn validate_recovery_root(source_root: &Path, recovery_root: &Path) -> Result<(), WorkspaceError> {
    if !recovery_root.is_absolute() || recovery_root.exists() {
        return Err(WorkspaceError::InvalidRoot);
    }
    let source_parent = source_root.parent().ok_or(WorkspaceError::InvalidRoot)?;
    let recovery_parent = recovery_root.parent().ok_or(WorkspaceError::InvalidRoot)?;
    if fs::canonicalize(source_parent).map_err(map_io)?
        != fs::canonicalize(recovery_parent).map_err(map_io)?
    {
        return Err(WorkspaceError::InvalidRoot);
    }
    Ok(())
}

fn copy_snapshot(
    source_root: &Path,
    staging_root: &Path,
    snapshot: &WorkspaceSnapshot,
) -> Result<(), WorkspaceError> {
    for (relative, fingerprint) in &snapshot.entries {
        let source = source_root.join(relative);
        let destination = staging_root.join(relative);
        match fingerprint.kind {
            WorkspaceEntryKind::Directory => fs::create_dir_all(&destination).map_err(map_io)?,
            WorkspaceEntryKind::File => {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent).map_err(map_io)?;
                }
                let copied = fs::copy(source, destination).map_err(map_io)?;
                if copied != fingerprint.length {
                    return Err(WorkspaceError::Conflict);
                }
            }
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<[u8; 32], WorkspaceError> {
    let mut file = File::open(path).map_err(map_io)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(map_io)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

fn map_io(_: io::Error) -> WorkspaceError {
    WorkspaceError::Io
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
    use std::{fs, path::PathBuf};

    use super::{
        DirectWorkspaceBackend, StagedWorkspaceTransaction, WorkspaceBackend, WorkspaceChange,
        WorkspaceChangeKind, WorkspaceError, WorkspaceKind, WorkspaceLimits, WorkspaceSnapshot,
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
        let fixture =
            std::env::temp_dir().join(format!("bolt-workspace-diff-{}", std::process::id()));
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

    #[test]
    fn ws_018_snapshot_rejects_external_source_conflicts() {
        let fixture =
            std::env::temp_dir().join(format!("bolt-workspace-conflict-{}", std::process::id()));
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir_all(&fixture).expect("fixture must create");
        fs::write(fixture.join("source.txt"), b"before").expect("seed must write");
        let snapshot = WorkspaceSnapshot::capture(
            &fixture,
            WorkspaceLimits {
                maximum_items: 8,
                maximum_bytes: 1_048_576,
            },
        )
        .expect("snapshot must capture");

        snapshot
            .validate_source_unchanged(&fixture)
            .expect("unchanged source must validate");
        fs::write(fixture.join("source.txt"), b"external-change")
            .expect("external mutation must write");
        assert_eq!(
            snapshot.validate_source_unchanged(&fixture),
            Err(WorkspaceError::Conflict)
        );
        fs::remove_dir_all(fixture).expect("fixture must clean");
    }

    #[test]
    fn ws_007_staged_transaction_isolated_query_and_discard() {
        let fixture =
            std::env::temp_dir().join(format!("bolt-workspace-stage-{}", std::process::id()));
        let source = fixture.join("source");
        let staged = fixture.join("staged");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir_all(source.join("nested")).expect("source must create");
        fs::write(source.join(r"nested\file.txt"), b"before").expect("seed must write");

        let transaction = StagedWorkspaceTransaction::prepare(
            &source,
            &staged,
            WorkspaceLimits {
                maximum_items: 16,
                maximum_bytes: 1_048_576,
            },
        )
        .expect("transaction must prepare");
        assert_eq!(transaction.execution_root(), staged);
        fs::write(staged.join(r"nested\file.txt"), b"after").expect("stage must mutate");
        assert_eq!(
            fs::read(source.join(r"nested\file.txt")).expect("source"),
            b"before"
        );
        assert_eq!(
            transaction.query_changes().expect("query must succeed"),
            vec![WorkspaceChange {
                relative_path: PathBuf::from(r"nested\file.txt"),
                kind: WorkspaceChangeKind::Modified,
            }]
        );

        transaction.discard().expect("discard must succeed");
        assert!(!staged.exists());
        assert_eq!(
            fs::read(source.join(r"nested\file.txt")).expect("source"),
            b"before"
        );
        fs::remove_dir_all(fixture).expect("fixture must clean");
    }

    #[test]
    fn ws_016_commit_swaps_complete_workspace_and_retains_recovery_root() {
        let fixture =
            std::env::temp_dir().join(format!("bolt-workspace-commit-{}", std::process::id()));
        let source = fixture.join("source");
        let staged = fixture.join("staged");
        let recovery = fixture.join("recovery");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir_all(&source).expect("source must create");
        fs::write(source.join("file.txt"), b"before").expect("seed must write");
        let transaction = StagedWorkspaceTransaction::prepare(
            &source,
            &staged,
            WorkspaceLimits {
                maximum_items: 16,
                maximum_bytes: 1_048_576,
            },
        )
        .expect("transaction must prepare");
        fs::write(staged.join("file.txt"), b"after").expect("stage must mutate");

        let committed = transaction.commit(&recovery).expect("commit must succeed");

        assert_eq!(fs::read(source.join("file.txt")).expect("source"), b"after");
        assert_eq!(
            fs::read(recovery.join("file.txt")).expect("recovery"),
            b"before"
        );
        assert_eq!(committed.recovery_root(), recovery);
        assert_eq!(
            committed.changes(),
            &[WorkspaceChange {
                relative_path: PathBuf::from("file.txt"),
                kind: WorkspaceChangeKind::Modified,
            }]
        );
        committed.revert().expect("revert must succeed");
        assert_eq!(
            fs::read(source.join("file.txt")).expect("source"),
            b"before"
        );
        assert!(!recovery.exists());
        assert!(!staged.exists());
        fs::remove_dir_all(fixture).expect("fixture must clean");
    }
}
