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
    use std::fs;

    use super::{
        DirectWorkspaceBackend, WorkspaceBackend, WorkspaceChange, WorkspaceChangeKind,
        WorkspaceError, WorkspaceKind, WorkspaceLimits, WorkspaceSnapshot,
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
        let fixture = std::env::temp_dir().join(format!(
            "bolt-workspace-conflict-{}",
            std::process::id()
        ));
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
}
