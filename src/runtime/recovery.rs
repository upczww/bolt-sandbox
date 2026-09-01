use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::policy::compiler::{CompiledFilesystemPolicy, FilesystemAccess, FilesystemDecision};
use crate::{RecoveryArtifact, RecoveryFailure, RecoveryFailureReason, SandboxEvent};

use super::{
    preparation::PreparedRecovery,
    recovery_protocol::{RecoveryOperation, RecoveryRequest},
};

pub(super) struct RecoveryCoordinator {
    execution_directory: PathBuf,
    active_lock: Option<File>,
    active_lock_path: PathBuf,
    maximum_bytes: u64,
    maximum_items: u32,
    used_bytes: u64,
    used_items: u32,
    next_artifact_id: u64,
    filesystem: CompiledFilesystemPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryCoordinatorError {
    InvalidStore,
    CreateExecutionDirectory,
}

pub(super) struct RecoveryOutcome {
    pub(super) artifact_id: Option<u64>,
    pub(super) byte_count: u64,
    pub(super) event: Option<SandboxEvent>,
}

impl RecoveryCoordinator {
    pub(super) fn new(
        configuration: Option<&PreparedRecovery>,
        nonce: &[u8; 16],
    ) -> Result<Option<Self>, RecoveryCoordinatorError> {
        let Some(configuration) = configuration else {
            return Ok(None);
        };
        if !configuration.directory.is_absolute()
            || !configuration.directory.is_dir()
            || configuration.maximum_bytes == 0
            || configuration.maximum_items == 0
        {
            return Err(RecoveryCoordinatorError::InvalidStore);
        }
        let _ = cleanup_expired(
            &configuration.directory,
            configuration.retention,
            SystemTime::now(),
        );
        let mut execution_name = String::from("bolt-");
        for byte in nonce {
            use std::fmt::Write as _;
            write!(execution_name, "{byte:02x}")
                .map_err(|_| RecoveryCoordinatorError::CreateExecutionDirectory)?;
        }
        let execution_directory = configuration.directory.join(execution_name);
        fs::create_dir(&execution_directory)
            .map_err(|_| RecoveryCoordinatorError::CreateExecutionDirectory)?;
        let active_lock_path = execution_directory.join("active.lock");
        let active_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(1)
            .open(&active_lock_path)
            .map_err(|_| RecoveryCoordinatorError::CreateExecutionDirectory)?;
        if !write_execution_marker(&execution_directory, SystemTime::now()) {
            drop(active_lock);
            let _ = fs::remove_dir_all(&execution_directory);
            return Err(RecoveryCoordinatorError::CreateExecutionDirectory);
        }
        Ok(Some(Self {
            execution_directory,
            active_lock: Some(active_lock),
            active_lock_path,
            maximum_bytes: configuration.maximum_bytes,
            maximum_items: configuration.maximum_items,
            used_bytes: 0,
            used_items: 0,
            next_artifact_id: 1,
            filesystem: configuration.filesystem.clone(),
        }))
    }

    pub(super) fn backup(&mut self, request: &RecoveryRequest) -> RecoveryOutcome {
        let silent_failure = || RecoveryOutcome {
            artifact_id: None,
            byte_count: 0,
            event: None,
        };
        if !matches!(
            request.operation,
            RecoveryOperation::Delete
                | RecoveryOperation::Truncate
                | RecoveryOperation::Replace
                | RecoveryOperation::Rename
        ) || !request.path.is_absolute()
        {
            return silent_failure();
        }
        let indexed_path = display_path(&request.path);
        if self
            .filesystem
            .decide(&indexed_path, FilesystemAccess::Write)
            != FilesystemDecision::Allow
        {
            return silent_failure();
        }
        let Ok(metadata) = fs::symlink_metadata(&request.path) else {
            return recovery_failure(request.process_id, RecoveryFailureReason::SourceUnavailable);
        };
        if !metadata.file_type().is_file() {
            return recovery_failure(request.process_id, RecoveryFailureReason::UnsupportedObject);
        }
        let byte_count = metadata.len();
        let Some(next_bytes) = self.used_bytes.checked_add(byte_count) else {
            return recovery_failure(request.process_id, RecoveryFailureReason::CounterOverflow);
        };
        let Some(next_items) = self.used_items.checked_add(1) else {
            return recovery_failure(request.process_id, RecoveryFailureReason::CounterOverflow);
        };
        if next_bytes > self.maximum_bytes || next_items > self.maximum_items {
            return recovery_failure(request.process_id, RecoveryFailureReason::QuotaExceeded);
        }
        let Some(next_artifact_id) = self.next_artifact_id.checked_add(1) else {
            return recovery_failure(request.process_id, RecoveryFailureReason::CounterOverflow);
        };
        let artifact_id = self.next_artifact_id;
        let final_directory = self
            .execution_directory
            .join(format!("artifact-{artifact_id:016x}"));
        let temporary_directory = self
            .execution_directory
            .join(format!("artifact-{artifact_id:016x}.partial"));
        if fs::create_dir(&temporary_directory).is_err() {
            return recovery_failure(request.process_id, RecoveryFailureReason::StoreUnavailable);
        }
        let content_path = temporary_directory.join("content.bin");
        let metadata_path = temporary_directory.join("metadata.bin");
        let committed = fs::copy(&request.path, &content_path)
            .is_ok_and(|copied| copied == byte_count)
            && sync_file(&content_path)
            && write_metadata(&metadata_path, artifact_id, request, byte_count)
            && fs::rename(&temporary_directory, &final_directory).is_ok();
        if !committed {
            let _ = fs::remove_dir_all(&temporary_directory);
            let _ = fs::remove_dir_all(&final_directory);
            return recovery_failure(request.process_id, RecoveryFailureReason::StoreUnavailable);
        }
        self.used_bytes = next_bytes;
        self.used_items = next_items;
        self.next_artifact_id = next_artifact_id;
        RecoveryOutcome {
            artifact_id: Some(artifact_id),
            byte_count,
            event: Some(SandboxEvent::RecoveryArtifactCreated(RecoveryArtifact {
                process_id: request.process_id,
                artifact_id,
                original_path: indexed_path,
                byte_count,
            })),
        }
    }
}

fn sync_file(path: &Path) -> bool {
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .is_ok()
}

fn write_metadata(
    path: &Path,
    artifact_id: u64,
    request: &RecoveryRequest,
    byte_count: u64,
) -> bool {
    const HEADER_LENGTH: usize = 40;
    const HEADER_LENGTH_U16: u16 = 40;
    let indexed_path = display_path(&request.path);
    let encoded_path: Vec<u16> = indexed_path.as_os_str().encode_wide().collect();
    let Some(total_length) = encoded_path
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(HEADER_LENGTH))
        .and_then(|length| u32::try_from(length).ok())
    else {
        return false;
    };
    let Ok(path_length) = u32::try_from(encoded_path.len()) else {
        return false;
    };
    let Ok(capacity) = usize::try_from(total_length) else {
        return false;
    };
    let mut metadata = Vec::with_capacity(capacity);
    metadata.extend_from_slice(b"BRI1");
    metadata.extend_from_slice(&1_u16.to_le_bytes());
    metadata.extend_from_slice(&HEADER_LENGTH_U16.to_le_bytes());
    metadata.extend_from_slice(&artifact_id.to_le_bytes());
    metadata.extend_from_slice(&request.process_id.to_le_bytes());
    metadata.extend_from_slice(&[request.operation as u8, 0, 0, 0]);
    metadata.extend_from_slice(&byte_count.to_le_bytes());
    metadata.extend_from_slice(&path_length.to_le_bytes());
    metadata.extend_from_slice(&total_length.to_le_bytes());
    for unit in encoded_path {
        metadata.extend_from_slice(&unit.to_le_bytes());
    }
    let file = OpenOptions::new().write(true).create_new(true).open(path);
    let Ok(mut file) = file else {
        return false;
    };
    file.write_all(&metadata).is_ok() && file.sync_all().is_ok()
}

fn recovery_failure(process_id: u32, reason: RecoveryFailureReason) -> RecoveryOutcome {
    RecoveryOutcome {
        artifact_id: None,
        byte_count: 0,
        event: Some(SandboxEvent::RecoveryFailed(RecoveryFailure {
            process_id,
            reason,
        })),
    }
}

fn display_path(path: &Path) -> PathBuf {
    const VERBATIM_PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const VERBATIM_UNC: &[u16] = &[
        b'\\' as u16,
        b'\\' as u16,
        b'?' as u16,
        b'\\' as u16,
        b'U' as u16,
        b'N' as u16,
        b'C' as u16,
        b'\\' as u16,
    ];
    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if let Some(remainder) = encoded.strip_prefix(VERBATIM_UNC) {
        let mut unc = vec![u16::from(b'\\'), u16::from(b'\\')];
        unc.extend_from_slice(remainder);
        return PathBuf::from(OsString::from_wide(&unc));
    }
    if let Some(remainder) = encoded.strip_prefix(VERBATIM_PREFIX) {
        return PathBuf::from(OsString::from_wide(remainder));
    }
    path.to_path_buf()
}

impl Drop for RecoveryCoordinator {
    fn drop(&mut self) {
        drop(self.active_lock.take());
        let _ = fs::remove_file(&self.active_lock_path);
        if self.used_items == 0 {
            let _ = fs::remove_file(self.execution_directory.join("execution.bin"));
            let _ = fs::remove_dir(&self.execution_directory);
        }
    }
}

fn write_execution_marker(directory: &Path, created: SystemTime) -> bool {
    let Ok(created_millis) = created
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(())
    else {
        return false;
    };
    let mut marker = Vec::from(*b"BRE1");
    marker.extend_from_slice(&created_millis.to_le_bytes());
    let path = directory.join("execution.bin");
    let file = OpenOptions::new().write(true).create_new(true).open(path);
    let Ok(mut file) = file else {
        return false;
    };
    file.write_all(&marker).is_ok() && file.sync_all().is_ok()
}

fn cleanup_expired(root: &Path, retention: Duration, now: SystemTime) -> std::io::Result<()> {
    let now_millis = now
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0);
    let retention_millis = u64::try_from(retention.as_millis()).unwrap_or(u64::MAX);
    for entry in fs::read_dir(root)? {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let name_matches = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("bolt-"));
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !name_matches || !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let Ok(marker) = fs::read(path.join("execution.bin")) else {
            continue;
        };
        if marker.len() != 12 || marker[..4] != *b"BRE1" {
            continue;
        }
        let created = u64::from_le_bytes(marker[4..12].try_into().expect("marker length checked"));
        if now_millis.saturating_sub(created) < retention_millis {
            continue;
        }
        match fs::remove_file(path.join("active.lock")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => continue,
        }
        let _ = fs::remove_dir_all(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxPolicy, policy::compiler};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::{
        os::windows::fs::OpenOptionsExt,
        time::{Duration, SystemTime},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn rec_018_coordinator_rejects_source_without_write_authority() {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "bolt-recovery-authority-unit-{}-{id}",
            std::process::id()
        ));
        let work = root.join("work");
        let outside = root.join("outside");
        let store = root.join("store");
        fs::create_dir_all(&work).expect("work must be created");
        fs::create_dir_all(&outside).expect("outside must be created");
        fs::create_dir_all(&store).expect("store must be created");
        let secret = outside.join("secret.bin");
        fs::write(&secret, b"secret").expect("secret fixture must be written");
        let compiled = compiler::compile(&SandboxPolicy::default(), &work)
            .expect("default policy must compile");
        let configuration = PreparedRecovery {
            directory: store.clone(),
            maximum_bytes: 1_024,
            maximum_items: 4,
            retention: std::time::Duration::from_secs(24 * 60 * 60),
            filesystem: compiled.filesystem,
        };
        let mut coordinator = RecoveryCoordinator::new(Some(&configuration), &[0xA5; 16])
            .expect("coordinator must initialize")
            .expect("recovery must be enabled");
        let outcome = coordinator.backup(&RecoveryRequest {
            request_id: 1,
            process_id: 42,
            operation: RecoveryOperation::Delete,
            path: secret,
        });

        assert_eq!(outcome.artifact_id, None);
        assert!(outcome.event.is_none());
        assert!(recovery_files_for_test(&store).is_empty());
        drop(coordinator);
        fs::remove_dir_all(root).expect("fixture must clean up");
    }

    #[test]
    fn rec_001_artifact_commits_content_and_versioned_path_index_together() {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "bolt-recovery-index-unit-{}-{id}",
            std::process::id()
        ));
        let work = root.join("work");
        let store = root.join("store");
        fs::create_dir_all(&work).expect("work must be created");
        fs::create_dir_all(&store).expect("store must be created");
        let source = work.join("indexed.bin");
        fs::write(&source, b"indexed-content").expect("source must be written");
        let compiled = compiler::compile(&SandboxPolicy::default(), &work)
            .expect("default policy must compile");
        let configuration = PreparedRecovery {
            directory: store.clone(),
            maximum_bytes: 1_024,
            maximum_items: 4,
            retention: std::time::Duration::from_secs(24 * 60 * 60),
            filesystem: compiled.filesystem,
        };
        let mut coordinator = RecoveryCoordinator::new(Some(&configuration), &[0x5A; 16])
            .expect("coordinator must initialize")
            .expect("recovery must be enabled");
        let outcome = coordinator.backup(&RecoveryRequest {
            request_id: 1,
            process_id: 42,
            operation: RecoveryOperation::Delete,
            path: source.clone(),
        });
        assert_eq!(outcome.artifact_id, Some(1));

        let execution = fs::read_dir(&store)
            .expect("store must be readable")
            .next()
            .expect("execution directory must exist")
            .expect("execution entry must be readable")
            .path();
        let artifact = fs::read_dir(execution)
            .expect("execution directory must be readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.is_dir()
                    && path.file_name().is_some_and(|name| {
                        let name = name.to_string_lossy();
                        name.starts_with("artifact-") && !name.ends_with(".partial")
                    })
            })
            .expect("artifact directory must exist");
        assert!(artifact.is_dir());
        assert_eq!(
            fs::read(artifact.join("content.bin")).expect("artifact content must be readable"),
            b"indexed-content"
        );
        let metadata =
            fs::read(artifact.join("metadata.bin")).expect("artifact metadata must be readable");
        assert_eq!(&metadata[..4], b"BRI1");
        assert_eq!(&metadata[8..16], &1_u64.to_le_bytes());
        assert_eq!(&metadata[16..20], &42_u32.to_le_bytes());
        assert_eq!(&metadata[24..32], &15_u64.to_le_bytes());
        let encoded_path: Vec<u8> = source
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(metadata.ends_with(&encoded_path));
        drop(coordinator);
        fs::remove_dir_all(root).expect("fixture must clean up");
    }

    #[test]
    fn rec_008_cleanup_skips_active_and_fresh_execution_directories() {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "bolt-recovery-retention-unit-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("retention root must be created");
        let stale = root.join("bolt-stale");
        let active = root.join("bolt-active");
        let fresh = root.join("bolt-fresh");
        for directory in [&stale, &active, &fresh] {
            fs::create_dir(directory).expect("execution directory must be created");
        }
        write_test_execution_marker(&stale, 0);
        write_test_execution_marker(&active, 0);
        let now = SystemTime::now();
        let now_millis = u64::try_from(
            now.duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after epoch")
                .as_millis(),
        )
        .expect("current time fits");
        write_test_execution_marker(&fresh, now_millis);
        fs::write(active.join("active.lock"), []).expect("active marker must be written");
        let active_lease = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(active.join("active.lock"))
            .expect("active lease must open");

        cleanup_expired(&root, Duration::from_secs(1), now)
            .expect("retention cleanup must succeed");

        assert!(!stale.exists());
        assert!(active.exists());
        assert!(fresh.exists());
        drop(active_lease);
        fs::remove_dir_all(root).expect("retention fixture must clean up");
    }

    fn write_test_execution_marker(directory: &Path, created_millis: u64) {
        let mut marker = Vec::from(*b"BRE1");
        marker.extend_from_slice(&created_millis.to_le_bytes());
        fs::write(directory.join("execution.bin"), marker)
            .expect("execution marker must be written");
    }

    fn recovery_files_for_test(root: &Path) -> Vec<PathBuf> {
        let mut pending = vec![root.to_path_buf()];
        let mut files = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).expect("store must be readable") {
                let path = entry.expect("entry must be readable").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.file_name().is_some_and(|name| name == "content.bin") {
                    files.push(path);
                }
            }
        }
        files
    }
}
