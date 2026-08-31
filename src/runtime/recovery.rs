use std::{
    ffi::OsString,
    fs,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use crate::policy::compiler::{CompiledFilesystemPolicy, FilesystemAccess, FilesystemDecision};
use crate::{RecoveryArtifact, RecoveryFailure, RecoveryFailureReason, SandboxEvent};

use super::{
    preparation::PreparedRecovery,
    recovery_protocol::{RecoveryOperation, RecoveryRequest},
};

pub(super) struct RecoveryCoordinator {
    execution_directory: PathBuf,
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
        let mut execution_name = String::from("bolt-");
        for byte in nonce {
            use std::fmt::Write as _;
            write!(execution_name, "{byte:02x}")
                .map_err(|_| RecoveryCoordinatorError::CreateExecutionDirectory)?;
        }
        let execution_directory = configuration.directory.join(execution_name);
        fs::create_dir(&execution_directory)
            .map_err(|_| RecoveryCoordinatorError::CreateExecutionDirectory)?;
        Ok(Some(Self {
            execution_directory,
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
        if self
            .filesystem
            .decide(&request.path, FilesystemAccess::Write)
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
        let final_path = self
            .execution_directory
            .join(format!("artifact-{artifact_id:016x}.bin"));
        let temporary_path = final_path.with_extension("partial");
        let copied = fs::copy(&request.path, &temporary_path);
        let Ok(copied) = copied else {
            let _ = fs::remove_file(&temporary_path);
            return recovery_failure(request.process_id, RecoveryFailureReason::StoreUnavailable);
        };
        if copied != byte_count || fs::rename(&temporary_path, &final_path).is_err() {
            let _ = fs::remove_file(&temporary_path);
            let _ = fs::remove_file(&final_path);
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
                original_path: display_path(&request.path),
                byte_count,
            })),
        }
    }
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
        if self.used_items == 0 {
            let _ = fs::remove_dir(&self.execution_directory);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxPolicy, policy::compiler};
    use std::sync::atomic::{AtomicU64, Ordering};

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
        fs::remove_dir_all(root).expect("fixture must clean up");
    }

    fn recovery_files_for_test(root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in fs::read_dir(root).expect("store must be readable") {
            let path = entry.expect("entry must be readable").path();
            if path.is_dir() {
                files.extend(
                    fs::read_dir(path)
                        .expect("execution store must be readable")
                        .map(|entry| entry.expect("artifact must be readable").path()),
                );
            } else {
                files.push(path);
            }
        }
        files
    }
}
