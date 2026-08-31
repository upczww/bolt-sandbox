use std::{
    ffi::OsString,
    fs,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use crate::{RecoveryArtifact, SandboxEvent};

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
        }))
    }

    pub(super) fn backup(&mut self, request: &RecoveryRequest) -> RecoveryOutcome {
        let failed = || RecoveryOutcome {
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
            return failed();
        }
        let Ok(metadata) = fs::symlink_metadata(&request.path) else {
            return failed();
        };
        if !metadata.file_type().is_file() {
            return failed();
        }
        let byte_count = metadata.len();
        let Some(next_bytes) = self.used_bytes.checked_add(byte_count) else {
            return failed();
        };
        let Some(next_items) = self.used_items.checked_add(1) else {
            return failed();
        };
        if next_bytes > self.maximum_bytes || next_items > self.maximum_items {
            return failed();
        }
        let artifact_id = self.next_artifact_id;
        let final_path = self
            .execution_directory
            .join(format!("artifact-{artifact_id:016x}.bin"));
        let temporary_path = final_path.with_extension("partial");
        let copied = fs::copy(&request.path, &temporary_path);
        let Ok(copied) = copied else {
            let _ = fs::remove_file(&temporary_path);
            return failed();
        };
        if copied != byte_count || fs::rename(&temporary_path, &final_path).is_err() {
            let _ = fs::remove_file(&temporary_path);
            let _ = fs::remove_file(&final_path);
            return failed();
        }
        self.used_bytes = next_bytes;
        self.used_items = next_items;
        self.next_artifact_id = self.next_artifact_id.saturating_add(1);
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
