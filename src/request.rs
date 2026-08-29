use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, time::Duration};

use crate::{InvalidRequestReason, RequestField, SandboxError, SandboxPolicy};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxRequest {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub policy: SandboxPolicy,
    pub timeout: Option<Duration>,
}

impl SandboxRequest {
    /// Validates the host-owned fields needed before launcher startup.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::InvalidRequest`] when the program or current
    /// directory is not absolute or does not identify the required object type.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if !self.program.is_absolute() {
            return Err(SandboxError::InvalidRequest {
                field: RequestField::Program,
                reason: InvalidRequestReason::MustBeAbsolute,
            });
        }

        if !self.program.is_file() {
            return Err(SandboxError::InvalidRequest {
                field: RequestField::Program,
                reason: InvalidRequestReason::NotAFile,
            });
        }

        if !self.cwd.is_absolute() {
            return Err(SandboxError::InvalidRequest {
                field: RequestField::CurrentDirectory,
                reason: InvalidRequestReason::MustBeAbsolute,
            });
        }

        if !self.cwd.is_dir() {
            return Err(SandboxError::InvalidRequest {
                field: RequestField::CurrentDirectory,
                reason: InvalidRequestReason::NotADirectory,
            });
        }

        Ok(())
    }
}
