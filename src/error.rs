use std::{error::Error, fmt};

use crate::{ConfigurationErrorReason, ConfigurationField, InitializationStage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestField {
    Program,
    Arguments,
    CurrentDirectory,
    Environment,
    Timeout,
    FilesystemPolicy,
    NetworkPolicy,
    RegistryPolicy,
    RecoveryPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidRequestReason {
    Empty,
    MustBeAbsolute,
    NotAFile,
    NotADirectory,
    InvalidCharacter,
    ReservedName,
    ConflictingNames,
    OutOfRange,
    TooManyItems,
    TooLarge,
    EscapesRoot,
    ConflictingRules,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxError {
    InvalidRequest {
        field: RequestField,
        reason: InvalidRequestReason,
    },
    InvalidConfiguration {
        field: ConfigurationField,
        reason: ConfigurationErrorReason,
    },
    InitializationFailed {
        stage: InitializationStage,
    },
    ControlChannelClosed,
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { field, reason } => {
                write!(formatter, "invalid request field {field:?}: {reason:?}")
            }
            Self::InvalidConfiguration { field, reason } => {
                write!(
                    formatter,
                    "invalid configuration field {field:?}: {reason:?}"
                )
            }
            Self::InitializationFailed { stage } => {
                write!(formatter, "sandbox initialization failed at {stage:?}")
            }
            Self::ControlChannelClosed => formatter.write_str("sandbox control channel closed"),
        }
    }
}

impl Error for SandboxError {}
