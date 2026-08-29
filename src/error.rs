use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestField {
    Program,
    Arguments,
    CurrentDirectory,
    Environment,
    Timeout,
    FilesystemPolicy,
    NetworkPolicy,
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
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { field, reason } => {
                write!(formatter, "invalid request field {field:?}: {reason:?}")
            }
        }
    }
}

impl Error for SandboxError {}
