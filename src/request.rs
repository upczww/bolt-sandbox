use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    time::Duration,
};

use crate::{InvalidRequestReason, RequestField, SandboxError, SandboxPolicy, policy};

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

        validate_environment(&self.environment)?;

        let _compiled_policy = policy::compiler::compile(&self.policy, &self.cwd)?;

        Ok(())
    }
}

fn validate_environment(environment: &BTreeMap<OsString, OsString>) -> Result<(), SandboxError> {
    let mut normalized_names = BTreeSet::new();
    for (name, value) in environment {
        if name.is_empty() {
            return Err(invalid_environment(InvalidRequestReason::Empty));
        }
        if contains_nul(name) || contains_nul(value) {
            return Err(invalid_environment(InvalidRequestReason::InvalidCharacter));
        }
        if name.as_os_str().encode_wide().next() == Some(u16::from(b'=')) {
            return Err(invalid_environment(InvalidRequestReason::ReservedName));
        }
        if name
            .as_os_str()
            .encode_wide()
            .any(|code_unit| code_unit == u16::from(b'='))
        {
            return Err(invalid_environment(InvalidRequestReason::InvalidCharacter));
        }

        let normalized_name = normalize_environment_name(name)?;
        if !normalized_names.insert(normalized_name) {
            return Err(invalid_environment(InvalidRequestReason::ConflictingNames));
        }
    }
    Ok(())
}

fn normalize_environment_name(name: &OsStr) -> Result<String, SandboxError> {
    let mut normalized = String::new();
    for decoded in char::decode_utf16(name.encode_wide()) {
        let character =
            decoded.map_err(|_| invalid_environment(InvalidRequestReason::InvalidCharacter))?;
        normalized.extend(character.to_uppercase());
    }
    Ok(normalized)
}

fn contains_nul(value: &OsStr) -> bool {
    value.encode_wide().any(|code_unit| code_unit == 0)
}

const fn invalid_environment(reason: InvalidRequestReason) -> SandboxError {
    SandboxError::InvalidRequest {
        field: RequestField::Environment,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    fn valid_request() -> SandboxRequest {
        SandboxRequest {
            program: std::env::current_exe().expect("test executable path must be available"),
            arguments: Vec::new(),
            cwd: std::env::current_dir().expect("test working directory must be available"),
            environment: BTreeMap::new(),
            policy: SandboxPolicy::default(),
            timeout: None,
        }
    }

    #[test]
    fn req_005_empty_environment_name_is_rejected_without_echoing_data() {
        let mut request = valid_request();
        request
            .environment
            .insert(OsString::new(), OsString::from("secret-canary"));

        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::Empty,
            })
        );
    }

    #[test]
    fn req_005_reserved_and_malformed_environment_names_are_rejected() {
        for name in ["=C:", "A=B", "BAD\0NAME"] {
            let mut request = valid_request();
            request
                .environment
                .insert(OsString::from(name), OsString::from("value"));

            assert!(matches!(
                request.validate(),
                Err(SandboxError::InvalidRequest {
                    field: RequestField::Environment,
                    reason: InvalidRequestReason::InvalidCharacter
                        | InvalidRequestReason::ReservedName,
                })
            ));
        }
    }

    #[test]
    fn req_005_environment_value_with_nul_is_rejected() {
        let mut request = valid_request();
        request.environment.insert(
            OsString::from("BOLT_VALUE"),
            OsString::from("before\0after"),
        );

        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::InvalidCharacter,
            })
        );
    }

    #[test]
    fn req_005_ascii_case_colliding_environment_names_are_rejected() {
        let mut request = valid_request();
        request
            .environment
            .insert(OsString::from("Path"), OsString::from("first"));
        request
            .environment
            .insert(OsString::from("PATH"), OsString::from("second"));

        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::ConflictingNames,
            })
        );
    }

    #[test]
    fn req_005_unicode_case_colliding_environment_names_are_rejected() {
        let mut request = valid_request();
        request
            .environment
            .insert(OsString::from("BÖLT_KEY"), OsString::from("first"));
        request
            .environment
            .insert(OsString::from("bölt_key"), OsString::from("second"));

        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::ConflictingNames,
            })
        );
    }

    #[test]
    fn req_005_unpaired_utf16_in_environment_name_is_rejected() {
        let mut request = valid_request();
        request.environment.insert(
            OsString::from_wide(&[0xD800]),
            OsString::from("secret-canary"),
        );

        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::InvalidCharacter,
            })
        );
    }
}
