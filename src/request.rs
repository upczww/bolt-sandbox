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

        validate_arguments(&self.arguments)?;

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

fn validate_arguments(arguments: &[OsString]) -> Result<(), SandboxError> {
    if arguments.iter().any(|argument| contains_nul(argument)) {
        return Err(SandboxError::InvalidRequest {
            field: RequestField::Arguments,
            reason: InvalidRequestReason::InvalidCharacter,
        });
    }
    Ok(())
}

fn validate_environment(environment: &BTreeMap<OsString, OsString>) -> Result<(), SandboxError> {
    let mut normalized_names = BTreeSet::new();
    for (name, value) in environment {
        validate_environment_name(name)?;
        if contains_nul(value) {
            return Err(invalid_environment(InvalidRequestReason::InvalidCharacter));
        }

        let normalized_name = normalize_environment_name(name)?;
        if !normalized_names.insert(normalized_name) {
            return Err(invalid_environment(InvalidRequestReason::ConflictingNames));
        }
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "prepared environment is consumed by the process runtime in the next phase"
)]
struct PreparedEnvironment {
    variables: BTreeMap<OsString, OsString>,
    diagnostic: EnvironmentSanitization,
}

#[allow(
    dead_code,
    reason = "sanitization diagnostics are emitted by the process runtime in the next phase"
)]
struct EnvironmentSanitization {
    stripped_credentials: usize,
}

#[allow(
    dead_code,
    reason = "environment preparation is wired into child creation in the next phase"
)]
fn prepare_environment(
    environment: &BTreeMap<OsString, OsString>,
    credential_names: &[OsString],
) -> Result<PreparedEnvironment, SandboxError> {
    validate_environment(environment)?;

    let mut protected_names = BTreeSet::new();
    for name in credential_names {
        validate_environment_name(name)?;
        protected_names.insert(normalize_environment_name(name)?);
    }

    let mut variables = BTreeMap::new();
    for (name, value) in environment {
        if !protected_names.contains(&normalize_environment_name(name)?) {
            variables.insert(name.clone(), value.clone());
        }
    }

    let stripped_credentials = environment.len() - variables.len();
    Ok(PreparedEnvironment {
        variables,
        diagnostic: EnvironmentSanitization {
            stripped_credentials,
        },
    })
}

#[allow(
    dead_code,
    reason = "encoded environment block is passed to CreateProcessW in the runtime phase"
)]
fn encode_environment_block(
    environment: &BTreeMap<OsString, OsString>,
) -> Result<Vec<u16>, SandboxError> {
    validate_environment(environment)?;

    let mut sorted = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        sorted.push((normalize_environment_name(name)?, name, value));
    }
    sorted.sort_by(|left, right| left.0.cmp(&right.0));

    let mut encoded = Vec::new();
    for (_, name, value) in sorted {
        encoded.extend(name.encode_wide());
        encoded.push(u16::from(b'='));
        encoded.extend(value.encode_wide());
        encoded.push(0);
    }
    if encoded.is_empty() {
        encoded.push(0);
    }
    encoded.push(0);
    Ok(encoded)
}

fn validate_environment_name(name: &OsStr) -> Result<(), SandboxError> {
    if name.is_empty() {
        return Err(invalid_environment(InvalidRequestReason::Empty));
    }
    if contains_nul(name) {
        return Err(invalid_environment(InvalidRequestReason::InvalidCharacter));
    }
    if name.encode_wide().next() == Some(u16::from(b'=')) {
        return Err(invalid_environment(InvalidRequestReason::ReservedName));
    }
    if name
        .encode_wide()
        .any(|code_unit| code_unit == u16::from(b'='))
    {
        return Err(invalid_environment(InvalidRequestReason::InvalidCharacter));
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

    #[test]
    fn req_006_configured_credentials_are_stripped_case_insensitively() {
        let mut request = valid_request();
        request.environment.insert(
            OsString::from("OpenAI_Api_Key"),
            OsString::from("secret-canary"),
        );
        request.environment.insert(
            OsString::from("BOLT_SAFE_VALUE"),
            OsString::from("preserved exactly"),
        );

        let prepared =
            prepare_environment(&request.environment, &[OsString::from("OPENAI_API_KEY")])
                .expect("valid environment must prepare");

        assert_eq!(prepared.variables.len(), 1);
        assert_eq!(
            prepared.variables.get(&OsString::from("BOLT_SAFE_VALUE")),
            Some(&OsString::from("preserved exactly"))
        );
        assert_eq!(prepared.diagnostic.stripped_credentials, 1);
        assert!(
            request
                .environment
                .contains_key(&OsString::from("OpenAI_Api_Key"))
        );
    }

    #[test]
    fn req_006_unicode_credential_name_matching_uses_environment_semantics() {
        let mut request = valid_request();
        request.environment.insert(
            OsString::from("BÖLT_MODEL_TOKEN"),
            OsString::from("secret-canary"),
        );

        let prepared =
            prepare_environment(&request.environment, &[OsString::from("bölt_model_token")])
                .expect("valid environment must prepare");

        assert!(prepared.variables.is_empty());
        assert_eq!(prepared.diagnostic.stripped_credentials, 1);
    }

    #[test]
    fn req_006_invalid_configured_credential_name_fails_closed() {
        let request = valid_request();

        assert!(matches!(
            prepare_environment(
                &request.environment,
                &[OsString::from("INVALID\0CREDENTIAL")],
            ),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::InvalidCharacter,
            })
        ));
    }

    #[test]
    fn req_005_prepared_environment_encodes_as_sorted_unicode_block() {
        let environment = BTreeMap::from([
            (OsString::from("z_key"), OsString::from("last")),
            (OsString::from("Alpha"), OsString::from("一")),
            (OsString::from("b_key"), OsString::new()),
        ]);
        let prepared =
            prepare_environment(&environment, &[]).expect("valid environment must prepare");

        let encoded = encode_environment_block(&prepared.variables)
            .expect("prepared environment must encode");
        let expected: Vec<u16> = "Alpha=一\0b_key=\0z_key=last\0\0".encode_utf16().collect();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn req_005_empty_environment_encodes_with_double_terminator() {
        assert_eq!(encode_environment_block(&BTreeMap::new()), Ok(vec![0, 0]));
    }

    #[test]
    fn req_004_representable_arguments_validate_without_mutation() {
        let mut request = valid_request();
        request.arguments = vec![
            OsString::new(),
            OsString::from("space separated"),
            OsString::from("\"quoted\""),
            OsString::from("Unicode-参数"),
            OsString::from("trailing\\"),
        ];
        let expected = request.arguments.clone();

        assert_eq!(request.validate(), Ok(()));
        assert_eq!(request.arguments, expected);
    }

    #[test]
    fn req_004_argument_with_nul_is_rejected_without_echoing_data() {
        let mut request = valid_request();
        request.arguments = vec![OsString::from("before\0secret-canary")];

        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Arguments,
                reason: InvalidRequestReason::InvalidCharacter,
            })
        );
    }

    #[test]
    fn req_007_none_and_inclusive_timeout_boundaries_are_accepted() {
        for timeout in [None, Some(MIN_TIMEOUT), Some(MAX_TIMEOUT)] {
            let mut request = valid_request();
            request.timeout = timeout;

            assert_eq!(request.validate(), Ok(()));
        }
    }

    #[test]
    fn req_007_zero_and_over_maximum_timeout_are_rejected() {
        for timeout in [
            Duration::ZERO,
            MAX_TIMEOUT + Duration::from_nanos(1),
            Duration::MAX,
        ] {
            let mut request = valid_request();
            request.timeout = Some(timeout);

            assert_eq!(
                request.validate(),
                Err(SandboxError::InvalidRequest {
                    field: RequestField::Timeout,
                    reason: InvalidRequestReason::OutOfRange,
                })
            );
        }
    }
}
