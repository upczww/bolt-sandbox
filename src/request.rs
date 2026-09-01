use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{InvalidRequestReason, RequestField, SandboxError, SandboxPolicy, policy};

pub const MIN_TIMEOUT: Duration = Duration::from_millis(1);
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

const MAX_ARGUMENTS: usize = 4_096;
const MAX_ENVIRONMENT_VARIABLES: usize = 4_096;
const MAX_COMMAND_LINE_CODE_UNITS: usize = 32_767;
const MAX_ENVIRONMENT_ITEM_CODE_UNITS: usize = 32_767;
const MAX_ENVIRONMENT_BLOCK_CODE_UNITS: usize = 524_288;
const SPACE: u16 = 0x20;
const TAB: u16 = 0x09;
const QUOTE: u16 = 0x22;
const BACKSLASH: u16 = 0x5C;

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

        validate_arguments(&self.program, &self.arguments)?;

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
        validate_timeout(self.timeout)?;

        let _compiled_policy = policy::compiler::compile(&self.policy, &self.cwd)?;

        Ok(())
    }
}

fn validate_timeout(timeout: Option<Duration>) -> Result<(), SandboxError> {
    if timeout.is_some_and(|timeout| !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&timeout)) {
        return Err(SandboxError::InvalidRequest {
            field: RequestField::Timeout,
            reason: InvalidRequestReason::OutOfRange,
        });
    }
    Ok(())
}

fn validate_arguments(program: &Path, arguments: &[OsString]) -> Result<(), SandboxError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(invalid_arguments(InvalidRequestReason::TooManyItems));
    }
    if arguments.iter().any(|argument| contains_nul(argument)) {
        return Err(invalid_arguments(InvalidRequestReason::InvalidCharacter));
    }
    let _encoded = encode_command_line(program, arguments)?;
    Ok(())
}

fn validate_environment(environment: &BTreeMap<OsString, OsString>) -> Result<(), SandboxError> {
    if environment.len() > MAX_ENVIRONMENT_VARIABLES {
        return Err(invalid_environment(InvalidRequestReason::TooManyItems));
    }

    let mut normalized_names = BTreeSet::new();
    for (name, value) in environment {
        validate_environment_name(name)?;
        if contains_nul(value) {
            return Err(invalid_environment(InvalidRequestReason::InvalidCharacter));
        }
        if name.encode_wide().count() > MAX_ENVIRONMENT_ITEM_CODE_UNITS
            || value.encode_wide().count() > MAX_ENVIRONMENT_ITEM_CODE_UNITS
        {
            return Err(invalid_environment(InvalidRequestReason::TooLarge));
        }

        let normalized_name = normalize_environment_name(name)?;
        if !normalized_names.insert(normalized_name) {
            return Err(invalid_environment(InvalidRequestReason::ConflictingNames));
        }
    }
    let _encoded_length = encoded_environment_block_length(environment)?;
    Ok(())
}

pub(crate) fn encode_command_line(
    program: &Path,
    arguments: &[OsString],
) -> Result<Vec<u16>, SandboxError> {
    if contains_nul(program.as_os_str()) || arguments.iter().any(|value| contains_nul(value)) {
        return Err(invalid_arguments(InvalidRequestReason::InvalidCharacter));
    }

    let mut encoded_length = encoded_argument_length(program.as_os_str())
        .ok_or_else(|| invalid_arguments(InvalidRequestReason::TooLarge))?;
    for argument in arguments {
        encoded_length = encoded_length
            .checked_add(1)
            .and_then(|length| {
                encoded_argument_length(argument)
                    .and_then(|argument_length| length.checked_add(argument_length))
            })
            .ok_or_else(|| invalid_arguments(InvalidRequestReason::TooLarge))?;
    }
    encoded_length = encoded_length
        .checked_add(1)
        .ok_or_else(|| invalid_arguments(InvalidRequestReason::TooLarge))?;
    if encoded_length > MAX_COMMAND_LINE_CODE_UNITS {
        return Err(invalid_arguments(InvalidRequestReason::TooLarge));
    }

    let mut encoded = Vec::with_capacity(encoded_length);
    append_quoted_argument(&mut encoded, program.as_os_str());
    for argument in arguments {
        encoded.push(SPACE);
        append_quoted_argument(&mut encoded, argument);
    }
    encoded.push(0);
    debug_assert_eq!(encoded.len(), encoded_length);
    Ok(encoded)
}

fn encoded_argument_length(argument: &OsStr) -> Option<usize> {
    if !argument_needs_quotes(argument) {
        return Some(argument.encode_wide().count());
    }

    let mut length = 2_usize;
    let mut backslashes = 0_usize;
    for code_unit in argument.encode_wide() {
        match code_unit {
            BACKSLASH => backslashes = backslashes.checked_add(1)?,
            QUOTE => {
                length = length.checked_add(backslashes.checked_mul(2)?.checked_add(2)?)?;
                backslashes = 0;
            }
            _ => {
                length = length.checked_add(backslashes.checked_add(1)?)?;
                backslashes = 0;
            }
        }
    }
    length.checked_add(backslashes.checked_mul(2)?)
}

fn argument_needs_quotes(argument: &OsStr) -> bool {
    argument.is_empty()
        || argument
            .encode_wide()
            .any(|code_unit| matches!(code_unit, SPACE | TAB | QUOTE))
}

fn append_quoted_argument(encoded: &mut Vec<u16>, argument: &OsStr) {
    if !argument_needs_quotes(argument) {
        encoded.extend(argument.encode_wide());
        return;
    }

    encoded.push(QUOTE);
    let mut backslashes = 0_usize;
    for code_unit in argument.encode_wide() {
        match code_unit {
            BACKSLASH => backslashes += 1,
            QUOTE => {
                push_repeated(encoded, BACKSLASH, backslashes * 2 + 1);
                encoded.push(QUOTE);
                backslashes = 0;
            }
            _ => {
                push_repeated(encoded, BACKSLASH, backslashes);
                encoded.push(code_unit);
                backslashes = 0;
            }
        }
    }
    push_repeated(encoded, BACKSLASH, backslashes * 2);
    encoded.push(QUOTE);
}

fn push_repeated(encoded: &mut Vec<u16>, code_unit: u16, count: usize) {
    encoded.resize(encoded.len() + count, code_unit);
}

pub(crate) struct PreparedEnvironment {
    pub(crate) variables: BTreeMap<OsString, OsString>,
    pub(crate) diagnostic: EnvironmentSanitization,
}

pub(crate) struct EnvironmentSanitization {
    pub(crate) stripped_credentials: usize,
}

pub(crate) fn prepare_environment(
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

pub(crate) fn encode_environment_block(
    environment: &BTreeMap<OsString, OsString>,
) -> Result<Vec<u16>, SandboxError> {
    validate_environment(environment)?;

    let mut sorted = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        sorted.push((normalize_environment_name(name)?, name, value));
    }
    sorted.sort_by(|left, right| left.0.cmp(&right.0));

    let encoded_length = encoded_environment_block_length(environment)?;
    let mut encoded = Vec::with_capacity(encoded_length);
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
    debug_assert_eq!(encoded.len(), encoded_length);
    Ok(encoded)
}

fn encoded_environment_block_length(
    environment: &BTreeMap<OsString, OsString>,
) -> Result<usize, SandboxError> {
    if environment.is_empty() {
        return Ok(2);
    }

    let mut length = 1_usize;
    for (name, value) in environment {
        length = length
            .checked_add(name.encode_wide().count())
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(value.encode_wide().count()))
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| invalid_environment(InvalidRequestReason::TooLarge))?;
        if length > MAX_ENVIRONMENT_BLOCK_CODE_UNITS {
            return Err(invalid_environment(InvalidRequestReason::TooLarge));
        }
    }
    Ok(length)
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

const fn invalid_arguments(reason: InvalidRequestReason) -> SandboxError {
    SandboxError::InvalidRequest {
        field: RequestField::Arguments,
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

    #[test]
    fn req_012_argument_count_maximum_and_maximum_plus_one() {
        let mut request = valid_request();
        request.arguments = vec![OsString::new(); MAX_ARGUMENTS];
        assert_eq!(request.validate(), Ok(()));

        request.arguments.push(OsString::new());
        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Arguments,
                reason: InvalidRequestReason::TooManyItems,
            })
        );
    }

    #[test]
    fn req_012_environment_count_maximum_and_maximum_plus_one() {
        let mut request = valid_request();
        for index in 0..MAX_ENVIRONMENT_VARIABLES {
            request
                .environment
                .insert(OsString::from(format!("BOLT_{index:04}")), OsString::new());
        }
        assert_eq!(request.validate(), Ok(()));

        request
            .environment
            .insert(OsString::from("BOLT_OVER_LIMIT"), OsString::new());
        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::TooManyItems,
            })
        );
    }

    #[test]
    fn req_012_windows_command_line_maximum_and_maximum_plus_one() {
        let program = PathBuf::from(r"C:\p.exe");
        let fixed_code_units = program.as_os_str().encode_wide().count() + 2;
        let at_maximum = OsString::from("a".repeat(MAX_COMMAND_LINE_CODE_UNITS - fixed_code_units));

        assert_eq!(
            encode_command_line(&program, std::slice::from_ref(&at_maximum))
                .expect("maximum command line must encode")
                .len(),
            MAX_COMMAND_LINE_CODE_UNITS
        );
        assert_eq!(
            encode_command_line(
                &program,
                &[OsString::from(format!("{}a", at_maximum.to_string_lossy()))],
            ),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Arguments,
                reason: InvalidRequestReason::TooLarge,
            })
        );
    }

    #[test]
    fn req_004_windows_command_line_encoding_preserves_argument_boundaries() {
        let mut expected: Vec<u16> =
            r#""C:\Program Files\tool.exe" "" plain "space separated" "a\\\"b""#
                .encode_utf16()
                .collect();
        expected.push(0);

        assert_eq!(
            encode_command_line(
                &PathBuf::from(r"C:\Program Files\tool.exe"),
                &[
                    OsString::new(),
                    OsString::from("plain"),
                    OsString::from("space separated"),
                    OsString::from(r#"a\"b"#),
                ],
            ),
            Ok(expected)
        );
    }

    #[test]
    fn req_012_environment_item_maximum_and_maximum_plus_one() {
        let mut request = valid_request();
        request.environment.insert(
            OsString::from("BOLT_VALUE"),
            OsString::from("v".repeat(MAX_ENVIRONMENT_ITEM_CODE_UNITS)),
        );
        assert_eq!(request.validate(), Ok(()));

        request.environment.insert(
            OsString::from("BOLT_VALUE"),
            OsString::from("v".repeat(MAX_ENVIRONMENT_ITEM_CODE_UNITS + 1)),
        );
        assert_eq!(
            request.validate(),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::TooLarge,
            })
        );
    }

    #[test]
    fn req_012_environment_block_maximum_and_maximum_plus_one() {
        let mut environment = BTreeMap::new();
        let entry_overhead = 7;
        let full_value = MAX_ENVIRONMENT_ITEM_CODE_UNITS;
        let final_value =
            MAX_ENVIRONMENT_BLOCK_CODE_UNITS - 1 - (16 * entry_overhead) - (15 * full_value);
        for index in 0..15 {
            environment.insert(
                OsString::from(format!("K{index:04}")),
                OsString::from("v".repeat(full_value)),
            );
        }
        environment.insert(
            OsString::from("K0015"),
            OsString::from("v".repeat(final_value)),
        );

        assert_eq!(
            encode_environment_block(&environment)
                .expect("maximum environment block must encode")
                .len(),
            MAX_ENVIRONMENT_BLOCK_CODE_UNITS
        );
        environment.insert(
            OsString::from("K0015"),
            OsString::from("v".repeat(final_value + 1)),
        );
        assert_eq!(
            encode_environment_block(&environment),
            Err(SandboxError::InvalidRequest {
                field: RequestField::Environment,
                reason: InvalidRequestReason::TooLarge,
            })
        );
    }
}
