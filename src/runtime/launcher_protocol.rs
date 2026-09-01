use sha2::{Digest, Sha256};

const MAGIC: [u8; 4] = *b"BLS1";
const LAUNCHER_START_VERSION: u16 = 3;
const HEADER_LENGTH: usize = 116;
const DIGEST_OFFSET: usize = 84;
const DIGEST_LENGTH: usize = 32;
const FLAG_HAS_TIMEOUT: u32 = 1;
const FLAG_RECOVERY_ENABLED: u32 = 2;
const FLAG_PSEUDO_CONSOLE: u32 = 4;
const MAX_START_REQUEST_LENGTH: usize = 3 * 1_048_576;
const MAX_PATH_CODE_UNITS: usize = 32_767;
const MAX_COMMAND_CODE_UNITS: usize = 32_767;
const MAX_ENVIRONMENT_CODE_UNITS: usize = 524_288;
const MAX_POLICY_BYTES: usize = 1_048_620;

#[derive(Clone, Copy)]
pub(super) struct LauncherStartRequest<'a> {
    pub(super) program: &'a [u16],
    pub(super) cwd: &'a [u16],
    pub(super) command_line: &'a [u16],
    pub(super) environment_block: &'a [u16],
    pub(super) policy: &'a [u8],
    pub(super) hook_path: &'a [u16],
    pub(super) timeout_milliseconds: Option<u64>,
    pub(super) nonce: [u8; 16],
    pub(super) endpoint_identifier: [u8; 16],
    pub(super) recovery_enabled: bool,
    pub(super) pseudo_console_size: Option<crate::PseudoConsoleSize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LauncherProtocolError {
    InvalidLength,
    InvalidMagic,
    InvalidVersion,
    InvalidHeader,
    InvalidFlags,
    InvalidField,
    DigestMismatch,
    Allocation,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DecodedLauncherStartRequest<'a> {
    pub(super) program: Vec<u16>,
    pub(super) cwd: Vec<u16>,
    pub(super) command_line: Vec<u16>,
    pub(super) environment_block: Vec<u16>,
    pub(super) policy: &'a [u8],
    pub(super) hook_path: Vec<u16>,
    pub(super) timeout_milliseconds: Option<u64>,
    pub(super) nonce: [u8; 16],
    pub(super) endpoint_identifier: [u8; 16],
    pub(super) recovery_enabled: bool,
    pub(super) pseudo_console_size: Option<crate::PseudoConsoleSize>,
}

pub(super) fn encode_start_request(
    request: LauncherStartRequest<'_>,
) -> Result<Vec<u8>, LauncherProtocolError> {
    validate_fields(&request)?;
    let body_length = request
        .program
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(request.cwd.len().checked_mul(2)?))
        .and_then(|length| length.checked_add(request.command_line.len().checked_mul(2)?))
        .and_then(|length| length.checked_add(request.environment_block.len().checked_mul(2)?))
        .and_then(|length| length.checked_add(request.policy.len()))
        .and_then(|length| length.checked_add(request.hook_path.len().checked_mul(2)?))
        .ok_or(LauncherProtocolError::InvalidLength)?;
    let total_length = HEADER_LENGTH
        .checked_add(body_length)
        .filter(|length| *length <= MAX_START_REQUEST_LENGTH)
        .ok_or(LauncherProtocolError::InvalidLength)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total_length)
        .map_err(|_| LauncherProtocolError::Allocation)?;
    encoded.resize(HEADER_LENGTH, 0);
    encoded[..4].copy_from_slice(&MAGIC);
    write_u16(&mut encoded, 4, LAUNCHER_START_VERSION);
    write_u16(
        &mut encoded,
        6,
        u16::try_from(HEADER_LENGTH).map_err(|_| LauncherProtocolError::InvalidHeader)?,
    );
    write_u32(
        &mut encoded,
        8,
        u32::try_from(total_length).map_err(|_| LauncherProtocolError::InvalidLength)?,
    );
    for (offset, length) in [
        (12, request.program.len()),
        (16, request.cwd.len()),
        (20, request.command_line.len()),
        (24, request.environment_block.len()),
        (28, request.policy.len()),
        (32, request.hook_path.len()),
    ] {
        write_u32(
            &mut encoded,
            offset,
            u32::try_from(length).map_err(|_| LauncherProtocolError::InvalidLength)?,
        );
    }
    write_u64(&mut encoded, 36, request.timeout_milliseconds.unwrap_or(0));
    encoded[44..60].copy_from_slice(&request.nonce);
    write_u32(
        &mut encoded,
        60,
        (if request.timeout_milliseconds.is_some() {
            FLAG_HAS_TIMEOUT
        } else {
            0
        }) | (if request.recovery_enabled {
            FLAG_RECOVERY_ENABLED
        } else {
            0
        }) | (if request.pseudo_console_size.is_some() {
            FLAG_PSEUDO_CONSOLE
        } else {
            0
        }),
    );
    encoded[64..80].copy_from_slice(&request.endpoint_identifier);
    if let Some(size) = request.pseudo_console_size {
        write_u16(&mut encoded, 80, size.columns());
        write_u16(&mut encoded, 82, size.rows());
    }
    append_utf16(&mut encoded, request.program);
    append_utf16(&mut encoded, request.cwd);
    append_utf16(&mut encoded, request.command_line);
    append_utf16(&mut encoded, request.environment_block);
    encoded.extend_from_slice(request.policy);
    append_utf16(&mut encoded, request.hook_path);
    let digest = request_digest(&encoded);
    encoded[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_LENGTH].copy_from_slice(&digest);
    Ok(encoded)
}

pub(super) fn decode_start_request(
    encoded: &[u8],
) -> Result<DecodedLauncherStartRequest<'_>, LauncherProtocolError> {
    if encoded.len() < HEADER_LENGTH || encoded.len() > MAX_START_REQUEST_LENGTH {
        return Err(LauncherProtocolError::InvalidLength);
    }
    if encoded[..4] != MAGIC {
        return Err(LauncherProtocolError::InvalidMagic);
    }
    if read_u16(encoded, 4)? != LAUNCHER_START_VERSION {
        return Err(LauncherProtocolError::InvalidVersion);
    }
    if usize::from(read_u16(encoded, 6)?) != HEADER_LENGTH {
        return Err(LauncherProtocolError::InvalidHeader);
    }
    if usize::try_from(read_u32(encoded, 8)?) != Ok(encoded.len()) {
        return Err(LauncherProtocolError::InvalidLength);
    }
    let flags = read_u32(encoded, 60)?;
    if flags & !(FLAG_HAS_TIMEOUT | FLAG_RECOVERY_ENABLED | FLAG_PSEUDO_CONSOLE) != 0 {
        return Err(LauncherProtocolError::InvalidFlags);
    }
    if request_digest(encoded) != encoded[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_LENGTH] {
        return Err(LauncherProtocolError::DigestMismatch);
    }
    let read_length = |offset| {
        usize::try_from(read_u32(encoded, offset)?)
            .map_err(|_| LauncherProtocolError::InvalidLength)
    };
    let program_length = read_length(12)?;
    let cwd_length = read_length(16)?;
    let command_length = read_length(20)?;
    let environment_length = read_length(24)?;
    let policy_length = read_length(28)?;
    let hook_length = read_length(32)?;
    let timeout_value = read_u64(encoded, 36)?;
    let timeout_milliseconds = match (flags & FLAG_HAS_TIMEOUT != 0, timeout_value) {
        (false, 0) => None,
        (true, value @ 1..) => Some(value),
        _ => return Err(LauncherProtocolError::InvalidFlags),
    };
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&encoded[44..60]);
    let mut endpoint_identifier = [0_u8; 16];
    endpoint_identifier.copy_from_slice(&encoded[64..80]);
    let columns = read_u16(encoded, 80)?;
    let rows = read_u16(encoded, 82)?;
    let pseudo_console_size = match (flags & FLAG_PSEUDO_CONSOLE != 0, columns, rows) {
        (false, 0, 0) => None,
        (true, columns, rows) => crate::PseudoConsoleSize::new(columns, rows)
            .ok_or(LauncherProtocolError::InvalidField)
            .map(Some)?,
        _ => return Err(LauncherProtocolError::InvalidFlags),
    };
    if nonce.iter().all(|byte| *byte == 0) || endpoint_identifier.iter().all(|byte| *byte == 0) {
        return Err(LauncherProtocolError::InvalidField);
    }
    let mut offset = HEADER_LENGTH;
    let program = take_utf16(encoded, &mut offset, program_length)?;
    let cwd = take_utf16(encoded, &mut offset, cwd_length)?;
    let command_line = take_utf16(encoded, &mut offset, command_length)?;
    let environment_block = take_utf16(encoded, &mut offset, environment_length)?;
    let policy_end = offset
        .checked_add(policy_length)
        .filter(|end| *end <= encoded.len())
        .ok_or(LauncherProtocolError::InvalidLength)?;
    let policy = &encoded[offset..policy_end];
    offset = policy_end;
    let hook_path = take_utf16(encoded, &mut offset, hook_length)?;
    if offset != encoded.len() {
        return Err(LauncherProtocolError::InvalidLength);
    }
    let decoded = DecodedLauncherStartRequest {
        program,
        cwd,
        command_line,
        environment_block,
        policy,
        hook_path,
        timeout_milliseconds,
        nonce,
        endpoint_identifier,
        recovery_enabled: flags & FLAG_RECOVERY_ENABLED != 0,
        pseudo_console_size,
    };
    validate_decoded(&decoded)?;
    Ok(decoded)
}

fn validate_fields(request: &LauncherStartRequest<'_>) -> Result<(), LauncherProtocolError> {
    if request.program.is_empty()
        || request.program.len() > MAX_PATH_CODE_UNITS
        || request.cwd.is_empty()
        || request.cwd.len() > MAX_PATH_CODE_UNITS
        || request.hook_path.is_empty()
        || request.hook_path.len() > MAX_PATH_CODE_UNITS
        || request.command_line.is_empty()
        || request.command_line.len() > MAX_COMMAND_CODE_UNITS
        || request.environment_block.len() < 2
        || request.environment_block.len() > MAX_ENVIRONMENT_CODE_UNITS
        || request.policy.is_empty()
        || request.policy.len() > MAX_POLICY_BYTES
        || request.nonce.iter().all(|byte| *byte == 0)
        || request.endpoint_identifier.iter().all(|byte| *byte == 0)
        || request.timeout_milliseconds == Some(0)
        || contains_nul(request.program)
        || contains_nul(request.cwd)
        || contains_nul(request.hook_path)
        || request.command_line.last() != Some(&0)
        || request.command_line[..request.command_line.len() - 1].contains(&0)
        || !request.environment_block.ends_with(&[0, 0])
    {
        return Err(LauncherProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_decoded(
    request: &DecodedLauncherStartRequest<'_>,
) -> Result<(), LauncherProtocolError> {
    validate_fields(&LauncherStartRequest {
        program: &request.program,
        cwd: &request.cwd,
        command_line: &request.command_line,
        environment_block: &request.environment_block,
        policy: request.policy,
        hook_path: &request.hook_path,
        timeout_milliseconds: request.timeout_milliseconds,
        nonce: request.nonce,
        endpoint_identifier: request.endpoint_identifier,
        recovery_enabled: request.recovery_enabled,
        pseudo_console_size: request.pseudo_console_size,
    })
}

fn contains_nul(value: &[u16]) -> bool {
    value.contains(&0)
}

fn append_utf16(output: &mut Vec<u8>, value: &[u16]) {
    for code_unit in value {
        output.extend_from_slice(&code_unit.to_le_bytes());
    }
}

fn take_utf16(
    encoded: &[u8],
    offset: &mut usize,
    code_units: usize,
) -> Result<Vec<u16>, LauncherProtocolError> {
    let byte_length = code_units
        .checked_mul(2)
        .ok_or(LauncherProtocolError::InvalidLength)?;
    let end = offset
        .checked_add(byte_length)
        .filter(|end| *end <= encoded.len())
        .ok_or(LauncherProtocolError::InvalidLength)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(code_units)
        .map_err(|_| LauncherProtocolError::Allocation)?;
    for bytes in encoded[*offset..end].chunks_exact(2) {
        output.push(u16::from_le_bytes([bytes[0], bytes[1]]));
    }
    *offset = end;
    Ok(output)
}

fn request_digest(encoded: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&encoded[..DIGEST_OFFSET]);
    hasher.update(&encoded[HEADER_LENGTH..]);
    hasher.finalize().into()
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, LauncherProtocolError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(LauncherProtocolError::InvalidLength)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, LauncherProtocolError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(LauncherProtocolError::InvalidLength)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, LauncherProtocolError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(LauncherProtocolError::InvalidLength)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::assert_total_parser;

    fn request<'a>(
        program: &'a [u16],
        cwd: &'a [u16],
        command: &'a [u16],
        environment: &'a [u16],
        policy: &'a [u8],
        hook: &'a [u16],
    ) -> LauncherStartRequest<'a> {
        LauncherStartRequest {
            program,
            cwd,
            command_line: command,
            environment_block: environment,
            policy,
            hook_path: hook,
            timeout_milliseconds: Some(5_000),
            nonce: [0xA5; 16],
            endpoint_identifier: [0x3C; 16],
            recovery_enabled: true,
            pseudo_console_size: crate::PseudoConsoleSize::new(80, 24),
        }
    }

    #[test]
    fn launcher_start_request_round_trips_all_private_inputs() {
        let program: Vec<u16> = r"C:\tool.exe".encode_utf16().collect();
        let cwd: Vec<u16> = r"C:\work".encode_utf16().collect();
        let command: Vec<u16> = "\"C:\\tool.exe\" arg\0".encode_utf16().collect();
        let environment: Vec<u16> = "A=B\0\0".encode_utf16().collect();
        let hook: Vec<u16> = r"C:\bolt-sandbox-x64.dll".encode_utf16().collect();
        let policy = b"sealed-policy";

        let encoded = encode_start_request(request(
            &program,
            &cwd,
            &command,
            &environment,
            policy,
            &hook,
        ))
        .expect("valid launcher request must encode");
        let decoded = decode_start_request(&encoded).expect("encoded request must verify");

        assert_eq!(decoded.program, program);
        assert_eq!(decoded.cwd, cwd);
        assert_eq!(decoded.command_line, command);
        assert_eq!(decoded.environment_block, environment);
        assert_eq!(decoded.policy, policy);
        assert_eq!(decoded.hook_path, hook);
        assert_eq!(decoded.timeout_milliseconds, Some(5_000));
        assert_eq!(decoded.nonce, [0xA5; 16]);
        assert_eq!(decoded.endpoint_identifier, [0x3C; 16]);
        assert!(decoded.recovery_enabled);
        assert_eq!(
            decoded.pseudo_console_size,
            crate::PseudoConsoleSize::new(80, 24)
        );
    }

    #[test]
    fn launcher_start_request_rejects_tampering_and_noncanonical_flags() {
        let program: Vec<u16> = r"C:\tool.exe".encode_utf16().collect();
        let cwd: Vec<u16> = r"C:\work".encode_utf16().collect();
        let command: Vec<u16> = "tool\0".encode_utf16().collect();
        let environment: Vec<u16> = "\0\0".encode_utf16().collect();
        let hook: Vec<u16> = r"C:\hook.dll".encode_utf16().collect();
        let mut encoded = encode_start_request(request(
            &program,
            &cwd,
            &command,
            &environment,
            b"policy",
            &hook,
        ))
        .expect("valid launcher request must encode");

        encoded[HEADER_LENGTH] ^= 1;
        assert_eq!(
            decode_start_request(&encoded),
            Err(LauncherProtocolError::DigestMismatch)
        );
        encoded[HEADER_LENGTH] ^= 1;
        let digest = request_digest(&encoded);
        encoded[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_LENGTH].copy_from_slice(&digest);
        write_u32(&mut encoded, 60, 4);
        let digest = request_digest(&encoded);
        encoded[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_LENGTH].copy_from_slice(&digest);
        assert_eq!(
            decode_start_request(&encoded),
            Err(LauncherProtocolError::InvalidFlags)
        );
    }

    #[test]
    fn launcher_start_request_rejects_embedded_command_terminator() {
        let program: Vec<u16> = r"C:\tool.exe".encode_utf16().collect();
        let cwd: Vec<u16> = r"C:\work".encode_utf16().collect();
        let command: Vec<u16> = "tool\0hidden\0".encode_utf16().collect();
        let environment: Vec<u16> = "\0\0".encode_utf16().collect();
        let hook: Vec<u16> = r"C:\hook.dll".encode_utf16().collect();

        assert_eq!(
            encode_start_request(request(
                &program,
                &cwd,
                &command,
                &environment,
                b"policy",
                &hook,
            )),
            Err(LauncherProtocolError::InvalidField)
        );
    }

    #[test]
    fn ipc_023_launcher_v3_rejects_zero_endpoint_identity() {
        let program: Vec<u16> = r"C:\tool.exe".encode_utf16().collect();
        let cwd: Vec<u16> = r"C:\work".encode_utf16().collect();
        let command: Vec<u16> = "tool\0".encode_utf16().collect();
        let environment: Vec<u16> = "\0\0".encode_utf16().collect();
        let hook: Vec<u16> = r"C:\hook.dll".encode_utf16().collect();
        let mut request = request(&program, &cwd, &command, &environment, b"policy", &hook);
        request.endpoint_identifier = [0; 16];

        assert_eq!(
            encode_start_request(request),
            Err(LauncherProtocolError::InvalidField)
        );
    }

    #[test]
    fn fuzz_003_launcher_request_parser_is_total_for_bounded_mutations() {
        let program: Vec<u16> = r"C:\tool.exe".encode_utf16().collect();
        let cwd: Vec<u16> = r"C:\work".encode_utf16().collect();
        let command: Vec<u16> = "tool\0".encode_utf16().collect();
        let environment: Vec<u16> = "A=B\0\0".encode_utf16().collect();
        let hook: Vec<u16> = r"C:\hook.dll".encode_utf16().collect();
        let encoded = encode_start_request(request(
            &program,
            &cwd,
            &command,
            &environment,
            b"sealed-policy",
            &hook,
        ))
        .expect("valid launcher request must encode");

        assert_total_parser("launcher request", &[encoded], |bytes| {
            let _ = decode_start_request(bytes);
        });
    }
}
