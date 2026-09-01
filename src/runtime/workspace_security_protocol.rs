use std::{io::Read, os::windows::ffi::OsStrExt, path::Path};

use sha2::{Digest, Sha256};

const REQUEST_MAGIC: [u8; 4] = *b"BWS1";
const RESPONSE_MAGIC: [u8; 4] = *b"BWR1";
const VERSION: u16 = 1;
const HEADER_LENGTH: usize = 64;
const RESPONSE_LENGTH: usize = 12;
const DIGEST_OFFSET: usize = 32;
const MAXIMUM_REQUEST_LENGTH: usize = 256 * 1_024;
const MAXIMUM_PATH_CODE_UNITS: usize = 32_767;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceSecurityOperation {
    Copy = 1,
    Verify = 2,
    CopyRoot = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceSecurityResult {
    Success,
    InvalidRoot,
    UnsupportedObject,
    QuotaExceeded,
    SecurityQueryFailed,
    SecurityApplyFailed,
    Mismatch,
    ProtocolError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkspaceSecurityProtocolError {
    InvalidField,
    InvalidLength,
    InvalidResponse,
    Io,
}

pub(super) fn encode_request(
    operation: WorkspaceSecurityOperation,
    source_root: &Path,
    destination_root: &Path,
    maximum_items: u32,
) -> Result<Vec<u8>, WorkspaceSecurityProtocolError> {
    let source = encode_path(source_root)?;
    let destination = encode_path(destination_root)?;
    if maximum_items == 0 {
        return Err(WorkspaceSecurityProtocolError::InvalidField);
    }
    let body_length = source
        .len()
        .checked_add(destination.len())
        .and_then(|length| length.checked_mul(2))
        .ok_or(WorkspaceSecurityProtocolError::InvalidLength)?;
    let total_length = HEADER_LENGTH
        .checked_add(body_length)
        .filter(|length| *length <= MAXIMUM_REQUEST_LENGTH)
        .ok_or(WorkspaceSecurityProtocolError::InvalidLength)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total_length)
        .map_err(|_| WorkspaceSecurityProtocolError::InvalidLength)?;
    encoded.resize(HEADER_LENGTH, 0);
    encoded[..4].copy_from_slice(&REQUEST_MAGIC);
    encoded[4..6].copy_from_slice(&VERSION.to_le_bytes());
    encoded[6..8].copy_from_slice(
        &u16::try_from(HEADER_LENGTH)
            .map_err(|_| WorkspaceSecurityProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    encoded[8..12].copy_from_slice(
        &u32::try_from(total_length)
            .map_err(|_| WorkspaceSecurityProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    encoded[12..14].copy_from_slice(&(operation as u16).to_le_bytes());
    encoded[16..20].copy_from_slice(&maximum_items.to_le_bytes());
    encoded[20..24].copy_from_slice(
        &u32::try_from(source.len())
            .map_err(|_| WorkspaceSecurityProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    encoded[24..28].copy_from_slice(
        &u32::try_from(destination.len())
            .map_err(|_| WorkspaceSecurityProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    append_utf16(&mut encoded, &source);
    append_utf16(&mut encoded, &destination);
    let digest = request_digest(&encoded);
    encoded[DIGEST_OFFSET..HEADER_LENGTH].copy_from_slice(&digest);
    Ok(encoded)
}

pub(super) fn decode_response(
    reader: &mut impl Read,
) -> Result<WorkspaceSecurityResult, WorkspaceSecurityProtocolError> {
    let mut encoded = [0_u8; RESPONSE_LENGTH];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| WorkspaceSecurityProtocolError::Io)?;
    if encoded[..4] != RESPONSE_MAGIC
        || u16::from_le_bytes([encoded[4], encoded[5]]) != VERSION
        || usize::from(u16::from_le_bytes([encoded[6], encoded[7]])) != RESPONSE_LENGTH
    {
        return Err(WorkspaceSecurityProtocolError::InvalidResponse);
    }
    match u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]) {
        0 => Ok(WorkspaceSecurityResult::Success),
        1 => Ok(WorkspaceSecurityResult::InvalidRoot),
        2 => Ok(WorkspaceSecurityResult::UnsupportedObject),
        3 => Ok(WorkspaceSecurityResult::QuotaExceeded),
        4 => Ok(WorkspaceSecurityResult::SecurityQueryFailed),
        5 => Ok(WorkspaceSecurityResult::SecurityApplyFailed),
        6 => Ok(WorkspaceSecurityResult::Mismatch),
        7 => Ok(WorkspaceSecurityResult::ProtocolError),
        _ => Err(WorkspaceSecurityProtocolError::InvalidResponse),
    }
}

fn encode_path(path: &Path) -> Result<Vec<u16>, WorkspaceSecurityProtocolError> {
    if !path.is_absolute() {
        return Err(WorkspaceSecurityProtocolError::InvalidField);
    }
    let encoded: Vec<_> = path.as_os_str().encode_wide().collect();
    if encoded.is_empty() || encoded.len() > MAXIMUM_PATH_CODE_UNITS || encoded.contains(&0) {
        return Err(WorkspaceSecurityProtocolError::InvalidField);
    }
    Ok(encoded)
}

fn append_utf16(output: &mut Vec<u8>, value: &[u16]) {
    for code_unit in value {
        output.extend_from_slice(&code_unit.to_le_bytes());
    }
}

fn request_digest(encoded: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(&encoded[..DIGEST_OFFSET]);
    digest.update(&encoded[HEADER_LENGTH..]);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use super::*;

    #[test]
    fn ws_023_workspace_security_request_and_response_match_native_vectors() {
        let encoded = encode_request(
            WorkspaceSecurityOperation::Copy,
            Path::new(r"C:\work\source"),
            Path::new(r"C:\work\staged"),
            100,
        )
        .expect("valid request must encode");
        assert_eq!(&encoded[..4], b"BWS1");
        assert_eq!(u16::from_le_bytes([encoded[4], encoded[5]]), 1);
        assert_eq!(u16::from_le_bytes([encoded[6], encoded[7]]), 64);

        let response = b"BWR1\x01\x00\x0c\x00\x06\x00\x00\x00";
        assert_eq!(
            decode_response(&mut Cursor::new(response)),
            Ok(WorkspaceSecurityResult::Mismatch)
        );
    }

    #[test]
    fn ws_023_workspace_security_protocol_rejects_invalid_bounds_and_response() {
        assert_eq!(
            encode_request(
                WorkspaceSecurityOperation::Verify,
                Path::new(r"C:\work\source"),
                Path::new(r"C:\work\staged"),
                0,
            ),
            Err(WorkspaceSecurityProtocolError::InvalidField)
        );
        assert_eq!(
            decode_response(&mut Cursor::new(b"bad-response")),
            Err(WorkspaceSecurityProtocolError::InvalidResponse)
        );
    }
}
