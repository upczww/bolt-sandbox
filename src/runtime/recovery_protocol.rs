use std::{io, io::Write, os::windows::ffi::OsStringExt, path::PathBuf};

const REQUEST_MAGIC: [u8; 4] = *b"BRQ1";
const RESPONSE_MAGIC: [u8; 4] = *b"BRP1";
const VERSION: u16 = 1;
const REQUEST_HEADER_LENGTH: usize = 32;
const RESPONSE_LENGTH: usize = 40;
const RESPONSE_LENGTH_U16: u16 = 40;
const RESPONSE_LENGTH_U32: u32 = 40;
const MAX_PATH_CODE_UNITS: usize = 32_767;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryOperation {
    Delete = 1,
    Truncate = 2,
    Replace = 3,
    Rename = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveryRequest {
    pub(super) request_id: u64,
    pub(super) process_id: u32,
    pub(super) operation: RecoveryOperation,
    pub(super) path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryProtocolError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidHeader,
    InvalidRequest,
    InvalidPath,
}

pub(super) fn decode_request(encoded: &[u8]) -> Result<RecoveryRequest, RecoveryProtocolError> {
    if encoded.len() < REQUEST_HEADER_LENGTH {
        return Err(RecoveryProtocolError::InvalidLength);
    }
    if encoded[..4] != REQUEST_MAGIC {
        return Err(RecoveryProtocolError::InvalidMagic);
    }
    if read_u16(encoded, 4) != VERSION {
        return Err(RecoveryProtocolError::UnsupportedVersion);
    }
    if usize::from(read_u16(encoded, 6)) != REQUEST_HEADER_LENGTH {
        return Err(RecoveryProtocolError::InvalidHeader);
    }
    if usize::try_from(read_u32(encoded, 8)) != Ok(encoded.len()) {
        return Err(RecoveryProtocolError::InvalidLength);
    }
    let path_length =
        usize::try_from(read_u32(encoded, 12)).map_err(|_| RecoveryProtocolError::InvalidLength)?;
    if path_length == 0 || path_length > MAX_PATH_CODE_UNITS {
        return Err(RecoveryProtocolError::InvalidPath);
    }
    let request_id = read_u64(encoded, 16);
    let process_id = read_u32(encoded, 24);
    let operation = match encoded[28] {
        1 => RecoveryOperation::Delete,
        2 => RecoveryOperation::Truncate,
        3 => RecoveryOperation::Replace,
        4 => RecoveryOperation::Rename,
        _ => return Err(RecoveryProtocolError::InvalidRequest),
    };
    if request_id == 0 || process_id == 0 || encoded[29..32] != [0; 3] {
        return Err(RecoveryProtocolError::InvalidRequest);
    }
    let expected_length = REQUEST_HEADER_LENGTH
        .checked_add(
            path_length
                .checked_mul(2)
                .ok_or(RecoveryProtocolError::InvalidLength)?,
        )
        .ok_or(RecoveryProtocolError::InvalidLength)?;
    if encoded.len() != expected_length {
        return Err(RecoveryProtocolError::InvalidLength);
    }
    let mut path = Vec::with_capacity(path_length);
    for bytes in encoded[REQUEST_HEADER_LENGTH..].chunks_exact(2) {
        path.push(u16::from_le_bytes([bytes[0], bytes[1]]));
    }
    if path.contains(&0) {
        return Err(RecoveryProtocolError::InvalidPath);
    }
    Ok(RecoveryRequest {
        request_id,
        process_id,
        operation,
        path: PathBuf::from(std::ffi::OsString::from_wide(&path)),
    })
}

pub(super) fn write_response(
    writer: &mut impl Write,
    request_id: u64,
    artifact_id: Option<u64>,
    byte_count: u64,
) -> io::Result<()> {
    let mut encoded = [0_u8; RESPONSE_LENGTH];
    encoded[..4].copy_from_slice(&RESPONSE_MAGIC);
    encoded[4..6].copy_from_slice(&VERSION.to_le_bytes());
    encoded[6..8].copy_from_slice(&RESPONSE_LENGTH_U16.to_le_bytes());
    encoded[8..12].copy_from_slice(&RESPONSE_LENGTH_U32.to_le_bytes());
    encoded[12..20].copy_from_slice(&request_id.to_le_bytes());
    encoded[20] = u8::from(artifact_id.is_none());
    encoded[24..32].copy_from_slice(&artifact_id.unwrap_or(0).to_le_bytes());
    encoded[32..40].copy_from_slice(&byte_count.to_le_bytes());
    writer.write_all(&encoded)?;
    writer.flush()
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("bounded field"))
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("bounded field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::assert_total_parser;

    fn valid_request() -> Vec<u8> {
        let path: Vec<u16> = r"C:\work\delete.bin".encode_utf16().collect();
        let mut request = Vec::from(REQUEST_MAGIC);
        request.extend_from_slice(&VERSION.to_le_bytes());
        request.extend_from_slice(&(REQUEST_HEADER_LENGTH as u16).to_le_bytes());
        request.extend_from_slice(&(REQUEST_HEADER_LENGTH as u32 + path.len() as u32 * 2).to_le_bytes());
        request.extend_from_slice(&(path.len() as u32).to_le_bytes());
        request.extend_from_slice(&7_u64.to_le_bytes());
        request.extend_from_slice(&42_u32.to_le_bytes());
        request.extend_from_slice(&[RecoveryOperation::Delete as u8, 0, 0, 0]);
        for unit in path {
            request.extend_from_slice(&unit.to_le_bytes());
        }
        request
    }

    #[test]
    fn recovery_request_decodes_and_response_has_stable_shape() {
        let path: Vec<u16> = r"C:\work\delete.bin".encode_utf16().collect();
        let mut request = Vec::from(REQUEST_MAGIC);
        request.extend_from_slice(&VERSION.to_le_bytes());
        request.extend_from_slice(
            &u16::try_from(REQUEST_HEADER_LENGTH)
                .expect("header length fits")
                .to_le_bytes(),
        );
        request.extend_from_slice(
            &u32::try_from(REQUEST_HEADER_LENGTH + path.len() * 2)
                .expect("fixture length fits")
                .to_le_bytes(),
        );
        request.extend_from_slice(
            &u32::try_from(path.len())
                .expect("path length fits")
                .to_le_bytes(),
        );
        request.extend_from_slice(&7_u64.to_le_bytes());
        request.extend_from_slice(&42_u32.to_le_bytes());
        request.extend_from_slice(&[RecoveryOperation::Delete as u8, 0, 0, 0]);
        for unit in path {
            request.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode_request(&request).expect("request must decode");
        assert_eq!(decoded.request_id, 7);
        assert_eq!(decoded.process_id, 42);
        assert_eq!(decoded.operation, RecoveryOperation::Delete);

        let mut response = Vec::new();
        write_response(&mut response, 7, Some(9), 123).expect("response must encode");
        assert_eq!(response.len(), RESPONSE_LENGTH);
        assert_eq!(&response[..4], b"BRP1");
        assert_eq!(response[20], 0);
        assert_eq!(&response[24..32], &9_u64.to_le_bytes());
        assert_eq!(&response[32..40], &123_u64.to_le_bytes());
    }

    #[test]
    fn fuzz_005_recovery_request_parser_is_total_for_bounded_mutations() {
        assert_total_parser("recovery request", &[valid_request()], decode_request);
    }
}
