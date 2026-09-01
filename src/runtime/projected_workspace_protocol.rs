use std::{io::Read, os::windows::ffi::OsStrExt, path::Path};

use sha2::{Digest, Sha256};

const REQUEST_MAGIC: [u8; 4] = *b"BPJ1";
const READY_MAGIC: [u8; 4] = *b"BPY1";
const FINISHED_MAGIC: [u8; 4] = *b"BPF1";
const CONTROL_MAGIC: [u8; 4] = *b"BPC1";
const VERSION: u16 = 1;
const HEADER_LENGTH: usize = 80;
const DIGEST_OFFSET: usize = 48;
const RESPONSE_LENGTH: usize = 12;
const MAXIMUM_REQUEST_LENGTH: usize = 256 * 1_024;
const MAXIMUM_PATH_CODE_UNITS: usize = 32_767;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProjectedWorkspaceResponseKind {
    Ready,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProjectedWorkspaceResult {
    Success,
    Unavailable,
    InvalidRoot,
    UnsupportedObject,
    QuotaExceeded,
    SecurityFailure,
    Io,
    Conflict,
    ProtocolError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProjectedWorkspaceControl {
    Materialize = 1,
    Discard = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProjectedWorkspaceProtocolError {
    InvalidField,
    InvalidLength,
    InvalidResponse,
    Io,
}

pub(super) fn encode_request(
    source_root: &Path,
    projection_root: &Path,
    maximum_items: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ProjectedWorkspaceProtocolError> {
    let source = encode_path(source_root)?;
    let projection = encode_path(projection_root)?;
    if maximum_items == 0 || maximum_bytes == 0 {
        return Err(ProjectedWorkspaceProtocolError::InvalidField);
    }
    let body_length = source
        .len()
        .checked_add(projection.len())
        .and_then(|length| length.checked_mul(2))
        .ok_or(ProjectedWorkspaceProtocolError::InvalidLength)?;
    let total_length = HEADER_LENGTH
        .checked_add(body_length)
        .filter(|length| *length <= MAXIMUM_REQUEST_LENGTH)
        .ok_or(ProjectedWorkspaceProtocolError::InvalidLength)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total_length)
        .map_err(|_| ProjectedWorkspaceProtocolError::InvalidLength)?;
    encoded.resize(HEADER_LENGTH, 0);
    encoded[..4].copy_from_slice(&REQUEST_MAGIC);
    encoded[4..6].copy_from_slice(&VERSION.to_le_bytes());
    encoded[6..8].copy_from_slice(
        &u16::try_from(HEADER_LENGTH)
            .map_err(|_| ProjectedWorkspaceProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    encoded[8..12].copy_from_slice(
        &u32::try_from(total_length)
            .map_err(|_| ProjectedWorkspaceProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    encoded[12..16].copy_from_slice(
        &u32::try_from(source.len())
            .map_err(|_| ProjectedWorkspaceProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    encoded[16..20].copy_from_slice(
        &u32::try_from(projection.len())
            .map_err(|_| ProjectedWorkspaceProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    encoded[20..24].copy_from_slice(&maximum_items.to_le_bytes());
    encoded[24..32].copy_from_slice(&maximum_bytes.to_le_bytes());
    append_utf16(&mut encoded, &source);
    append_utf16(&mut encoded, &projection);
    let digest = request_digest(&encoded);
    encoded[DIGEST_OFFSET..HEADER_LENGTH].copy_from_slice(&digest);
    Ok(encoded)
}

pub(super) fn decode_response(
    reader: &mut impl Read,
    expected_kind: ProjectedWorkspaceResponseKind,
) -> Result<ProjectedWorkspaceResult, ProjectedWorkspaceProtocolError> {
    let mut encoded = [0_u8; RESPONSE_LENGTH];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| ProjectedWorkspaceProtocolError::Io)?;
    let expected_magic = match expected_kind {
        ProjectedWorkspaceResponseKind::Ready => READY_MAGIC,
        ProjectedWorkspaceResponseKind::Finished => FINISHED_MAGIC,
    };
    if encoded[..4] != expected_magic
        || u16::from_le_bytes([encoded[4], encoded[5]]) != VERSION
        || usize::from(u16::from_le_bytes([encoded[6], encoded[7]])) != RESPONSE_LENGTH
    {
        return Err(ProjectedWorkspaceProtocolError::InvalidResponse);
    }
    match u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]) {
        0 => Ok(ProjectedWorkspaceResult::Success),
        1 => Ok(ProjectedWorkspaceResult::Unavailable),
        2 => Ok(ProjectedWorkspaceResult::InvalidRoot),
        3 => Ok(ProjectedWorkspaceResult::UnsupportedObject),
        4 => Ok(ProjectedWorkspaceResult::QuotaExceeded),
        5 => Ok(ProjectedWorkspaceResult::SecurityFailure),
        6 => Ok(ProjectedWorkspaceResult::Io),
        7 => Ok(ProjectedWorkspaceResult::Conflict),
        8 => Ok(ProjectedWorkspaceResult::ProtocolError),
        _ => Err(ProjectedWorkspaceProtocolError::InvalidResponse),
    }
}

pub(super) fn encode_control(control: ProjectedWorkspaceControl) -> [u8; 8] {
    let mut encoded = [0_u8; 8];
    encoded[..4].copy_from_slice(&CONTROL_MAGIC);
    encoded[4..6].copy_from_slice(&VERSION.to_le_bytes());
    encoded[6..8].copy_from_slice(&(control as u16).to_le_bytes());
    encoded
}

fn encode_path(path: &Path) -> Result<Vec<u16>, ProjectedWorkspaceProtocolError> {
    if !path.is_absolute() {
        return Err(ProjectedWorkspaceProtocolError::InvalidField);
    }
    let encoded: Vec<_> = path.as_os_str().encode_wide().collect();
    if encoded.is_empty() || encoded.len() > MAXIMUM_PATH_CODE_UNITS || encoded.contains(&0) {
        return Err(ProjectedWorkspaceProtocolError::InvalidField);
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
    fn ws_004_projected_workspace_protocol_matches_native_vectors() {
        let encoded = encode_request(
            Path::new(r"C:\source"),
            Path::new(r"C:\projection"),
            100,
            1_048_576,
        )
        .expect("valid projected request must encode");
        assert_eq!(&encoded[..4], b"BPJ1");
        assert_eq!(u16::from_le_bytes([encoded[4], encoded[5]]), 1);
        assert_eq!(u16::from_le_bytes([encoded[6], encoded[7]]), 80);

        assert_eq!(
            decode_response(
                &mut Cursor::new(b"BPY1\x01\x00\x0c\x00\x01\x00\x00\x00"),
                ProjectedWorkspaceResponseKind::Ready,
            ),
            Ok(ProjectedWorkspaceResult::Unavailable)
        );
        assert_eq!(
            encode_control(ProjectedWorkspaceControl::Materialize),
            *b"BPC1\x01\x00\x01\x00"
        );
    }
}
