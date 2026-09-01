use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use sha2::{Digest, Sha256};

pub(super) const MANIFEST_NAME: &str = "bolt-sandbox-components.manifest";
const MAGIC: [u8; 4] = *b"BCM1";
const VERSION: u16 = 1;
const HEADER_LENGTH: usize = 16;
const RECORD_HEADER_LENGTH: usize = 44;
const MAX_MANIFEST_LENGTH: u64 = 64 * 1_024;
const MAX_RECORDS: usize = 16;
const MAX_NAME_LENGTH: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ComponentRecord {
    pub(super) length: u64,
    pub(super) digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ManifestError {
    Open,
    Read,
    Invalid,
    LengthMismatch,
    HashMismatch,
    DigestMismatch,
}

pub(super) fn read_manifest(
    root: &Path,
    expected_digest: Option<&[u8; 32]>,
) -> Result<BTreeMap<String, ComponentRecord>, ManifestError> {
    let mut file = File::open(root.join(MANIFEST_NAME)).map_err(|_| ManifestError::Open)?;
    let length = file.metadata().map_err(|_| ManifestError::Read)?.len();
    if length < HEADER_LENGTH as u64 || length > MAX_MANIFEST_LENGTH {
        return Err(ManifestError::Invalid);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(usize::try_from(length).map_err(|_| ManifestError::Invalid)?)
        .map_err(|_| ManifestError::Read)?;
    file.read_to_end(&mut encoded)
        .map_err(|_| ManifestError::Read)?;
    if expected_digest.is_some_and(|expected| {
        let actual: [u8; 32] = Sha256::digest(&encoded).into();
        actual != *expected
    }) {
        return Err(ManifestError::DigestMismatch);
    }
    parse_manifest(&encoded)
}

fn parse_manifest(encoded: &[u8]) -> Result<BTreeMap<String, ComponentRecord>, ManifestError> {
    if encoded.len() < HEADER_LENGTH
        || encoded[..4] != MAGIC
        || read_u16(encoded, 4)? != VERSION
        || usize::from(read_u16(encoded, 6)?) != HEADER_LENGTH
        || read_u16(encoded, 10)? != crate::ipc::framing::PROTOCOL_VERSION
        || encoded[12..16] != [0; 4]
    {
        return Err(ManifestError::Invalid);
    }
    let count = usize::from(read_u16(encoded, 8)?);
    if count == 0 || count > MAX_RECORDS {
        return Err(ManifestError::Invalid);
    }
    let mut offset = HEADER_LENGTH;
    let mut records = BTreeMap::new();
    for _ in 0..count {
        let header_end = offset
            .checked_add(RECORD_HEADER_LENGTH)
            .filter(|end| *end <= encoded.len())
            .ok_or(ManifestError::Invalid)?;
        let name_length = usize::from(read_u16(encoded, offset)?);
        if name_length == 0 || name_length > MAX_NAME_LENGTH || read_u16(encoded, offset + 2)? != 0
        {
            return Err(ManifestError::Invalid);
        }
        let length = read_u64(encoded, offset + 4)?;
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&encoded[offset + 12..header_end]);
        let name_end = header_end
            .checked_add(name_length)
            .filter(|end| *end <= encoded.len())
            .ok_or(ManifestError::Invalid)?;
        let name = std::str::from_utf8(&encoded[header_end..name_end])
            .map_err(|_| ManifestError::Invalid)?;
        if !name.is_ascii()
            || name.contains(['/', '\\', '\0'])
            || records
                .insert(name.to_owned(), ComponentRecord { length, digest })
                .is_some()
        {
            return Err(ManifestError::Invalid);
        }
        offset = name_end;
    }
    if offset != encoded.len() {
        return Err(ManifestError::Invalid);
    }
    Ok(records)
}

pub(super) fn verify_component(
    file: &mut File,
    record: &ComponentRecord,
) -> Result<(), ManifestError> {
    if file.metadata().map_err(|_| ManifestError::Read)?.len() != record.length {
        return Err(ManifestError::LengthMismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ManifestError::Read)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1_024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| ManifestError::Read)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ManifestError::Read)?;
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != record.digest {
        return Err(ManifestError::HashMismatch);
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ManifestError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(ManifestError::Invalid)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, ManifestError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(ManifestError::Invalid)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| ManifestError::Invalid)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::assert_total_parser;

    fn valid_manifest() -> Vec<u8> {
        let name = b"bolt-sandbox.exe";
        let mut encoded = Vec::from(MAGIC);
        encoded.extend_from_slice(&VERSION.to_le_bytes());
        encoded.extend_from_slice(
            &u16::try_from(HEADER_LENGTH)
                .expect("header length fits")
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&1_u16.to_le_bytes());
        encoded.extend_from_slice(&crate::ipc::framing::PROTOCOL_VERSION.to_le_bytes());
        encoded.extend_from_slice(&[0; 4]);
        encoded.extend_from_slice(
            &u16::try_from(name.len())
                .expect("component name length fits")
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&0_u16.to_le_bytes());
        encoded.extend_from_slice(&42_u64.to_le_bytes());
        encoded.extend_from_slice(&[0x5a; 32]);
        encoded.extend_from_slice(name);
        encoded
    }

    #[test]
    fn fuzz_002_component_manifest_parser_is_total_for_bounded_mutations() {
        assert_total_parser("component manifest", &[valid_manifest()], |bytes| {
            let _ = parse_manifest(bytes);
        });
    }
}
