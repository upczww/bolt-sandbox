const MAGIC: [u8; 4] = *b"BLT1";
pub(super) const PROTOCOL_VERSION: u16 = 1;
const HEADER_LENGTH: usize = 24;
const VERSION_OFFSET: usize = 4;
const KIND_OFFSET: usize = 6;
const LENGTH_OFFSET: usize = 8;
const SEQUENCE_OFFSET: usize = 12;
const CHECKSUM_OFFSET: usize = 20;
const MAX_PAYLOAD_LENGTH: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Frame {
    pub(super) version: u16,
    pub(super) kind: FrameKind,
    pub(super) sequence: u64,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(super) enum FrameKind {
    Ready = 1,
}

impl TryFrom<u16> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ready),
            _ => Err(ProtocolError::UnknownFrameKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtocolError {
    TruncatedHeader,
    TruncatedPayload,
    PayloadTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    UnknownFrameKind,
    ChecksumMismatch,
    TrailingBytes,
}

pub(super) fn encode(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    if frame.version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if frame.payload.len() > MAX_PAYLOAD_LENGTH {
        return Err(ProtocolError::PayloadTooLarge);
    }

    let payload_length =
        u32::try_from(frame.payload.len()).map_err(|_| ProtocolError::PayloadTooLarge)?;
    let mut encoded = vec![0; HEADER_LENGTH + frame.payload.len()];
    encoded[..MAGIC.len()].copy_from_slice(&MAGIC);
    encoded[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&frame.version.to_le_bytes());
    encoded[KIND_OFFSET..KIND_OFFSET + 2].copy_from_slice(&(frame.kind as u16).to_le_bytes());
    encoded[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&payload_length.to_le_bytes());
    encoded[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 8].copy_from_slice(&frame.sequence.to_le_bytes());
    encoded[HEADER_LENGTH..].copy_from_slice(&frame.payload);

    let checksum = frame_checksum(&encoded);
    encoded[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    Ok(encoded)
}

pub(super) fn decode(encoded: &[u8]) -> Result<Frame, ProtocolError> {
    if encoded.len() < HEADER_LENGTH {
        return Err(ProtocolError::TruncatedHeader);
    }
    if encoded[..MAGIC.len()] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }

    let version = read_u16(encoded, VERSION_OFFSET);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let kind = FrameKind::try_from(read_u16(encoded, KIND_OFFSET))?;
    let payload_length = read_u32(encoded, LENGTH_OFFSET) as usize;
    if payload_length > MAX_PAYLOAD_LENGTH {
        return Err(ProtocolError::PayloadTooLarge);
    }

    let expected_length = HEADER_LENGTH + payload_length;
    if encoded.len() < expected_length {
        return Err(ProtocolError::TruncatedPayload);
    }
    if encoded.len() > expected_length {
        return Err(ProtocolError::TrailingBytes);
    }

    let expected_checksum = read_u32(encoded, CHECKSUM_OFFSET);
    if frame_checksum(encoded) != expected_checksum {
        return Err(ProtocolError::ChecksumMismatch);
    }

    Ok(Frame {
        version,
        kind,
        sequence: read_u64(encoded, SEQUENCE_OFFSET),
        payload: encoded[HEADER_LENGTH..].to_vec(),
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn frame_checksum(encoded: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF;
    for byte in encoded[..CHECKSUM_OFFSET]
        .iter()
        .chain(&encoded[HEADER_LENGTH..])
    {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_frame(payload: Vec<u8>) -> Frame {
        Frame {
            version: PROTOCOL_VERSION,
            kind: FrameKind::Ready,
            sequence: 42,
            payload,
        }
    }

    #[test]
    fn ipc_004_zero_and_normal_payloads_round_trip() {
        for payload in [Vec::new(), b"ready".to_vec()] {
            let expected = ready_frame(payload);

            let encoded = encode(&expected).expect("valid frame must encode");
            let decoded = decode(&encoded).expect("encoded frame must decode");

            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn ipc_004_maximum_payload_round_trips() {
        let expected = ready_frame(vec![0xA5; MAX_PAYLOAD_LENGTH]);

        let encoded = encode(&expected).expect("maximum frame must encode");
        let decoded = decode(&encoded).expect("maximum frame must decode");

        assert_eq!(decoded, expected);
    }

    #[test]
    fn ipc_005_truncated_header_and_payload_are_rejected() {
        assert_eq!(
            decode(&[0; HEADER_LENGTH - 1]),
            Err(ProtocolError::TruncatedHeader)
        );

        let encoded = encode(&ready_frame(b"ready".to_vec())).expect("frame must encode");
        assert_eq!(
            decode(&encoded[..encoded.len() - 1]),
            Err(ProtocolError::TruncatedPayload)
        );
    }

    #[test]
    fn ipc_006_oversized_payload_is_rejected_before_encoding() {
        let frame = ready_frame(vec![0; MAX_PAYLOAD_LENGTH + 1]);

        assert_eq!(encode(&frame), Err(ProtocolError::PayloadTooLarge));
    }

    #[test]
    fn ipc_007_corrupted_payload_fails_checksum() {
        let mut encoded = encode(&ready_frame(b"ready".to_vec())).expect("frame must encode");
        *encoded.last_mut().expect("payload byte must exist") ^= 0xFF;

        assert_eq!(decode(&encoded), Err(ProtocolError::ChecksumMismatch));
    }

    #[test]
    fn ipc_008_unknown_version_is_rejected() {
        let mut encoded = encode(&ready_frame(Vec::new())).expect("frame must encode");
        encoded[VERSION_OFFSET..VERSION_OFFSET + 2]
            .copy_from_slice(&(PROTOCOL_VERSION + 1).to_le_bytes());

        assert_eq!(decode(&encoded), Err(ProtocolError::UnsupportedVersion));
    }

    #[test]
    fn ipc_005_invalid_magic_and_trailing_bytes_are_rejected() {
        let mut invalid_magic = encode(&ready_frame(Vec::new())).expect("frame must encode");
        invalid_magic[0] ^= 0xFF;
        assert_eq!(decode(&invalid_magic), Err(ProtocolError::InvalidMagic));

        let mut trailing = encode(&ready_frame(Vec::new())).expect("frame must encode");
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(ProtocolError::TrailingBytes));
    }

    #[test]
    fn ipc_006_oversized_declared_length_is_rejected_before_payload_read() {
        let mut encoded = encode(&ready_frame(Vec::new())).expect("frame must encode");
        let oversized = u32::try_from(MAX_PAYLOAD_LENGTH + 1).expect("limit must fit u32");
        encoded[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&oversized.to_le_bytes());

        assert_eq!(decode(&encoded), Err(ProtocolError::PayloadTooLarge));
    }

    #[test]
    fn ipc_007_header_tampering_fails_checksum() {
        let mut encoded = encode(&ready_frame(Vec::new())).expect("frame must encode");
        encoded[SEQUENCE_OFFSET] ^= 0x01;

        assert_eq!(decode(&encoded), Err(ProtocolError::ChecksumMismatch));
    }

    #[test]
    fn ipc_009_unknown_frame_kind_is_rejected() {
        let mut encoded = encode(&ready_frame(Vec::new())).expect("frame must encode");
        encoded[KIND_OFFSET..KIND_OFFSET + 2].copy_from_slice(&u16::MAX.to_le_bytes());

        assert_eq!(decode(&encoded), Err(ProtocolError::UnknownFrameKind));
    }

    #[test]
    fn ipc_015_ready_frame_matches_protocol_v1_golden_vector() {
        let encoded = encode(&ready_frame(b"ready".to_vec())).expect("frame must encode");
        let expected = [
            0x42, 0x4C, 0x54, 0x31, // magic
            0x01, 0x00, // version
            0x01, 0x00, // ready kind
            0x05, 0x00, 0x00, 0x00, // payload length
            0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence
            0xF9, 0xD9, 0xF7, 0xB6, // CRC-32
            0x72, 0x65, 0x61, 0x64, 0x79, // "ready"
        ];

        assert_eq!(encoded, expected);
    }
}
