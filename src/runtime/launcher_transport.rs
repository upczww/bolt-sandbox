use std::io::{self, Read};

const MAGIC: [u8; 4] = *b"BLX1";
const VERSION: u16 = 1;
const HEADER_LENGTH: usize = 12;
const MAX_PAYLOAD_LENGTH: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransportKind {
    Stdout,
    Stderr,
    Event,
    StdoutEof,
    StderrEof,
    EventEof,
    ProcessExit,
    InfrastructureFailure,
}

impl TryFrom<u16> for TransportKind {
    type Error = TransportError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stdout),
            2 => Ok(Self::Stderr),
            3 => Ok(Self::Event),
            4 => Ok(Self::StdoutEof),
            5 => Ok(Self::StderrEof),
            6 => Ok(Self::EventEof),
            7 => Ok(Self::ProcessExit),
            8 => Ok(Self::InfrastructureFailure),
            _ => Err(TransportError::UnknownKind),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TransportFrame {
    pub(super) kind: TransportKind,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransportError {
    TruncatedHeader,
    TruncatedPayload,
    InvalidMagic,
    UnsupportedVersion,
    UnknownKind,
    PayloadTooLarge,
    Read(io::ErrorKind),
}

pub(super) fn read_frame(reader: &mut impl Read) -> Result<Option<TransportFrame>, TransportError> {
    let mut header = [0_u8; HEADER_LENGTH];
    let mut header_read = 0;
    while header_read != header.len() {
        match reader.read(&mut header[header_read..]) {
            Ok(0) if header_read == 0 => return Ok(None),
            Ok(0) => return Err(TransportError::TruncatedHeader),
            Ok(count) => header_read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(TransportError::Read(error.kind())),
        }
    }
    if header[..4] != MAGIC {
        return Err(TransportError::InvalidMagic);
    }
    if u16::from_le_bytes([header[4], header[5]]) != VERSION {
        return Err(TransportError::UnsupportedVersion);
    }
    let kind = TransportKind::try_from(u16::from_le_bytes([header[6], header[7]]))?;
    let payload_length = usize::try_from(u32::from_le_bytes([
        header[8], header[9], header[10], header[11],
    ]))
    .map_err(|_| TransportError::PayloadTooLarge)?;
    if payload_length > MAX_PAYLOAD_LENGTH {
        return Err(TransportError::PayloadTooLarge);
    }
    let mut payload = vec![0; payload_length];
    read_exact_payload(reader, &mut payload)?;
    Ok(Some(TransportFrame { kind, payload }))
}

fn read_exact_payload(reader: &mut impl Read, payload: &mut [u8]) -> Result<(), TransportError> {
    let mut offset = 0;
    while offset != payload.len() {
        match reader.read(&mut payload[offset..]) {
            Ok(0) => return Err(TransportError::TruncatedPayload),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(TransportError::Read(error.kind())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use super::*;

    fn encoded(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(*b"BLX1");
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload length fits")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn transport_preserves_binary_stream_bytes_and_frame_boundaries() {
        let mut input = encoded(1, &[0, 0xff, 0xe4]);
        input.extend_from_slice(&encoded(2, &[0xb8, 0xad, b'\n']));
        let mut reader = Cursor::new(input);

        assert_eq!(
            read_frame(&mut reader),
            Ok(Some(TransportFrame {
                kind: TransportKind::Stdout,
                payload: vec![0, 0xff, 0xe4],
            }))
        );
        assert_eq!(
            read_frame(&mut reader),
            Ok(Some(TransportFrame {
                kind: TransportKind::Stderr,
                payload: vec![0xb8, 0xad, b'\n'],
            }))
        );
        assert_eq!(read_frame(&mut reader), Ok(None));
    }

    #[test]
    fn transport_rejects_unknown_oversized_and_truncated_frames() {
        assert_eq!(
            read_frame(&mut Cursor::new(encoded(99, &[]))),
            Err(TransportError::UnknownKind)
        );

        let mut oversized = encoded(1, &[]);
        oversized[8..12].copy_from_slice(&1_048_577_u32.to_le_bytes());
        assert_eq!(
            read_frame(&mut Cursor::new(oversized)),
            Err(TransportError::PayloadTooLarge)
        );

        assert_eq!(
            read_frame(&mut Cursor::new(&b"BLX1\x01"[..])),
            Err(TransportError::TruncatedHeader)
        );
        assert_eq!(
            read_frame(&mut Cursor::new(encoded(3, &[1, 2, 3])[..14].to_vec())),
            Err(TransportError::TruncatedPayload)
        );
    }

    struct BrokenPipe;

    impl Read for BrokenPipe {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn transport_treats_windows_pipe_close_as_clean_eof_only_between_frames() {
        assert_eq!(read_frame(&mut BrokenPipe), Ok(None));

        let mut partial_then_broken = Cursor::new(b"BLX1".to_vec()).chain(BrokenPipe);
        assert_eq!(
            read_frame(&mut partial_then_broken),
            Err(TransportError::Read(io::ErrorKind::BrokenPipe))
        );
    }
}
