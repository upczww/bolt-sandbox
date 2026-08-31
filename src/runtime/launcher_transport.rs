#[cfg(test)]
mod tests {
    use std::io::Cursor;

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
}
