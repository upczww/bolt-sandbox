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
        assert_eq!(decode(&[0; HEADER_LENGTH - 1]), Err(ProtocolError::TruncatedHeader));

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
}
