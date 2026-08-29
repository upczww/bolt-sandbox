#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxEvent, ipc::framing};

    const EXPECTED_NONCE: [u8; 16] = [0xA5; 16];

    fn ready_frame(nonce: [u8; 16], sequence: u64) -> Vec<u8> {
        framing::encode(&framing::Frame {
            version: framing::PROTOCOL_VERSION,
            kind: framing::FrameKind::Ready,
            sequence,
            payload: nonce.to_vec(),
        })
        .expect("ready frame must encode")
    }

    #[test]
    fn ipc_002_matching_nonce_and_initial_sequence_complete_handshake() {
        let mut handshake = Handshake::new(EXPECTED_NONCE);

        let event = handshake.accept(&ready_frame(EXPECTED_NONCE, 0));

        assert_eq!(event, Ok(SandboxEvent::Ready));
        assert_eq!(handshake.state(), HandshakeState::Ready);
    }

    #[test]
    fn ipc_012_duplicate_ready_is_rejected() {
        let mut handshake = Handshake::new(EXPECTED_NONCE);
        handshake
            .accept(&ready_frame(EXPECTED_NONCE, 0))
            .expect("first ready must succeed");

        let duplicate = handshake.accept(&ready_frame(EXPECTED_NONCE, 1));

        assert_eq!(duplicate, Err(HandshakeError::DuplicateReady));
        assert_eq!(handshake.state(), HandshakeState::Ready);
    }

    #[test]
    fn ipc_018_replayed_ready_from_another_execution_is_rejected() {
        let mut handshake = Handshake::new(EXPECTED_NONCE);

        let result = handshake.accept(&ready_frame([0x5A; 16], 0));

        assert_eq!(result, Err(HandshakeError::NonceMismatch));
        assert_eq!(handshake.state(), HandshakeState::AwaitingReady);
    }

    #[test]
    fn evt_002_first_sequence_must_be_zero() {
        let mut handshake = Handshake::new(EXPECTED_NONCE);

        let result = handshake.accept(&ready_frame(EXPECTED_NONCE, 42));

        assert_eq!(
            result,
            Err(HandshakeError::UnexpectedSequence {
                expected: 0,
                actual: 42,
            })
        );
        assert_eq!(handshake.state(), HandshakeState::AwaitingReady);
    }

    #[test]
    fn ipc_012_malformed_ready_frame_does_not_advance_state() {
        let mut handshake = Handshake::new(EXPECTED_NONCE);
        let mut malformed = ready_frame(EXPECTED_NONCE, 0);
        *malformed.last_mut().expect("nonce byte must exist") ^= 0xFF;

        let result = handshake.accept(&malformed);

        assert_eq!(result, Err(HandshakeError::Protocol));
        assert_eq!(handshake.state(), HandshakeState::AwaitingReady);
    }
}
