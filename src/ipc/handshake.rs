use super::framing::{self, FrameKind};
use crate::SandboxEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandshakeState {
    AwaitingReady,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandshakeError {
    Protocol,
    DuplicateReady,
    UnexpectedSequence { expected: u64, actual: u64 },
    UnexpectedMessage,
    InvalidReadyPayload,
    NonceMismatch,
}

pub(super) struct Handshake {
    expected_nonce: [u8; 16],
    state: HandshakeState,
}

impl Handshake {
    pub(super) fn new(expected_nonce: [u8; 16]) -> Self {
        Self {
            expected_nonce,
            state: HandshakeState::AwaitingReady,
        }
    }

    pub(super) fn state(&self) -> HandshakeState {
        self.state
    }

    pub(super) fn accept(&mut self, encoded: &[u8]) -> Result<SandboxEvent, HandshakeError> {
        if self.state == HandshakeState::Ready {
            return Err(HandshakeError::DuplicateReady);
        }

        let frame = framing::decode(encoded).map_err(|_| HandshakeError::Protocol)?;
        if frame.sequence != 0 {
            return Err(HandshakeError::UnexpectedSequence {
                expected: 0,
                actual: frame.sequence,
            });
        }
        if frame.kind != FrameKind::Ready {
            return Err(HandshakeError::UnexpectedMessage);
        }
        let nonce: [u8; 16] = frame
            .payload
            .try_into()
            .map_err(|_| HandshakeError::InvalidReadyPayload)?;
        if !constant_time_eq(&nonce, &self.expected_nonce) {
            return Err(HandshakeError::NonceMismatch);
        }

        self.state = HandshakeState::Ready;
        Ok(SandboxEvent::Ready)
    }
}

fn constant_time_eq(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

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
