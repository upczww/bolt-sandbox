use super::{
    event_codec,
    framing::{self, FrameKind},
    handshake::{Handshake, HandshakeError},
};
use crate::SandboxEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionState {
    AwaitingReady,
    Running,
    Exited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionError {
    Protocol,
    ExpectedReady,
    DuplicateReady,
    UnexpectedSequence { expected: u64, actual: u64 },
    SequenceExhausted,
    EventAfterExit,
}

pub(crate) struct SessionProtocol {
    handshake: Handshake,
    state: SessionState,
    next_sequence: u64,
}

impl SessionProtocol {
    pub(crate) fn new(expected_nonce: [u8; 16]) -> Self {
        Self {
            handshake: Handshake::new(expected_nonce),
            state: SessionState::AwaitingReady,
            next_sequence: 0,
        }
    }

    pub(crate) fn state(&self) -> SessionState {
        self.state
    }

    pub(crate) fn accept(&mut self, encoded: &[u8]) -> Result<SandboxEvent, SessionError> {
        match self.state {
            SessionState::AwaitingReady => self.accept_ready(encoded),
            SessionState::Running => self.accept_running_event(encoded),
            SessionState::Exited => Err(SessionError::EventAfterExit),
        }
    }

    fn accept_ready(&mut self, encoded: &[u8]) -> Result<SandboxEvent, SessionError> {
        let event = self
            .handshake
            .accept(encoded)
            .map_err(|error| match error {
                HandshakeError::UnexpectedMessage => SessionError::ExpectedReady,
                HandshakeError::DuplicateReady => SessionError::DuplicateReady,
                HandshakeError::UnexpectedSequence { expected, actual } => {
                    SessionError::UnexpectedSequence { expected, actual }
                }
                HandshakeError::Protocol
                | HandshakeError::InvalidReadyPayload
                | HandshakeError::NonceMismatch => SessionError::Protocol,
            })?;

        self.state = SessionState::Running;
        self.next_sequence = 1;
        Ok(event)
    }

    fn accept_running_event(&mut self, encoded: &[u8]) -> Result<SandboxEvent, SessionError> {
        let frame = framing::decode(encoded).map_err(|_| SessionError::Protocol)?;
        if frame.kind == FrameKind::Ready {
            return Err(SessionError::DuplicateReady);
        }

        let sequenced = event_codec::decode_event(encoded).map_err(|_| SessionError::Protocol)?;
        if sequenced.sequence != self.next_sequence {
            return Err(SessionError::UnexpectedSequence {
                expected: self.next_sequence,
                actual: sequenced.sequence,
            });
        }

        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(SessionError::SequenceExhausted)?;
        if matches!(sequenced.event, SandboxEvent::ProcessExited(_)) {
            self.state = SessionState::Exited;
        }

        Ok(sequenced.event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProcessExit, ProcessExitReason, SandboxEvent, ipc::event_codec};

    const NONCE: [u8; 16] = [0x3C; 16];

    fn ready(sequence: u64) -> Vec<u8> {
        event_codec::encode_ready(NONCE, sequence).expect("ready must encode")
    }

    fn process_exit(sequence: u64) -> Vec<u8> {
        event_codec::encode_event(
            &SandboxEvent::ProcessExited(ProcessExit {
                process_id: 1234,
                exit_code: Some(0),
                reason: ProcessExitReason::Exited,
            }),
            sequence,
        )
        .expect("process exit must encode")
    }

    #[test]
    fn evt_002_ready_then_sequence_one_event_reaches_exited_state() {
        let mut session = SessionProtocol::new(NONCE);

        assert_eq!(session.accept(&ready(0)), Ok(SandboxEvent::Ready));
        assert_eq!(session.state(), SessionState::Running);
        assert!(matches!(
            session.accept(&process_exit(1)),
            Ok(SandboxEvent::ProcessExited(_))
        ));
        assert_eq!(session.state(), SessionState::Exited);
    }

    #[test]
    fn ipc_012_event_before_ready_is_rejected_without_state_change() {
        let mut session = SessionProtocol::new(NONCE);

        let result = session.accept(&process_exit(1));

        assert_eq!(result, Err(SessionError::ExpectedReady));
        assert_eq!(session.state(), SessionState::AwaitingReady);
    }

    #[test]
    fn evt_003_gap_is_rejected_and_expected_sequence_does_not_advance() {
        let mut session = SessionProtocol::new(NONCE);
        session.accept(&ready(0)).expect("ready must succeed");

        assert_eq!(
            session.accept(&process_exit(2)),
            Err(SessionError::UnexpectedSequence {
                expected: 1,
                actual: 2,
            })
        );
        assert!(matches!(
            session.accept(&process_exit(1)),
            Ok(SandboxEvent::ProcessExited(_))
        ));
    }

    #[test]
    fn ipc_012_duplicate_ready_after_running_is_rejected() {
        let mut session = SessionProtocol::new(NONCE);
        session.accept(&ready(0)).expect("ready must succeed");

        assert_eq!(session.accept(&ready(1)), Err(SessionError::DuplicateReady));
        assert_eq!(session.state(), SessionState::Running);
    }

    #[test]
    fn life_010_event_after_process_exit_is_rejected() {
        let mut session = SessionProtocol::new(NONCE);
        session.accept(&ready(0)).expect("ready must succeed");
        session
            .accept(&process_exit(1))
            .expect("process exit must succeed");

        assert_eq!(
            session.accept(&process_exit(2)),
            Err(SessionError::EventAfterExit)
        );
        assert_eq!(session.state(), SessionState::Exited);
    }
}
