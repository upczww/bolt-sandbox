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

        assert_eq!(session.accept(&process_exit(2)), Err(SessionError::EventAfterExit));
        assert_eq!(session.state(), SessionState::Exited);
    }
}
