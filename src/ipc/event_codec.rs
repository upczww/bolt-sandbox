#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProcessExit, ProcessExitReason, SandboxEvent,
        ipc::framing::{self, ProtocolError},
    };

    fn exited_event() -> SandboxEvent {
        SandboxEvent::ProcessExited(ProcessExit {
            process_id: 1234,
            exit_code: Some(7),
            reason: ProcessExitReason::Exited,
        })
    }

    #[test]
    fn evt_001_process_exit_round_trips_as_typed_event() {
        let encoded = encode_event(&exited_event(), 9).expect("event must encode");

        let decoded = decode_event(&encoded).expect("event must decode");

        assert_eq!(decoded.sequence, 9);
        assert_eq!(decoded.event, exited_event());
    }

    #[test]
    fn life_001_all_process_exit_reasons_round_trip() {
        for (reason, exit_code) in [
            (ProcessExitReason::Exited, Some(0)),
            (ProcessExitReason::Terminated, None),
            (ProcessExitReason::TimedOut, None),
            (ProcessExitReason::Crashed, Some(0xC000_0005)),
        ] {
            let event = SandboxEvent::ProcessExited(ProcessExit {
                process_id: 99,
                exit_code,
                reason,
            });

            let encoded = encode_event(&event, 1).expect("event must encode");
            let decoded = decode_event(&encoded).expect("event must decode");

            assert_eq!(decoded.event, event);
        }
    }

    #[test]
    fn ipc_005_process_exit_payload_with_wrong_length_is_rejected() {
        let encoded = framing::encode(&framing::Frame {
            version: framing::PROTOCOL_VERSION,
            kind: framing::FrameKind::ProcessExited,
            sequence: 1,
            payload: vec![0; PROCESS_EXIT_PAYLOAD_LENGTH - 1],
        })
        .expect("structurally valid frame must encode");

        assert_eq!(decode_event(&encoded), Err(ProtocolError::InvalidPayload));
    }

    #[test]
    fn ipc_005_unknown_exit_reason_is_rejected() {
        let mut encoded = encode_event(&exited_event(), 1).expect("event must encode");
        encoded[framing::HEADER_LENGTH + PROCESS_EXIT_REASON_OFFSET] = u8::MAX;
        framing::rewrite_checksum(&mut encoded);

        assert_eq!(decode_event(&encoded), Err(ProtocolError::InvalidPayload));
    }

    #[test]
    fn ipc_005_absent_exit_code_must_have_canonical_zero_bytes() {
        let event = SandboxEvent::ProcessExited(ProcessExit {
            process_id: 99,
            exit_code: None,
            reason: ProcessExitReason::Terminated,
        });
        let mut encoded = encode_event(&event, 1).expect("event must encode");
        encoded[framing::HEADER_LENGTH + PROCESS_EXIT_CODE_OFFSET] = 1;
        framing::rewrite_checksum(&mut encoded);

        assert_eq!(decode_event(&encoded), Err(ProtocolError::InvalidPayload));
    }
}
