use super::framing::{self, Frame, FrameKind, ProtocolError};
use crate::{ProcessExit, ProcessExitReason, SandboxEvent};

const PROCESS_EXIT_PAYLOAD_LENGTH: usize = 10;
const PROCESS_EXIT_REASON_OFFSET: usize = 4;
const PROCESS_EXIT_CODE_PRESENT_OFFSET: usize = 5;
const PROCESS_EXIT_CODE_OFFSET: usize = 6;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SequencedEvent {
    pub(super) sequence: u64,
    pub(super) event: SandboxEvent,
}

#[allow(
    dead_code,
    reason = "Ready frames are emitted by the launcher transport in the next phase"
)]
pub(super) fn encode_ready(nonce: [u8; 16], sequence: u64) -> Result<Vec<u8>, ProtocolError> {
    framing::encode(&Frame {
        version: framing::PROTOCOL_VERSION,
        kind: FrameKind::Ready,
        sequence,
        payload: nonce.to_vec(),
    })
}

#[allow(
    dead_code,
    reason = "event frames are emitted by the launcher transport in the next phase"
)]
pub(super) fn encode_event(event: &SandboxEvent, sequence: u64) -> Result<Vec<u8>, ProtocolError> {
    let (kind, payload) = match event {
        SandboxEvent::Ready => (FrameKind::Ready, Vec::new()),
        SandboxEvent::ProcessExited(process_exit) => {
            let mut payload = vec![0; PROCESS_EXIT_PAYLOAD_LENGTH];
            payload[..4].copy_from_slice(&process_exit.process_id.to_le_bytes());
            payload[PROCESS_EXIT_REASON_OFFSET] = process_exit.reason.wire_value();
            if let Some(exit_code) = process_exit.exit_code {
                payload[PROCESS_EXIT_CODE_PRESENT_OFFSET] = 1;
                payload[PROCESS_EXIT_CODE_OFFSET..PROCESS_EXIT_CODE_OFFSET + 4]
                    .copy_from_slice(&exit_code.to_le_bytes());
            }
            (FrameKind::ProcessExited, payload)
        }
    };

    framing::encode(&Frame {
        version: framing::PROTOCOL_VERSION,
        kind,
        sequence,
        payload,
    })
}

pub(super) fn decode_event(encoded: &[u8]) -> Result<SequencedEvent, ProtocolError> {
    let frame = framing::decode(encoded)?;
    let event = match frame.kind {
        FrameKind::Ready if frame.payload.is_empty() => SandboxEvent::Ready,
        FrameKind::Ready => return Err(ProtocolError::InvalidPayload),
        FrameKind::ProcessExited => decode_process_exit(&frame.payload)?,
    };

    Ok(SequencedEvent {
        sequence: frame.sequence,
        event,
    })
}

fn decode_process_exit(payload: &[u8]) -> Result<SandboxEvent, ProtocolError> {
    if payload.len() != PROCESS_EXIT_PAYLOAD_LENGTH {
        return Err(ProtocolError::InvalidPayload);
    }

    let reason = ProcessExitReason::from_wire(payload[PROCESS_EXIT_REASON_OFFSET])
        .ok_or(ProtocolError::InvalidPayload)?;
    let raw_exit_code = read_u32(payload, PROCESS_EXIT_CODE_OFFSET);
    let exit_code = match payload[PROCESS_EXIT_CODE_PRESENT_OFFSET] {
        0 if raw_exit_code == 0 => None,
        1 => Some(raw_exit_code),
        _ => return Err(ProtocolError::InvalidPayload),
    };

    Ok(SandboxEvent::ProcessExited(ProcessExit {
        process_id: read_u32(payload, 0),
        exit_code,
        reason,
    }))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

impl ProcessExitReason {
    #[allow(
        dead_code,
        reason = "event frames are emitted by the launcher transport in the next phase"
    )]
    fn wire_value(self) -> u8 {
        match self {
            Self::Exited => 0,
            Self::Terminated => 1,
            Self::TimedOut => 2,
            Self::Crashed => 3,
        }
    }

    fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Exited),
            1 => Some(Self::Terminated),
            2 => Some(Self::TimedOut),
            3 => Some(Self::Crashed),
            _ => None,
        }
    }
}

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
