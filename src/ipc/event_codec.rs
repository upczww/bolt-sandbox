use std::{
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};

use super::framing::{self, Frame, FrameKind, ProtocolError};
use crate::{
    ChildInjectionFailure, ChildInjectionFailureReason, FilesystemOperation, FilesystemViolation,
    NetworkOperation, NetworkTarget, NetworkViolation, ProcessExit, ProcessExitReason,
    ProcessOperation, ProcessViolation, RecoveryArtifact, RegistryOperation, RegistryViolation,
    SandboxEvent,
};

const PROCESS_EXIT_PAYLOAD_LENGTH: usize = 10;
const PROCESS_EXIT_REASON_OFFSET: usize = 4;
const PROCESS_EXIT_CODE_PRESENT_OFFSET: usize = 5;
const PROCESS_EXIT_CODE_OFFSET: usize = 6;
const MAX_EVENT_PATH_CODE_UNITS: usize = 32_767;
const MAX_EVENT_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SequencedEvent {
    pub(super) sequence: u64,
    pub(super) event: SandboxEvent,
}

#[allow(
    dead_code,
    reason = "Ready frames are emitted by the launcher transport in the next phase"
)]
pub(crate) fn encode_ready(nonce: [u8; 16], sequence: u64) -> Result<Vec<u8>, ProtocolError> {
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
pub(crate) fn encode_event(event: &SandboxEvent, sequence: u64) -> Result<Vec<u8>, ProtocolError> {
    let (kind, payload) = match event {
        SandboxEvent::Ready => (FrameKind::Ready, Vec::new()),
        SandboxEvent::FilesystemViolation(violation) => (
            FrameKind::FilesystemViolation,
            encode_filesystem_violation(violation)?,
        ),
        SandboxEvent::RegistryViolation(violation) => (
            FrameKind::RegistryViolation,
            encode_registry_violation(violation)?,
        ),
        SandboxEvent::NetworkViolation(violation) => (
            FrameKind::NetworkViolation,
            encode_network_violation(violation)?,
        ),
        SandboxEvent::RecoveryArtifactCreated(artifact) => (
            FrameKind::RecoveryArtifactCreated,
            encode_recovery_artifact(artifact)?,
        ),
        SandboxEvent::ChildInjectionFailed(failure) => (
            FrameKind::ChildInjectionFailed,
            encode_child_injection_failure(failure),
        ),
        SandboxEvent::ProcessViolation(violation) => (
            FrameKind::ProcessViolation,
            encode_process_violation(violation),
        ),
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
        FrameKind::FilesystemViolation => decode_filesystem_violation(&frame.payload)?,
        FrameKind::RegistryViolation => decode_registry_violation(&frame.payload)?,
        FrameKind::NetworkViolation => decode_network_violation(&frame.payload)?,
        FrameKind::RecoveryArtifactCreated => decode_recovery_artifact(&frame.payload)?,
        FrameKind::ChildInjectionFailed => decode_child_injection_failure(&frame.payload)?,
        FrameKind::ProcessViolation => decode_process_violation(&frame.payload)?,
        FrameKind::ProcessExited => decode_process_exit(&frame.payload)?,
    };

    Ok(SequencedEvent {
        sequence: frame.sequence,
        event,
    })
}

fn encode_filesystem_violation(violation: &FilesystemViolation) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    push_u32(&mut payload, violation.process_id);
    payload.push(violation.operation.wire_value());
    push_path(&mut payload, &violation.path)?;
    Ok(payload)
}

fn decode_filesystem_violation(payload: &[u8]) -> Result<SandboxEvent, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let process_id = reader.read_u32()?;
    let operation =
        FilesystemOperation::from_wire(reader.read_u8()?).ok_or(ProtocolError::InvalidPayload)?;
    let path = reader.read_path()?;
    reader.finish()?;
    Ok(SandboxEvent::FilesystemViolation(FilesystemViolation {
        process_id,
        operation,
        path,
    }))
}

fn encode_registry_violation(violation: &RegistryViolation) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    push_u32(&mut payload, violation.process_id);
    payload.push(violation.operation.wire_value());
    push_text(&mut payload, &violation.key)?;
    Ok(payload)
}

fn decode_registry_violation(payload: &[u8]) -> Result<SandboxEvent, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let process_id = reader.read_u32()?;
    let operation =
        RegistryOperation::from_wire(reader.read_u8()?).ok_or(ProtocolError::InvalidPayload)?;
    let key = reader.read_text()?.to_owned();
    reader.finish()?;
    Ok(SandboxEvent::RegistryViolation(RegistryViolation {
        process_id,
        operation,
        key,
    }))
}

fn encode_network_violation(violation: &NetworkViolation) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    push_u32(&mut payload, violation.process_id);
    payload.push(violation.operation.wire_value());
    match &violation.target {
        NetworkTarget::Domain(domain) => {
            payload.push(0);
            push_text(&mut payload, domain)?;
        }
        NetworkTarget::Socket(SocketAddr::V4(address)) => {
            payload.push(4);
            payload.extend_from_slice(&address.ip().octets());
            payload.extend_from_slice(&address.port().to_le_bytes());
        }
        NetworkTarget::Socket(SocketAddr::V6(address)) => {
            payload.push(6);
            payload.extend_from_slice(&address.ip().octets());
            payload.extend_from_slice(&address.port().to_le_bytes());
        }
    }
    Ok(payload)
}

fn decode_network_violation(payload: &[u8]) -> Result<SandboxEvent, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let process_id = reader.read_u32()?;
    let operation =
        NetworkOperation::from_wire(reader.read_u8()?).ok_or(ProtocolError::InvalidPayload)?;
    let target = match reader.read_u8()? {
        0 => NetworkTarget::Domain(reader.read_text()?.to_owned()),
        4 => {
            let octets: [u8; 4] = reader.read_exact(4)?.try_into().map_err(invalid_payload)?;
            NetworkTarget::Socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                reader.read_u16()?,
            ))
        }
        6 => {
            let octets: [u8; 16] = reader.read_exact(16)?.try_into().map_err(invalid_payload)?;
            NetworkTarget::Socket(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                reader.read_u16()?,
            ))
        }
        _ => return Err(ProtocolError::InvalidPayload),
    };
    reader.finish()?;
    Ok(SandboxEvent::NetworkViolation(NetworkViolation {
        process_id,
        operation,
        target,
    }))
}

fn encode_recovery_artifact(artifact: &RecoveryArtifact) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    push_u32(&mut payload, artifact.process_id);
    payload.extend_from_slice(&artifact.artifact_id.to_le_bytes());
    payload.extend_from_slice(&artifact.byte_count.to_le_bytes());
    push_path(&mut payload, &artifact.original_path)?;
    Ok(payload)
}

fn decode_recovery_artifact(payload: &[u8]) -> Result<SandboxEvent, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let process_id = reader.read_u32()?;
    let artifact_id = reader.read_u64()?;
    let byte_count = reader.read_u64()?;
    let original_path = reader.read_path()?;
    reader.finish()?;
    Ok(SandboxEvent::RecoveryArtifactCreated(RecoveryArtifact {
        process_id,
        artifact_id,
        original_path,
        byte_count,
    }))
}

fn encode_child_injection_failure(failure: &ChildInjectionFailure) -> Vec<u8> {
    let mut payload = Vec::with_capacity(9);
    push_u32(&mut payload, failure.parent_process_id);
    push_u32(&mut payload, failure.child_process_id);
    payload.push(failure.reason.wire_value());
    payload
}

fn decode_child_injection_failure(payload: &[u8]) -> Result<SandboxEvent, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let parent_process_id = reader.read_u32()?;
    let child_process_id = reader.read_u32()?;
    let reason = ChildInjectionFailureReason::from_wire(reader.read_u8()?)
        .ok_or(ProtocolError::InvalidPayload)?;
    reader.finish()?;
    Ok(SandboxEvent::ChildInjectionFailed(ChildInjectionFailure {
        parent_process_id,
        child_process_id,
        reason,
    }))
}

fn encode_process_violation(violation: &ProcessViolation) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5);
    push_u32(&mut payload, violation.process_id);
    payload.push(violation.operation.wire_value());
    payload
}

fn decode_process_violation(payload: &[u8]) -> Result<SandboxEvent, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let process_id = reader.read_u32()?;
    let operation =
        ProcessOperation::from_wire(reader.read_u8()?).ok_or(ProtocolError::InvalidPayload)?;
    reader.finish()?;
    Ok(SandboxEvent::ProcessViolation(ProcessViolation {
        process_id,
        operation,
    }))
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

macro_rules! wire_enum {
    ($type:ty, $($variant:path => $value:literal),+ $(,)?) => {
        impl $type {
            const fn wire_value(self) -> u8 {
                match self {
                    $($variant => $value),+
                }
            }

            const fn from_wire(value: u8) -> Option<Self> {
                match value {
                    $($value => Some($variant)),+,
                    _ => None,
                }
            }
        }
    };
}

wire_enum!(
    FilesystemOperation,
    FilesystemOperation::Read => 0,
    FilesystemOperation::Write => 1,
    FilesystemOperation::Metadata => 2,
    FilesystemOperation::Create => 3,
    FilesystemOperation::Delete => 4,
    FilesystemOperation::Rename => 5,
    FilesystemOperation::Enumerate => 6,
);
wire_enum!(
    RegistryOperation,
    RegistryOperation::Open => 0,
    RegistryOperation::Query => 1,
    RegistryOperation::Enumerate => 2,
    RegistryOperation::Create => 3,
    RegistryOperation::SetValue => 4,
    RegistryOperation::Delete => 5,
    RegistryOperation::Rename => 6,
);
wire_enum!(
    NetworkOperation,
    NetworkOperation::Resolve => 0,
    NetworkOperation::Connect => 1,
    NetworkOperation::Send => 2,
);
wire_enum!(
    ChildInjectionFailureReason,
    ChildInjectionFailureReason::UnsupportedArchitecture => 0,
    ChildInjectionFailureReason::PolicyUnavailable => 1,
    ChildInjectionFailureReason::InjectionFailed => 2,
    ChildInjectionFailureReason::HandshakeFailed => 3,
);
wire_enum!(
    ProcessOperation,
    ProcessOperation::CreateWithToken => 0,
    ProcessOperation::CreateWithLogon => 1,
    ProcessOperation::Elevation => 2,
);

fn push_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

fn push_text(payload: &mut Vec<u8>, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_EVENT_TEXT_BYTES {
        return Err(ProtocolError::InvalidPayload);
    }
    let length = u32::try_from(value.len()).map_err(|_| ProtocolError::InvalidPayload)?;
    push_u32(payload, length);
    payload.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_path(payload: &mut Vec<u8>, path: &std::path::Path) -> Result<(), ProtocolError> {
    let length = path.as_os_str().encode_wide().count();
    if length == 0 || length > MAX_EVENT_PATH_CODE_UNITS {
        return Err(ProtocolError::InvalidPayload);
    }
    push_u32(
        payload,
        u32::try_from(length).map_err(|_| ProtocolError::InvalidPayload)?,
    );
    for code_unit in path.as_os_str().encode_wide() {
        payload.extend_from_slice(&code_unit.to_le_bytes());
    }
    Ok(())
}

fn invalid_payload<T>(_: T) -> ProtocolError {
    ProtocolError::InvalidPayload
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::InvalidPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::InvalidPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        let value: [u8; 2] = self.read_exact(2)?.try_into().map_err(invalid_payload)?;
        Ok(u16::from_le_bytes(value))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        let value: [u8; 4] = self.read_exact(4)?.try_into().map_err(invalid_payload)?;
        Ok(u32::from_le_bytes(value))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        let value: [u8; 8] = self.read_exact(8)?.try_into().map_err(invalid_payload)?;
        Ok(u64::from_le_bytes(value))
    }

    fn read_text(&mut self) -> Result<&'a str, ProtocolError> {
        let length = usize::try_from(self.read_u32()?).map_err(invalid_payload)?;
        if length == 0 || length > MAX_EVENT_TEXT_BYTES {
            return Err(ProtocolError::InvalidPayload);
        }
        std::str::from_utf8(self.read_exact(length)?).map_err(invalid_payload)
    }

    fn read_path(&mut self) -> Result<PathBuf, ProtocolError> {
        let length = usize::try_from(self.read_u32()?).map_err(invalid_payload)?;
        if length == 0 || length > MAX_EVENT_PATH_CODE_UNITS {
            return Err(ProtocolError::InvalidPayload);
        }
        let byte_length = length.checked_mul(2).ok_or(ProtocolError::InvalidPayload)?;
        let bytes = self.read_exact(byte_length)?;
        let wide = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        Ok(PathBuf::from(OsString::from_wide(&wide)))
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::InvalidPayload)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv6Addr, SocketAddr},
        path::PathBuf,
    };

    use super::*;
    use crate::{
        ChildInjectionFailure, ChildInjectionFailureReason, FilesystemOperation,
        FilesystemViolation, NetworkOperation, NetworkTarget, NetworkViolation, ProcessExit,
        ProcessExitReason, ProcessOperation, ProcessViolation, RecoveryArtifact, RegistryOperation,
        RegistryViolation, SandboxEvent,
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
    fn evt_001_all_security_event_families_round_trip_as_typed_events() {
        let events = [
            SandboxEvent::FilesystemViolation(FilesystemViolation {
                process_id: 101,
                operation: FilesystemOperation::Write,
                path: PathBuf::from(r"C:\workspace\denied-文件.txt"),
            }),
            SandboxEvent::RegistryViolation(RegistryViolation {
                process_id: 102,
                operation: RegistryOperation::SetValue,
                key: r"HKEY_CURRENT_USER\Software\Denied".to_owned(),
            }),
            SandboxEvent::NetworkViolation(NetworkViolation {
                process_id: 103,
                operation: NetworkOperation::Connect,
                target: NetworkTarget::Socket(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    8443,
                )),
            }),
            SandboxEvent::RecoveryArtifactCreated(RecoveryArtifact {
                process_id: 104,
                artifact_id: 55,
                original_path: PathBuf::from(r"C:\workspace\changed.txt"),
                byte_count: 4096,
            }),
            SandboxEvent::ChildInjectionFailed(ChildInjectionFailure {
                parent_process_id: 105,
                child_process_id: 106,
                reason: ChildInjectionFailureReason::HandshakeFailed,
            }),
            SandboxEvent::ProcessViolation(ProcessViolation {
                process_id: 107,
                operation: ProcessOperation::CreateWithLogon,
            }),
        ];

        for (sequence, event) in (10_u64..).zip(events) {
            let encoded = encode_event(&event, sequence).expect("typed event must encode");
            let decoded = decode_event(&encoded).expect("typed event must decode");

            assert_eq!(decoded.sequence, sequence);
            assert_eq!(decoded.event, event);
        }
    }

    #[test]
    fn evt_001_domain_network_violation_round_trips_without_stringly_typed_socket() {
        let event = SandboxEvent::NetworkViolation(NetworkViolation {
            process_id: 22,
            operation: NetworkOperation::Resolve,
            target: NetworkTarget::Domain("xn--bcher-kva.example".to_owned()),
        });

        let encoded = encode_event(&event, 2).expect("domain event must encode");
        let decoded = decode_event(&encoded).expect("domain event must decode");

        assert_eq!(decoded.event, event);
    }

    #[test]
    fn proc_014_all_child_injection_failure_reasons_round_trip_without_command_data() {
        for reason in [
            ChildInjectionFailureReason::UnsupportedArchitecture,
            ChildInjectionFailureReason::PolicyUnavailable,
            ChildInjectionFailureReason::InjectionFailed,
            ChildInjectionFailureReason::HandshakeFailed,
        ] {
            let event = SandboxEvent::ChildInjectionFailed(ChildInjectionFailure {
                parent_process_id: 1,
                child_process_id: 2,
                reason,
            });
            let encoded = encode_event(&event, 3).expect("child failure must encode");

            assert_eq!(
                decode_event(&encoded)
                    .expect("child failure must decode")
                    .event,
                event
            );
        }
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

    #[test]
    fn proc_027_unknown_process_operation_is_rejected() {
        let event = SandboxEvent::ProcessViolation(ProcessViolation {
            process_id: 99,
            operation: ProcessOperation::CreateWithToken,
        });
        let mut encoded = encode_event(&event, 1).expect("event must encode");
        encoded[framing::HEADER_LENGTH + 4] = u8::MAX;
        framing::rewrite_checksum(&mut encoded);

        assert_eq!(decode_event(&encoded), Err(ProtocolError::InvalidPayload));
    }

    #[test]
    fn proc_027_process_violation_with_trailing_data_is_rejected() {
        let encoded = framing::encode(&framing::Frame {
            version: framing::PROTOCOL_VERSION,
            kind: framing::FrameKind::ProcessViolation,
            sequence: 1,
            payload: vec![0; 6],
        })
        .expect("structurally valid frame must encode");

        assert_eq!(decode_event(&encoded), Err(ProtocolError::InvalidPayload));
    }

    #[test]
    fn proc_020_all_process_violation_operations_round_trip() {
        for operation in [
            ProcessOperation::CreateWithToken,
            ProcessOperation::CreateWithLogon,
            ProcessOperation::Elevation,
        ] {
            let event = SandboxEvent::ProcessViolation(ProcessViolation {
                process_id: 99,
                operation,
            });
            let encoded = encode_event(&event, 7).expect("event must encode");

            assert_eq!(
                decode_event(&encoded).expect("event must decode").event,
                event
            );
        }
    }
}
