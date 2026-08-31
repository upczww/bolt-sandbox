use std::{
    io::{Read, Write},
    os::windows::ffi::OsStrExt,
    process::{Child, ChildStdout, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError, SyncSender, TryRecvError, TrySendError},
    thread,
    time::{Duration, Instant},
};

use crate::{
    ExecutionHandle, ExecutionResult, ExecutionTerminal, InitializationStage, ProcessExit,
    ProcessExitReason, ReceiverLoss, SandboxError, SandboxEvent,
};

use super::{
    launcher_protocol::{self, LauncherStartRequest},
    launcher_transport::{self, TransportFrame, TransportKind},
    preparation::PreparedLaunch,
};

const ACK_LENGTH: usize = 12;
const ACK_LENGTH_U16: u16 = 12;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn start(
    prepared: &PreparedLaunch,
    stream_capacity: usize,
) -> Result<ExecutionHandle, SandboxError> {
    let (launcher, process_id, transport) = spawn_and_acknowledge(prepared)?;
    Ok(build_execution_handle(
        launcher,
        transport,
        process_id,
        prepared.timeout(),
        stream_capacity,
        *prepared.handshake_nonce(),
    ))
}

fn spawn_and_acknowledge(
    prepared: &PreparedLaunch,
) -> Result<(Child, u32, ChildStdout), SandboxError> {
    let request = encode_request(prepared)?;
    let mut launcher = Command::new(prepared.launcher_component_path())
        .arg("--stdio-session")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| initialization_failure())?;
    let mut stdin = launcher.stdin.take().ok_or_else(initialization_failure)?;
    stdin
        .write_all(&request)
        .and_then(|()| stdin.flush())
        .map_err(|_| {
            terminate_launcher(&mut launcher);
            initialization_failure()
        })?;
    drop(stdin);
    let stdout = launcher.stdout.take().ok_or_else(|| {
        terminate_launcher(&mut launcher);
        initialization_failure()
    })?;
    let (ack_sender, ack_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut stdout = stdout;
        let mut acknowledgment = [0_u8; ACK_LENGTH];
        let result = stdout
            .read_exact(&mut acknowledgment)
            .map(|()| (acknowledgment, stdout))
            .map_err(|error| error.kind());
        let _ = ack_sender.send(result);
    });
    let (acknowledgment, transport) = match ack_receiver.recv_timeout(STARTUP_TIMEOUT) {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected | RecvTimeoutError::Timeout) => {
            terminate_launcher(&mut launcher);
            return Err(initialization_failure());
        }
    };
    let process_id = decode_acknowledgment(&acknowledgment).ok_or_else(|| {
        terminate_launcher(&mut launcher);
        initialization_failure()
    })?;
    Ok((launcher, process_id, transport))
}

fn build_execution_handle(
    mut launcher: Child,
    transport: ChildStdout,
    process_id: u32,
    timeout: Option<Duration>,
    stream_capacity: usize,
    nonce: [u8; 16],
) -> ExecutionHandle {
    let chunk_slots = stream_capacity.div_ceil(4_096).max(1);
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(chunk_slots);
    let (stderr_sender, stderr_receiver) = mpsc::sync_channel(chunk_slots);
    let (event_sender, event_receiver) = mpsc::sync_channel(64);
    let (cancel_sender, cancel_receiver) = mpsc::channel();
    let (completion_sender, completion_receiver) = mpsc::sync_channel(1);
    let (transport_sender, transport_receiver) = mpsc::channel();
    thread::spawn(move || read_transport(transport, &transport_sender));
    thread::spawn(move || {
        let result = run_execution(
            &mut launcher,
            process_id,
            timeout,
            nonce,
            &cancel_receiver,
            &transport_receiver,
            &stdout_sender,
            &stderr_sender,
            &event_sender,
        );
        let _ = completion_sender.send(Ok(result));
    });
    ExecutionHandle::new(
        process_id,
        stdout_receiver,
        stderr_receiver,
        event_receiver,
        cancel_sender,
        completion_receiver,
    )
}

fn read_transport(
    mut transport: ChildStdout,
    sender: &mpsc::Sender<Result<Option<TransportFrame>, launcher_transport::TransportError>>,
) {
    loop {
        match launcher_transport::read_frame(&mut transport) {
            Ok(Some(frame)) => {
                if sender.send(Ok(Some(frame))).is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(Ok(None));
                return;
            }
            Err(error) => {
                let _ = sender.send(Err(error));
                return;
            }
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the worker owns each independent public execution channel"
)]
fn run_execution(
    launcher: &mut Child,
    process_id: u32,
    timeout: Option<Duration>,
    nonce: [u8; 16],
    cancel: &mpsc::Receiver<()>,
    transport: &mpsc::Receiver<Result<Option<TransportFrame>, launcher_transport::TransportError>>,
    stdout: &SyncSender<Vec<u8>>,
    stderr: &SyncSender<Vec<u8>>,
    events: &SyncSender<SandboxEvent>,
) -> ExecutionResult {
    let started = Instant::now();
    let mut state = TransportState::new(nonce);
    loop {
        match cancel.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                terminate_launcher(launcher);
                return state.forced_result(process_id, ProcessExitReason::Terminated);
            }
            Err(TryRecvError::Empty) => {}
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            terminate_launcher(launcher);
            return state.forced_result(process_id, ProcessExitReason::TimedOut);
        }
        match transport.recv_timeout(POLL_INTERVAL) {
            Ok(Ok(Some(frame))) => {
                if state.dispatch(frame, stdout, stderr, events).is_err() {
                    terminate_launcher(launcher);
                    return state
                        .infrastructure_result(crate::InfrastructureFailure::ProtocolIntegrity);
                }
            }
            Ok(Ok(None)) => state.transport_eof = true,
            Ok(Err(_)) => {
                terminate_launcher(launcher);
                return state
                    .infrastructure_result(crate::InfrastructureFailure::ProtocolIntegrity);
            }
            Err(RecvTimeoutError::Disconnected) => {
                if !state.transport_eof {
                    terminate_launcher(launcher);
                    return state
                        .infrastructure_result(crate::InfrastructureFailure::ProtocolIntegrity);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        match launcher.try_wait() {
            Ok(Some(_)) => state.launcher_exited = true,
            Ok(None) => {}
            Err(_) => {
                terminate_launcher(launcher);
                return state.infrastructure_result(crate::InfrastructureFailure::LauncherExited);
            }
        }
        if state.launcher_exited && state.transport_eof {
            return state.completed_result(process_id, events);
        }
    }
}

struct TransportState {
    session: crate::ipc::session::SessionProtocol,
    process_exit: Option<ProcessExit>,
    stream_eof: StreamEofState,
    transport_eof: bool,
    launcher_exited: bool,
    receiver_loss: ReceiverLoss,
}

#[derive(Default)]
struct StreamEofState {
    stdout: bool,
    stderr: bool,
    events: bool,
}

impl TransportState {
    fn new(nonce: [u8; 16]) -> Self {
        Self {
            session: crate::ipc::session::SessionProtocol::new(nonce),
            process_exit: None,
            stream_eof: StreamEofState::default(),
            transport_eof: false,
            launcher_exited: false,
            receiver_loss: ReceiverLoss::default(),
        }
    }

    fn dispatch(
        &mut self,
        frame: TransportFrame,
        stdout: &SyncSender<Vec<u8>>,
        stderr: &SyncSender<Vec<u8>>,
        events: &SyncSender<SandboxEvent>,
    ) -> Result<(), ()> {
        match frame.kind {
            TransportKind::Stdout => {
                send_bounded(stdout, frame.payload, &mut self.receiver_loss.stdout);
            }
            TransportKind::Stderr => {
                send_bounded(stderr, frame.payload, &mut self.receiver_loss.stderr);
            }
            TransportKind::Event => {
                let event = self.session.accept(&frame.payload).map_err(|_| ())?;
                send_bounded(events, event, &mut self.receiver_loss.events);
            }
            TransportKind::StdoutEof => self.stream_eof.stdout = empty_eof(&frame.payload)?,
            TransportKind::StderrEof => self.stream_eof.stderr = empty_eof(&frame.payload)?,
            TransportKind::EventEof => self.stream_eof.events = empty_eof(&frame.payload)?,
            TransportKind::ProcessExit => {
                if self.process_exit.is_some() {
                    return Err(());
                }
                self.process_exit = Some(decode_process_exit(&frame.payload)?);
            }
            TransportKind::InfrastructureFailure => return Err(()),
        }
        Ok(())
    }

    fn forced_result(&self, process_id: u32, reason: ProcessExitReason) -> ExecutionResult {
        let process_exit = ProcessExit {
            process_id,
            exit_code: None,
            reason,
        };
        ExecutionResult {
            terminal: ExecutionTerminal::Process(process_exit),
            receiver_loss: self.receiver_loss,
        }
    }

    fn infrastructure_result(&self, failure: crate::InfrastructureFailure) -> ExecutionResult {
        ExecutionResult {
            terminal: ExecutionTerminal::Infrastructure(failure),
            receiver_loss: self.receiver_loss,
        }
    }

    fn completed_result(
        &mut self,
        expected_process_id: u32,
        events: &SyncSender<SandboxEvent>,
    ) -> ExecutionResult {
        let valid_eof = self.stream_eof.stdout && self.stream_eof.stderr && self.stream_eof.events;
        let Some(process_exit) = self
            .process_exit
            .take()
            .filter(|exit| valid_eof && exit.process_id == expected_process_id)
        else {
            return self.infrastructure_result(crate::InfrastructureFailure::ProtocolIntegrity);
        };
        send_bounded(
            events,
            SandboxEvent::ProcessExited(process_exit.clone()),
            &mut self.receiver_loss.events,
        );
        ExecutionResult {
            terminal: ExecutionTerminal::Process(process_exit),
            receiver_loss: self.receiver_loss,
        }
    }
}

fn send_bounded<T>(sender: &SyncSender<T>, value: T, receiver_lost: &mut bool) {
    match sender.try_send(value) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => *receiver_lost = true,
    }
}

fn empty_eof(payload: &[u8]) -> Result<bool, ()> {
    payload.is_empty().then_some(true).ok_or(())
}

fn decode_process_exit(payload: &[u8]) -> Result<ProcessExit, ()> {
    if payload.len() != 10 || payload[5] > 1 {
        return Err(());
    }
    let process_id = u32::from_le_bytes(payload[..4].try_into().map_err(|_| ())?);
    let reason = match payload[4] {
        0 => ProcessExitReason::Exited,
        1 => ProcessExitReason::Terminated,
        2 => ProcessExitReason::TimedOut,
        3 => ProcessExitReason::Crashed,
        _ => return Err(()),
    };
    let raw_code = u32::from_le_bytes(payload[6..10].try_into().map_err(|_| ())?);
    let exit_code = match payload[5] {
        0 if raw_code == 0 => None,
        1 => Some(raw_code),
        _ => return Err(()),
    };
    if process_id == 0
        || (!matches!(
            reason,
            ProcessExitReason::Exited | ProcessExitReason::Crashed
        ) && exit_code.is_some())
    {
        return Err(());
    }
    Ok(ProcessExit {
        process_id,
        exit_code,
        reason,
    })
}

fn encode_request(prepared: &PreparedLaunch) -> Result<Vec<u8>, SandboxError> {
    let program = encode_path(prepared.program());
    let cwd = encode_path(prepared.cwd());
    let hook = encode_path(prepared.hook_component_path());
    let timeout_milliseconds = prepared
        .timeout()
        .map(|timeout| u64::try_from(timeout.as_millis()))
        .transpose()
        .map_err(|_| initialization_failure())?;
    launcher_protocol::encode_start_request(LauncherStartRequest {
        program: &program,
        cwd: &cwd,
        command_line: prepared.command_line(),
        environment_block: prepared.environment_block(),
        policy: prepared.policy_payload(),
        hook_path: &hook,
        timeout_milliseconds,
        nonce: *prepared.handshake_nonce(),
    })
    .map_err(|_| initialization_failure())
}

fn encode_path(path: &std::path::Path) -> Vec<u16> {
    path.as_os_str().encode_wide().collect()
}

fn decode_acknowledgment(acknowledgment: &[u8; ACK_LENGTH]) -> Option<u32> {
    if acknowledgment[..4] != *b"BLA1"
        || u16::from_le_bytes([acknowledgment[4], acknowledgment[5]]) != 1
        || u16::from_le_bytes([acknowledgment[6], acknowledgment[7]]) != ACK_LENGTH_U16
    {
        return None;
    }
    let process_id = u32::from_le_bytes([
        acknowledgment[8],
        acknowledgment[9],
        acknowledgment[10],
        acknowledgment[11],
    ]);
    (process_id != 0).then_some(process_id)
}

fn terminate_launcher(launcher: &mut Child) {
    let _ = launcher.kill();
    let _ = launcher.wait();
}

fn initialization_failure() -> SandboxError {
    SandboxError::InitializationFailed {
        stage: InitializationStage::LauncherAdapter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_ack_requires_magic_version_length_and_nonzero_pid() {
        let mut acknowledgment = *b"BLA1\x01\x00\x0c\x00\x2a\x00\x00\x00";
        assert_eq!(decode_acknowledgment(&acknowledgment), Some(42));

        acknowledgment[0] ^= 1;
        assert_eq!(decode_acknowledgment(&acknowledgment), None);
        acknowledgment[0] ^= 1;
        acknowledgment[8..12].fill(0);
        assert_eq!(decode_acknowledgment(&acknowledgment), None);
    }
}
