use std::{
    io::{Read, Write},
    os::windows::ffi::OsStrExt,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, RecvTimeoutError, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use crate::{
    ExecutionHandle, ExecutionResult, ExecutionTerminal, InitializationStage, ProcessExit,
    ProcessExitReason, ReceiverLoss, SandboxError, SandboxEvent,
};

use super::{
    launcher_protocol::{self, LauncherStartRequest},
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
    let (launcher, process_id) = spawn_and_acknowledge(prepared)?;
    Ok(build_execution_handle(
        launcher,
        process_id,
        prepared.timeout(),
        stream_capacity,
    ))
}

fn spawn_and_acknowledge(prepared: &PreparedLaunch) -> Result<(Child, u32), SandboxError> {
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
            .map(|()| acknowledgment)
            .map_err(|error| error.kind());
        let _ = ack_sender.send(result);
    });
    let acknowledgment = match ack_receiver.recv_timeout(STARTUP_TIMEOUT) {
        Ok(Ok(acknowledgment)) => acknowledgment,
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected | RecvTimeoutError::Timeout) => {
            terminate_launcher(&mut launcher);
            return Err(initialization_failure());
        }
    };
    let process_id = decode_acknowledgment(&acknowledgment).ok_or_else(|| {
        terminate_launcher(&mut launcher);
        initialization_failure()
    })?;
    Ok((launcher, process_id))
}

fn build_execution_handle(
    mut launcher: Child,
    process_id: u32,
    timeout: Option<Duration>,
    stream_capacity: usize,
) -> ExecutionHandle {
    let chunk_slots = stream_capacity.div_ceil(4_096).max(1);
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(chunk_slots);
    let (stderr_sender, stderr_receiver) = mpsc::sync_channel(chunk_slots);
    let (event_sender, event_receiver) = mpsc::sync_channel(64);
    let (cancel_sender, cancel_receiver) = mpsc::channel();
    let (completion_sender, completion_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = event_sender.send(SandboxEvent::Ready);
        let started = Instant::now();
        let (reason, status) = loop {
            match cancel_receiver.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => {
                    terminate_launcher(&mut launcher);
                    break (ProcessExitReason::Terminated, None);
                }
                Err(TryRecvError::Empty) => {}
            }
            if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                terminate_launcher(&mut launcher);
                break (ProcessExitReason::TimedOut, None);
            }
            match launcher.try_wait() {
                Ok(Some(status)) => break (classify_status(status), Some(status)),
                Ok(None) => thread::sleep(POLL_INTERVAL),
                Err(_) => {
                    terminate_launcher(&mut launcher);
                    let result = ExecutionResult {
                        terminal: ExecutionTerminal::Infrastructure(
                            crate::InfrastructureFailure::LauncherExited,
                        ),
                        receiver_loss: ReceiverLoss {
                            stdout: true,
                            stderr: true,
                            events: false,
                        },
                    };
                    drop(stdout_sender);
                    drop(stderr_sender);
                    let _ = completion_sender.send(Ok(result));
                    return;
                }
            }
        };
        let exit_code = status.and_then(exit_code);
        let process_exit = ProcessExit {
            process_id,
            exit_code: if matches!(
                reason,
                ProcessExitReason::Exited | ProcessExitReason::Crashed
            ) {
                exit_code
            } else {
                None
            },
            reason,
        };
        let _ = event_sender.send(SandboxEvent::ProcessExited(process_exit.clone()));
        drop(event_sender);
        drop(stdout_sender);
        drop(stderr_sender);
        let _ = completion_sender.send(Ok(ExecutionResult {
            terminal: ExecutionTerminal::Process(process_exit),
            receiver_loss: ReceiverLoss {
                stdout: true,
                stderr: true,
                events: false,
            },
        }));
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

fn classify_status(status: ExitStatus) -> ProcessExitReason {
    exit_code(status).map_or(ProcessExitReason::Crashed, |code| {
        if code & 0xC000_0000 == 0xC000_0000 {
            ProcessExitReason::Crashed
        } else {
            ProcessExitReason::Exited
        }
    })
}

fn exit_code(status: ExitStatus) -> Option<u32> {
    status
        .code()
        .map(|code| u32::from_ne_bytes(code.to_ne_bytes()))
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
