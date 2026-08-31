use std::{io, process::Child};

use crate::{ProcessExit, ProcessExitReason};

use super::streams::{DrainedStreamPair, StreamDrainError, drain_child_streams};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminationExpectation {
    Natural,
    Terminated,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessObservationError {
    MissingStdout,
    MissingStderr,
    Stream(StreamDrainError),
    Wait(io::ErrorKind),
    MissingExitCode,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ObservedProcess {
    pub(super) exit: ProcessExit,
    pub(super) streams: DrainedStreamPair,
}

fn classify_exit(
    process_id: u32,
    exit_code: Option<u32>,
    expectation: TerminationExpectation,
) -> Result<ProcessExit, ProcessObservationError> {
    let (reason, reported_exit_code) = match expectation {
        TerminationExpectation::Terminated => (ProcessExitReason::Terminated, None),
        TerminationExpectation::TimedOut => (ProcessExitReason::TimedOut, None),
        TerminationExpectation::Natural => {
            let code = exit_code.ok_or(ProcessObservationError::MissingExitCode)?;
            let reason = if code & 0xC000_0000 == 0xC000_0000 {
                ProcessExitReason::Crashed
            } else {
                ProcessExitReason::Exited
            };
            (reason, Some(code))
        }
    };
    Ok(ProcessExit {
        process_id,
        exit_code: reported_exit_code,
        reason,
    })
}

fn terminate_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub(super) fn observe_child(
    mut child: Child,
    expectation: TerminationExpectation,
    capacity_per_stream: usize,
) -> Result<ObservedProcess, ProcessObservationError> {
    let process_id = child.id();
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(ProcessObservationError::MissingStdout);
    };
    let Some(stderr) = child.stderr.take() else {
        drop(stdout);
        terminate_and_reap(&mut child);
        return Err(ProcessObservationError::MissingStderr);
    };
    let streams = match drain_child_streams(stdout, stderr, capacity_per_stream) {
        Ok(streams) => streams,
        Err(error) => {
            terminate_and_reap(&mut child);
            return Err(ProcessObservationError::Stream(error));
        }
    };
    let status = child
        .wait()
        .map_err(|error| ProcessObservationError::Wait(error.kind()))?;
    let exit_code = status
        .code()
        .map(|code| u32::from_ne_bytes(code.to_ne_bytes()));
    Ok(ObservedProcess {
        exit: classify_exit(process_id, exit_code, expectation)?,
        streams,
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::ProcessExitReason;
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::Duration,
    };

    const FIXTURE_ENVIRONMENT: &str = "BOLT_LIFE_001_FIXTURE";
    const FIXTURE_TEST: &str = "runtime::process_observer::tests::life_001_process_fixture";

    #[test]
    fn life_001_process_fixture() {
        let Ok(mode) = std::env::var(FIXTURE_ENVIRONMENT) else {
            return;
        };
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(b"fixture-stdout")
            .expect("fixture stdout must be writable");
        stdout.flush().expect("fixture stdout must flush");
        let mut stderr = std::io::stderr().lock();
        stderr
            .write_all(b"fixture-stderr")
            .expect("fixture stderr must be writable");
        stderr.flush().expect("fixture stderr must flush");
        match mode.as_str() {
            "zero" => {}
            "nonzero" => std::process::exit(37),
            "crash" => std::process::abort(),
            "wait" => std::thread::sleep(Duration::from_secs(30)),
            _ => std::process::exit(38),
        }
    }

    fn spawn_fixture(mode: &str) -> std::process::Child {
        Command::new(std::env::current_exe().expect("test executable must resolve"))
            .args(["--exact", FIXTURE_TEST, "--nocapture"])
            .env(FIXTURE_ENVIRONMENT, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("fixture process must start")
    }

    #[test]
    fn life_001_real_exit_kinds_are_observed_after_stream_drain() {
        for (mode, expectation, reason, exit_code) in [
            (
                "zero",
                TerminationExpectation::Natural,
                ProcessExitReason::Exited,
                Some(0),
            ),
            (
                "nonzero",
                TerminationExpectation::Natural,
                ProcessExitReason::Exited,
                Some(37),
            ),
            (
                "crash",
                TerminationExpectation::Natural,
                ProcessExitReason::Crashed,
                None,
            ),
        ] {
            let observed = observe_child(spawn_fixture(mode), expectation, 1 << 20)
                .expect("fixture must be observed");
            assert_eq!(observed.exit.reason, reason);
            if let Some(expected) = exit_code {
                assert_eq!(observed.exit.exit_code, Some(expected));
            } else {
                assert!(
                    observed
                        .exit
                        .exit_code
                        .is_some_and(|code| code & 0xC000_0000 == 0xC000_0000)
                );
            }
            assert!(
                observed
                    .streams
                    .stdout
                    .bytes
                    .windows(b"fixture-stdout".len())
                    .any(|window| window == b"fixture-stdout")
            );
            assert!(
                observed
                    .streams
                    .stderr
                    .bytes
                    .windows(b"fixture-stderr".len())
                    .any(|window| window == b"fixture-stderr")
            );
        }
    }

    #[test]
    fn life_001_forced_and_timed_out_processes_use_committed_reason() {
        for (expectation, reason) in [
            (
                TerminationExpectation::Terminated,
                ProcessExitReason::Terminated,
            ),
            (
                TerminationExpectation::TimedOut,
                ProcessExitReason::TimedOut,
            ),
        ] {
            let mut child = spawn_fixture("wait");
            child.kill().expect("fixture must be terminable");
            let observed = observe_child(child, expectation, 1 << 20)
                .expect("terminated fixture must be observed");
            assert_eq!(observed.exit.reason, reason);
            assert_eq!(observed.exit.exit_code, None);
        }
    }
}
