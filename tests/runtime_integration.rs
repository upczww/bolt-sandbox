use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, time::Duration};

use bolt_sandbox::{
    ExecutionTerminal, ProcessExitReason, ReceiverLoss, Sandbox, SandboxConfig, SandboxEvent,
    SandboxPolicy, SandboxRequest,
};

const STREAM_BYTES: usize = 256 * 1_024;

#[test]
fn life_012_public_runtime_transports_arbitrary_binary_stdout_and_stderr() {
    assert_dual_stream_execution("--dual-stream-writer");
}

#[test]
fn proc_002_descendant_inherits_generic_binary_stdout_and_stderr() {
    assert_dual_stream_execution("--descendant-dual-stream-writer");
}

fn assert_dual_stream_execution(mode: &str) {
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let program = component_root.join("bolt-sandbox-native-tests.exe");
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: component_root.clone(),
        credential_environment_variables: Vec::new(),
        stream_capacity: 512 * 1_024,
    })
    .expect("native component root must be valid");
    let mut handle = sandbox
        .start(SandboxRequest {
            program,
            arguments: vec![
                OsString::from(mode),
                OsString::from(STREAM_BYTES.to_string()),
            ],
            cwd: component_root,
            environment: BTreeMap::new(),
            policy: SandboxPolicy::default(),
            timeout: Some(Duration::from_secs(10)),
        })
        .expect("generic native target must start sandboxed");

    let stdout_stream = handle.take_stdout().expect("stdout is available");
    let stderr_stream = handle.take_stderr().expect("stderr is available");
    let event_stream = handle.take_events().expect("events are available");
    let (stdout, stderr, events, result) = std::thread::scope(|scope| {
        let stdout = scope.spawn(move || stdout_stream.flatten().collect::<Vec<_>>());
        let stderr = scope.spawn(move || stderr_stream.flatten().collect::<Vec<_>>());
        let events = scope.spawn(move || event_stream.collect::<Vec<_>>());
        let result = handle.wait().expect("execution must complete");
        (
            stdout.join().expect("stdout reader must not panic"),
            stderr.join().expect("stderr reader must not panic"),
            events.join().expect("event reader must not panic"),
            result,
        )
    });

    assert_pattern(&stdout, false);
    assert_pattern(&stderr, true);
    assert_eq!(events.first(), Some(&SandboxEvent::Ready));
    assert!(matches!(
        events.last(),
        Some(SandboxEvent::ProcessExited(_))
    ));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit)
            if exit.exit_code == Some(0) && exit.reason == ProcessExitReason::Exited
    ));
    assert_eq!(result.receiver_loss, ReceiverLoss::default());
}

fn assert_pattern(bytes: &[u8], stderr_stream: bool) {
    assert_eq!(bytes.len(), STREAM_BYTES);
    for (offset, actual) in bytes.iter().copied().enumerate() {
        let value = u8::try_from(offset % 251).expect("pattern value fits");
        let expected = if stderr_stream {
            0xff_u8.wrapping_sub(value)
        } else {
            value
        };
        assert_eq!(actual, expected, "stream mismatch at byte {offset}");
    }
}

#[test]
fn life_003_timeout_drains_streams_and_emits_one_terminal_event() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let mut handle = sandbox
        .start(blocking_request(
            &component_root,
            Some(Duration::from_millis(100)),
        ))
        .expect("blocking target must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (stdout, stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert_eq!(stdout, b"ready");
    assert!(stderr.is_empty());
    assert_eq!(terminal_reasons(&events), vec![ProcessExitReason::TimedOut]);
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit)
            if exit.exit_code.is_none() && exit.reason == ProcessExitReason::TimedOut
    ));
}

#[test]
fn life_005_cancel_drains_streams_and_emits_one_terminal_event() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let mut handle = sandbox
        .start(blocking_request(&component_root, None))
        .expect("blocking target must start");
    let mut stdout = handle.take_stdout().expect("stdout is available");
    assert_eq!(stdout.next().as_deref(), Some(&b"ready"[..]));
    handle
        .cancel()
        .expect("running execution must accept cancellation");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (remaining_stdout, stderr, events, result) =
        collect_execution(handle, stdout, stderr, events);

    assert!(remaining_stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        terminal_reasons(&events),
        vec![ProcessExitReason::Terminated]
    );
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit)
            if exit.exit_code.is_none() && exit.reason == ProcessExitReason::Terminated
    ));
}

fn configured_sandbox() -> Option<(Sandbox, PathBuf)> {
    let component_root = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)?;
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: component_root.clone(),
        credential_environment_variables: Vec::new(),
        stream_capacity: 512 * 1_024,
    })
    .expect("native component root must be valid");
    Some((sandbox, component_root))
}

fn blocking_request(component_root: &PathBuf, timeout: Option<Duration>) -> SandboxRequest {
    SandboxRequest {
        program: component_root.join("bolt-sandbox-native-tests.exe"),
        arguments: vec![OsString::from("--blocking-stream-fixture")],
        cwd: component_root.clone(),
        environment: BTreeMap::new(),
        policy: SandboxPolicy::default(),
        timeout,
    }
}

fn collect_execution(
    handle: bolt_sandbox::ExecutionHandle,
    stdout: bolt_sandbox::ByteStream,
    stderr: bolt_sandbox::ByteStream,
    events: bolt_sandbox::EventStream,
) -> (
    Vec<u8>,
    Vec<u8>,
    Vec<SandboxEvent>,
    bolt_sandbox::ExecutionResult,
) {
    std::thread::scope(|scope| {
        let stdout = scope.spawn(move || stdout.flatten().collect::<Vec<_>>());
        let stderr = scope.spawn(move || stderr.flatten().collect::<Vec<_>>());
        let events = scope.spawn(move || events.collect::<Vec<_>>());
        let result = handle.wait().expect("execution must complete");
        (
            stdout.join().expect("stdout reader must not panic"),
            stderr.join().expect("stderr reader must not panic"),
            events.join().expect("event reader must not panic"),
            result,
        )
    })
}

fn terminal_reasons(events: &[SandboxEvent]) -> Vec<ProcessExitReason> {
    events
        .iter()
        .filter_map(|event| match event {
            SandboxEvent::ProcessExited(exit) => Some(exit.reason),
            _ => None,
        })
        .collect()
}
