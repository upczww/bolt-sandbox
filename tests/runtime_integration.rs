use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, time::Duration};

use bolt_sandbox::{
    ExecutionTerminal, ProcessExitReason, ReceiverLoss, Sandbox, SandboxConfig, SandboxEvent,
    SandboxPolicy, SandboxRequest,
};

const STREAM_BYTES: usize = 256 * 1_024;

#[test]
fn life_012_public_runtime_transports_arbitrary_binary_stdout_and_stderr() {
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
                OsString::from("--dual-stream-writer"),
                OsString::from(STREAM_BYTES.to_string()),
            ],
            cwd: component_root,
            environment: BTreeMap::new(),
            policy: SandboxPolicy::default(),
            timeout: Some(Duration::from_secs(10)),
        })
        .expect("generic native target must start sandboxed");

    let stdout = handle
        .take_stdout()
        .expect("stdout is available")
        .flatten()
        .collect::<Vec<_>>();
    let stderr = handle
        .take_stderr()
        .expect("stderr is available")
        .flatten()
        .collect::<Vec<_>>();
    let events = handle
        .take_events()
        .expect("events are available")
        .collect::<Vec<_>>();
    let result = handle.wait().expect("execution must complete");

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
