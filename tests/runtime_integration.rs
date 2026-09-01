use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use bolt_sandbox::{
    AttributedSandboxEvent, ExecutionOptions, ExecutionTerminal, InfrastructureFailure,
    ProcessExitReason, PseudoConsoleSize, ReceiverLoss, RecoveryFailureReason, RecoveryLimits,
    RecoveryPolicy, Sandbox, SandboxConfig, SandboxEvent, SandboxPolicy, SandboxRequest,
    TerminalMode, WorkspaceChangeKind, WorkspaceControlError, WorkspaceLimits, WorkspaceMode,
};

const STREAM_BYTES: usize = 256 * 1_024;
static NEXT_RECOVERY_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[test]
fn ws_016_staged_execution_requires_explicit_trusted_commit() {
    let Some((sandbox, _component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let source = std::env::temp_dir().join(format!(
        "bolt-sandbox-staged-public-{}-{fixture_id}",
        std::process::id()
    ));
    fs::create_dir_all(&source).expect("source must create");
    fs::write(source.join("file.txt"), b"before").expect("source must seed");
    let command = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join(r"System32\cmd.exe");
    let request = SandboxRequest {
        program: command,
        arguments: vec![
            OsString::from("/d"),
            OsString::from("/c"),
            OsString::from("echo after>file.txt"),
        ],
        cwd: source.clone(),
        environment: BTreeMap::new(),
        policy: SandboxPolicy::default(),
        timeout: Some(Duration::from_secs(5)),
    };
    let mut handle = sandbox
        .start_with_options(
            request,
            ExecutionOptions {
                workspace: WorkspaceMode::Staged,
                ..ExecutionOptions::default()
            },
        )
        .expect("staged execution must start");
    let stdout = handle.take_stdout().expect("stdout");
    let stderr = handle.take_stderr().expect("stderr");
    let events = handle.take_events().expect("events");
    let (_stdout, _stderr, _events, result) = collect_execution(handle, stdout, stderr, events);

    assert_eq!(
        fs::read(source.join("file.txt")).expect("source"),
        b"before"
    );
    let transaction = result
        .workspace_transaction
        .expect("staged result must return transaction ID");
    let changes = sandbox
        .query_workspace_changes(transaction)
        .expect("changes must query");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, WorkspaceChangeKind::Modified);
    sandbox
        .commit_workspace(transaction)
        .expect("trusted commit must succeed");
    assert!(
        String::from_utf8_lossy(&fs::read(source.join("file.txt")).expect("committed source"))
            .contains("after")
    );
    sandbox
        .revert_workspace(transaction)
        .expect("trusted revert must succeed");
    assert_eq!(
        fs::read(source.join("file.txt")).expect("reverted source"),
        b"before"
    );
    fs::remove_dir_all(source).expect("fixture must clean");
}

#[test]
fn ws_005_projected_mode_never_falls_back_when_optional_component_is_unavailable() {
    let Some((sandbox, _component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture = std::env::temp_dir().join(format!(
        "bolt-sandbox-projected-{}-{fixture_id}",
        std::process::id()
    ));
    let source = fixture.join("source");
    fs::create_dir_all(&source).expect("source must create");
    fs::write(source.join("baseline.txt"), b"before").expect("source must seed");
    let system_root = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
    let command = system_root.join(r"System32\cmd.exe");
    let component_available = system_root.join(r"System32\ProjectedFSLib.dll").is_file();
    let projected_cold_started = Instant::now();
    let started = sandbox.start_with_options(
        SandboxRequest {
            program: command,
            arguments: vec![
                OsString::from("/d"),
                OsString::from("/c"),
                OsString::from("echo projected>created.txt"),
            ],
            cwd: source.clone(),
            environment: BTreeMap::new(),
            policy: SandboxPolicy::default(),
            timeout: Some(Duration::from_secs(5)),
        },
        ExecutionOptions {
            workspace: WorkspaceMode::Projected,
            ..ExecutionOptions::default()
        },
    );

    match started {
        Err(error) => {
            assert!(
                !component_available,
                "available ProjFS must start projection"
            );
            assert!(matches!(
                error,
                bolt_sandbox::SandboxError::InitializationFailed {
                    stage: bolt_sandbox::InitializationStage::Workspace
                }
            ));
            assert!(!source.join("created.txt").exists());
            assert_eq!(
                fs::read_dir(&fixture).expect("fixture must remain").count(),
                1,
                "failed projection must not leave session roots"
            );
        }
        Ok(handle) => {
            assert!(
                component_available,
                "projection cannot bypass missing ProjFS"
            );
            assert!(
                projected_cold_started.elapsed() <= Duration::from_millis(250),
                "cold projected startup must stay within 250 ms"
            );
            let result = handle.wait().expect("projected execution must finish");
            let transaction = result
                .workspace_transaction
                .expect("projected execution must return transaction");
            assert!(!source.join("created.txt").exists());
            sandbox
                .commit_workspace(transaction)
                .expect("trusted projected commit must succeed");
            assert!(source.join("created.txt").is_file());
            assert_warm_projected_budget(&sandbox, &source, &system_root);
        }
    }
    fs::remove_dir_all(fixture).expect("fixture must clean");
}

fn assert_warm_projected_budget(sandbox: &Sandbox, source: &Path, system_root: &Path) {
    let started = Instant::now();
    let handle = sandbox
        .start_with_options(
            SandboxRequest {
                program: system_root.join(r"System32\cmd.exe"),
                arguments: vec![
                    OsString::from("/d"),
                    OsString::from("/c"),
                    OsString::from("exit 0"),
                ],
                cwd: source.to_path_buf(),
                environment: BTreeMap::new(),
                policy: SandboxPolicy::default(),
                timeout: Some(Duration::from_secs(5)),
            },
            ExecutionOptions {
                workspace: WorkspaceMode::Projected,
                ..ExecutionOptions::default()
            },
        )
        .expect("warm projected execution must start");
    assert!(
        started.elapsed() <= Duration::from_millis(100),
        "warm projected dispatch must stay within 100 ms"
    );
    let transaction = handle
        .wait()
        .expect("warm projected execution must finish")
        .workspace_transaction
        .expect("warm projected execution must return transaction");
    sandbox
        .discard_workspace(transaction)
        .expect("warm projected transaction must discard");
}

#[test]
fn ws_021_staged_execution_rejects_sensitive_descendant_before_copy_or_launch() {
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture = std::env::temp_dir().join(format!(
        "bolt-sandbox-staged-sensitive-{}-{fixture_id}",
        std::process::id()
    ));
    let source = fixture.join("source");
    let protected = source.join("protected");
    fs::create_dir_all(&protected).expect("protected source must create");
    fs::write(protected.join("credential.bin"), b"must-not-copy")
        .expect("protected source must seed");
    let sandbox = Sandbox::new(SandboxConfig {
        component_root,
        credential_environment_variables: Vec::new(),
        stream_capacity: 512 * 1_024,
        violation_aggregate_capacity: bolt_sandbox::DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: vec![protected],
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .expect("sandbox configuration must be valid");
    let command = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join(r"System32\cmd.exe");

    let Err(error) = sandbox.start_with_options(
        SandboxRequest {
            program: command,
            arguments: vec![
                OsString::from("/d"),
                OsString::from("/c"),
                OsString::from("exit 0"),
            ],
            cwd: source.clone(),
            environment: BTreeMap::new(),
            policy: SandboxPolicy::default(),
            timeout: Some(Duration::from_secs(5)),
        },
        ExecutionOptions {
            workspace: WorkspaceMode::Staged,
            ..ExecutionOptions::default()
        },
    ) else {
        panic!("sensitive descendant must reject staged execution");
    };

    assert!(matches!(
        error,
        bolt_sandbox::SandboxError::InitializationFailed {
            stage: bolt_sandbox::InitializationStage::Workspace
        }
    ));
    assert_eq!(
        fs::read_dir(&fixture).expect("fixture must remain").count(),
        1,
        "no staging or recovery directory may be created"
    );
    fs::remove_dir_all(fixture).expect("fixture must clean");
}

#[test]
fn rec_021_completed_staged_transaction_expires_and_removes_session_state() {
    let Some((sandbox, _component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture = std::env::temp_dir().join(format!(
        "bolt-sandbox-staged-retention-{}-{fixture_id}",
        std::process::id()
    ));
    let source = fixture.join("source");
    fs::create_dir_all(&source).expect("source must create");
    fs::write(source.join("file.txt"), b"before").expect("source must seed");
    let command = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join(r"System32\cmd.exe");
    let handle = sandbox
        .start_with_options(
            SandboxRequest {
                program: command,
                arguments: vec![
                    OsString::from("/d"),
                    OsString::from("/c"),
                    OsString::from("exit 0"),
                ],
                cwd: source,
                environment: BTreeMap::new(),
                policy: SandboxPolicy::default(),
                timeout: Some(Duration::from_secs(5)),
            },
            ExecutionOptions {
                workspace: WorkspaceMode::Staged,
                workspace_limits: WorkspaceLimits {
                    retention: Duration::from_millis(1),
                    ..WorkspaceLimits::default()
                },
                ..ExecutionOptions::default()
            },
        )
        .expect("staged execution must start");
    let transaction = handle
        .wait()
        .expect("execution must finish")
        .workspace_transaction
        .expect("transaction must be retained initially");
    std::thread::sleep(Duration::from_millis(5));

    assert_eq!(
        sandbox.query_workspace_changes(transaction),
        Err(WorkspaceControlError::NotFound)
    );
    assert_eq!(
        fs::read_dir(&fixture).expect("fixture must remain").count(),
        1,
        "expired staging and recovery state must be removed"
    );
    fs::remove_dir_all(fixture).expect("fixture must clean");
}

#[test]
fn ws_018_conflicted_commit_preserves_inspectable_transaction() {
    let Some((sandbox, _component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let source = std::env::temp_dir().join(format!(
        "bolt-sandbox-staged-conflict-{}-{fixture_id}",
        std::process::id()
    ));
    fs::create_dir_all(&source).expect("source must create");
    fs::write(source.join("file.txt"), b"before").expect("source must seed");
    let command = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join(r"System32\cmd.exe");
    let handle = sandbox
        .start_with_options(
            SandboxRequest {
                program: command,
                arguments: vec![
                    OsString::from("/d"),
                    OsString::from("/c"),
                    OsString::from("echo staged>file.txt"),
                ],
                cwd: source.clone(),
                environment: BTreeMap::new(),
                policy: SandboxPolicy::default(),
                timeout: Some(Duration::from_secs(5)),
            },
            ExecutionOptions {
                workspace: WorkspaceMode::Staged,
                ..ExecutionOptions::default()
            },
        )
        .expect("staged execution must start");
    let transaction = handle
        .wait()
        .expect("execution must finish")
        .workspace_transaction
        .expect("transaction must complete");
    fs::write(source.join("file.txt"), b"external").expect("external change must apply");

    assert_eq!(
        sandbox.commit_workspace(transaction),
        Err(WorkspaceControlError::Conflict)
    );
    assert_eq!(
        sandbox
            .query_workspace_changes(transaction)
            .expect("conflicted transaction must remain inspectable")
            .len(),
        1
    );
    sandbox
        .discard_workspace(transaction)
        .expect("conflicted transaction must remain discardable");
    assert_eq!(
        fs::read(source.join("file.txt")).expect("source must remain external version"),
        b"external"
    );
    fs::remove_dir_all(source).expect("fixture must clean");
}

#[test]
fn ws_024_staged_acl_mutation_is_rejected_before_commit() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let source = std::env::temp_dir().join(format!(
        "bolt-sandbox-staged-acl-{}-{fixture_id}",
        std::process::id()
    ));
    fs::create_dir_all(&source).expect("source must create");
    let handle = sandbox
        .start_with_options(
            SandboxRequest {
                program: component_root.join("bolt-sandbox-native-tests.exe"),
                arguments: vec![
                    OsString::from("--workspace-acl-mutation-fixture"),
                    OsString::from("created.txt"),
                ],
                cwd: source.clone(),
                environment: BTreeMap::new(),
                policy: SandboxPolicy::default(),
                timeout: Some(Duration::from_secs(5)),
            },
            ExecutionOptions {
                workspace: WorkspaceMode::Staged,
                ..ExecutionOptions::default()
            },
        )
        .expect("staged ACL fixture must start");
    let result = handle.wait().expect("staged ACL fixture must finish");
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    let transaction = result
        .workspace_transaction
        .expect("staged ACL fixture must return a transaction");

    assert_eq!(
        sandbox.commit_workspace(transaction),
        Err(WorkspaceControlError::Conflict)
    );
    assert!(!source.join("created.txt").exists());
    sandbox
        .discard_workspace(transaction)
        .expect("rejected ACL transaction must remain discardable");
    fs::remove_dir_all(source).expect("fixture must clean");
}

#[test]
fn pty_001_interactive_cmd_accepts_input_resize_and_exits_inside_job() {
    let Some((sandbox, _component_root)) = configured_sandbox() else {
        return;
    };
    let command = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join(r"System32\cmd.exe");
    let initial_size = PseudoConsoleSize::new(80, 24).expect("valid initial size");
    let mut handle = sandbox
        .start_with_options(
            SandboxRequest {
                program: command,
                arguments: vec![OsString::from("/d"), OsString::from("/q")],
                cwd: std::env::temp_dir(),
                environment: BTreeMap::new(),
                policy: SandboxPolicy::default(),
                timeout: Some(Duration::from_secs(5)),
            },
            ExecutionOptions {
                terminal: TerminalMode::PseudoConsole(initial_size),
                ..ExecutionOptions::default()
            },
        )
        .expect("PTY execution must start");
    handle
        .resize_pseudo_console(PseudoConsoleSize::new(100, 30).expect("valid resize"))
        .expect("PTY resize must queue");
    handle
        .write_input(b"echo BOLT_PTY_OK\r\nexit 0\r\n")
        .expect("PTY input must queue");
    let stdout = handle.take_stdout().expect("stdout");
    let stderr = handle.take_stderr().expect("stderr");
    let events = handle.take_events().expect("events");
    let (stdout, stderr, _events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(
        String::from_utf8_lossy(&stdout).contains("BOLT_PTY_OK"),
        "PTY output must contain command marker: {:?}",
        (String::from_utf8_lossy(&stdout), &result)
    );
    assert!(
        stderr.is_empty(),
        "ConPTY combines terminal output on stdout"
    );
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
}

#[test]
fn pty_001_x86_target_accepts_controlled_pseudo_console_input() {
    let Some(component_root) =
        std::env::var_os("BOLT_NATIVE_X86_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: component_root.clone(),
        credential_environment_variables: Vec::new(),
        stream_capacity: 512 * 1_024,
        violation_aggregate_capacity: bolt_sandbox::DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .expect("x86 sandbox configuration must validate");
    let mut handle = sandbox
        .start_with_options(
            SandboxRequest {
                program: component_root.join("bolt-sandbox-native-tests.exe"),
                arguments: vec![OsString::from("--pty-echo-fixture")],
                cwd: std::env::temp_dir(),
                environment: BTreeMap::new(),
                policy: SandboxPolicy::default(),
                timeout: Some(Duration::from_secs(5)),
            },
            ExecutionOptions {
                terminal: TerminalMode::PseudoConsole(
                    PseudoConsoleSize::new(80, 24).expect("valid size"),
                ),
                ..ExecutionOptions::default()
            },
        )
        .expect("x86 PTY execution must start");
    handle
        .resize_pseudo_console(PseudoConsoleSize::new(100, 30).expect("valid resize"))
        .expect("x86 PTY resize must queue");
    handle
        .write_input(b"BOLT_PTY_PING\r\n")
        .expect("x86 PTY input must queue");
    let stdout = handle.take_stdout().expect("stdout");
    let stderr = handle.take_stderr().expect("stderr");
    let events = handle.take_events().expect("events");
    let (stdout, stderr, _events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(
        String::from_utf8_lossy(&stdout).contains("BOLT_PTY_X86_ACK"),
        "x86 PTY target must acknowledge input: {:?}",
        (String::from_utf8_lossy(&stdout), &result)
    );
    assert!(stderr.is_empty());
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
}

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
        violation_aggregate_capacity: bolt_sandbox::DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
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
    assert!(matches!(
        events.first(),
        Some(AttributedSandboxEvent {
            event: SandboxEvent::Ready,
            ..
        })
    ));
    assert!(matches!(
        events.last(),
        Some(AttributedSandboxEvent {
            event: SandboxEvent::ProcessExited(_),
            ..
        })
    ));
    assert!(
        events
            .iter()
            .all(|event| event.attribution == result.attribution)
    );
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
        violation_aggregate_capacity: bolt_sandbox::DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .expect("native component root must be valid");
    Some((sandbox, component_root))
}

fn blocking_request(component_root: &Path, timeout: Option<Duration>) -> SandboxRequest {
    SandboxRequest {
        program: component_root.join("bolt-sandbox-native-tests.exe"),
        arguments: vec![OsString::from("--blocking-stream-fixture")],
        cwd: component_root.to_path_buf(),
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
    Vec<AttributedSandboxEvent>,
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

fn terminal_reasons(events: &[AttributedSandboxEvent]) -> Vec<ProcessExitReason> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            SandboxEvent::ProcessExited(exit) => Some(exit.reason),
            _ => None,
        })
        .collect()
}

#[test]
fn ipc_025_corrupt_event_terminates_and_drains_without_fabricated_exit() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let mut request = blocking_request(&component_root, Some(Duration::from_secs(5)));
    request.arguments = vec![OsString::from("--corrupt-event-fixture")];
    let mut handle = sandbox
        .start(request)
        .expect("corruption fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (stdout, stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert_pattern(&stdout, false);
    assert!(stderr.is_empty());
    assert!(terminal_reasons(&events).is_empty());
    assert_eq!(
        result.terminal,
        ExecutionTerminal::Infrastructure(InfrastructureFailure::ProtocolIntegrity)
    );
}

#[test]
fn ipc_014_event_channel_loss_terminates_job_without_waiting_for_timeout() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let mut request = blocking_request(&component_root, Some(Duration::from_secs(5)));
    request.arguments = vec![OsString::from("--drop-event-channel-fixture")];
    let mut handle = sandbox
        .start(request)
        .expect("event channel loss fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (stdout, stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(terminal_reasons(&events).is_empty());
    assert_eq!(
        result.terminal,
        ExecutionTerminal::Infrastructure(InfrastructureFailure::EventChannelLost)
    );
}

#[test]
fn rec_001_allowed_delete_is_backed_up_and_indexed_before_mutation() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let source = work.join("delete-me.bin");
    let expected = b"recoverable-content";
    fs::write(&source, expected).expect("source fixture must be written");

    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-delete-fixture"),
                source.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(5)),
        })
        .expect("recovery fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(!source.exists());
    let recovered = recovery_files(&recovery);
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read(&recovered[0]).expect("backup must be readable"),
        expected
    );
    assert!(events.iter().any(|event| matches!(
        &event.event,
        SandboxEvent::RecoveryArtifactCreated(artifact)
            if artifact.original_path == source && artifact.byte_count == expected.len() as u64
    )));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("recovery fixture must clean up");
}

fn recovery_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("recovery directory must be readable") {
            let path = entry.expect("recovery entry must be readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().is_some_and(|name| name == "content.bin") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn rec_002_truncate_backs_up_complete_pre_mutation_content() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-truncate-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let source = work.join("truncate-me.bin");
    let expected = b"truncate-complete-content";
    fs::write(&source, expected).expect("source fixture must be written");
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-truncate-fixture"),
                source.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(5)),
        })
        .expect("truncate fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert_eq!(
        fs::read(&source).expect("truncated source must exist"),
        &expected[..4]
    );
    let recovered = recovery_files(&recovery);
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read(&recovered[0]).expect("backup must be readable"),
        expected
    );
    assert!(events.iter().any(|event| matches!(
        &event.event,
        SandboxEvent::RecoveryArtifactCreated(artifact)
            if artifact.original_path == source && artifact.byte_count == expected.len() as u64
    )));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("truncate fixture must clean up");
}

#[test]
fn rec_003_replace_and_overwrite_rename_preserve_destroyed_objects() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-replace-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let replaced = work.join("replaced.bin");
    let replacement = work.join("replacement.bin");
    let move_source = work.join("move-source.bin");
    let move_destination = work.join("move-destination.bin");
    fs::write(&replaced, b"replaced-original").expect("replaced fixture must be written");
    fs::write(&replacement, b"replacement-new").expect("replacement fixture must be written");
    fs::write(&move_source, b"move-new").expect("move source must be written");
    fs::write(&move_destination, b"move-original").expect("move target must be written");
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-replace-rename-fixture"),
                replaced.as_os_str().to_os_string(),
                replacement.as_os_str().to_os_string(),
                move_source.as_os_str().to_os_string(),
                move_destination.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(5)),
        })
        .expect("replace and rename fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert_eq!(
        fs::read(&replaced).expect("replacement must land"),
        b"replacement-new"
    );
    assert_eq!(
        fs::read(&move_destination).expect("move source must land"),
        b"move-new"
    );
    let mut recovered_contents: Vec<Vec<u8>> = recovery_files(&recovery)
        .iter()
        .map(|path| fs::read(path).expect("backup must be readable"))
        .collect();
    recovered_contents.sort();
    assert_eq!(
        recovered_contents,
        vec![b"move-original".to_vec(), b"replaced-original".to_vec()]
    );
    let recovered_paths: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.event {
            SandboxEvent::RecoveryArtifactCreated(artifact) => Some(artifact.original_path.clone()),
            _ => None,
        })
        .collect();
    assert!(recovered_paths.contains(&replaced));
    assert!(recovered_paths.contains(&move_destination));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("replace fixture must clean up");
}

#[test]
fn rec_019_target_cannot_write_directly_to_recovery_channel() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-authority-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let outside = fixture_root.join("outside");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&outside).expect("outside directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let secret = outside.join("not-authorized.bin");
    fs::write(&secret, b"outside-secret").expect("outside fixture must be written");
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--unauthorized-recovery-request-fixture"),
                secret.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(5)),
        })
        .expect("authority fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert_eq!(
        fs::read(&secret).expect("outside source must remain"),
        b"outside-secret"
    );
    assert!(recovery_files(&recovery).is_empty());
    assert!(
        !events
            .iter()
            .any(|event| matches!(&event.event, SandboxEvent::RecoveryArtifactCreated(_)))
    );
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(346)
    ));
    fs::remove_dir_all(fixture_root).expect("authority fixture must clean up");
}

#[test]
fn rec_006_007_exact_quota_succeeds_and_next_byte_reports_typed_failure() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-quota-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let exact = work.join("exact.bin");
    let over = work.join("over.bin");
    fs::write(&exact, b"1234").expect("exact fixture must be written");
    fs::write(&over, b"5").expect("over fixture must be written");
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 4,
            maximum_items: 2,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-delete-two-fixture"),
                exact.as_os_str().to_os_string(),
                over.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(5)),
        })
        .expect("quota fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(!exact.exists());
    assert!(!over.exists());
    let recovered = recovery_files(&recovery);
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read(&recovered[0]).expect("exact backup must exist"),
        b"1234"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.event, SandboxEvent::RecoveryArtifactCreated(_)))
            .count(),
        1
    );
    assert!(events.iter().any(|event| matches!(
        &event.event,
        SandboxEvent::RecoveryFailed(failure)
            if failure.reason == RecoveryFailureReason::QuotaExceeded
    )));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("quota fixture must clean up");
}

#[test]
fn rec_014_handle_delete_and_child_delete_share_execution_recovery() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-child-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let handle_source = work.join("handle-delete.bin");
    let child_source = work.join("child-delete.bin");
    fs::write(&handle_source, b"handle-content").expect("handle fixture must be written");
    fs::write(&child_source, b"child-content").expect("child fixture must be written");
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-handle-child-fixture"),
                handle_source.as_os_str().to_os_string(),
                child_source.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(10)),
        })
        .expect("handle and child fixture must start");
    let root_process_id = handle.process_id();
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(!handle_source.exists());
    assert!(!child_source.exists());
    let mut contents: Vec<_> = recovery_files(&recovery)
        .iter()
        .map(|path| fs::read(path).expect("backup must be readable"))
        .collect();
    contents.sort();
    assert_eq!(
        contents,
        vec![b"child-content".to_vec(), b"handle-content".to_vec()]
    );
    let artifact_processes: Vec<u32> = events
        .iter()
        .filter_map(|event| match &event.event {
            SandboxEvent::RecoveryArtifactCreated(artifact) => Some(artifact.process_id),
            _ => None,
        })
        .collect();
    assert!(artifact_processes.contains(&root_process_id));
    assert!(
        artifact_processes
            .iter()
            .any(|process_id| *process_id != root_process_id)
    );
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("child fixture must clean up");
}

#[test]
fn rec_012_native_disposition_delete_preserves_original_content() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-native-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let source = work.join("native-delete.bin");
    fs::write(&source, b"native-content").expect("native fixture must be written");
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-native-disposition-fixture"),
                source.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(5)),
        })
        .expect("native disposition fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(!source.exists());
    let recovered = recovery_files(&recovery);
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read(&recovered[0]).expect("native backup must be readable"),
        b"native-content"
    );
    assert!(events.iter().any(|event| matches!(
        &event.event,
        SandboxEvent::RecoveryArtifactCreated(artifact)
            if artifact.original_path == source
    )));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("native fixture must clean up");
}

#[test]
fn rec_009_store_failure_is_typed_and_does_not_change_allowed_delete() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-store-failure-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let source = work.join("delete-after-store-loss.bin");
    let signal = work.join("continue.signal");
    fs::write(&source, b"store-failure-content").expect("source fixture must be written");
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-delayed-delete-fixture"),
                source.as_os_str().to_os_string(),
                signal.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(10)),
        })
        .expect("store failure fixture must start");
    let execution_directory = fs::read_dir(&recovery)
        .expect("recovery root must be readable")
        .next()
        .expect("execution directory must exist")
        .expect("execution entry must be readable")
        .path();
    fs::write(
        execution_directory.join("artifact-0000000000000001.partial"),
        b"block artifact directory creation",
    )
    .expect("artifact path blocker must be written");
    fs::write(&signal, b"continue").expect("signal must be written");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert!(!source.exists());
    assert!(recovery_files(&recovery).is_empty());
    assert!(events.iter().any(|event| matches!(
        &event.event,
        SandboxEvent::RecoveryFailed(failure)
            if failure.reason == RecoveryFailureReason::StoreUnavailable
    )));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("store failure fixture must clean up");
}

#[test]
fn pol_007_host_mandatory_deny_overrides_broad_grant_and_recovery() {
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-mandatory-deny-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let protected = fixture_root.join("protected");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&protected).expect("protected directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let source = protected.join("credential.bin");
    fs::write(&source, b"must-remain-secret").expect("protected fixture must be written");
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: component_root.clone(),
        credential_environment_variables: Vec::new(),
        stream_capacity: 512 * 1_024,
        violation_aggregate_capacity: bolt_sandbox::DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: vec![protected.clone()],
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .expect("sandbox configuration must be valid");
    let mut policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    policy.filesystem.read_write.push(fixture_root.clone());
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments: vec![
                OsString::from("--recovery-delete-fixture"),
                source.as_os_str().to_os_string(),
            ],
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(5)),
        })
        .expect("mandatory deny fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, _stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    assert_eq!(
        fs::read(&source).expect("protected source must remain"),
        b"must-remain-secret"
    );
    assert!(recovery_files(&recovery).is_empty());
    assert!(!events.iter().any(|event| matches!(
        &event.event,
        SandboxEvent::RecoveryArtifactCreated(_) | SandboxEvent::RecoveryFailed(_)
    )));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(335)
    ));
    fs::remove_dir_all(fixture_root).expect("mandatory deny fixture must clean up");
}

#[test]
fn rec_013_concurrent_children_commit_unique_consistent_artifacts() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let fixture_id = NEXT_RECOVERY_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "bolt-sandbox-recovery-concurrent-{}-{fixture_id}",
        std::process::id()
    ));
    let work = fixture_root.join("work");
    let recovery = fixture_root.join("recovery");
    fs::create_dir_all(&work).expect("work directory must be created");
    fs::create_dir_all(&recovery).expect("recovery directory must be created");
    let sources: Vec<PathBuf> = (0..4)
        .map(|index| {
            let path = work.join(format!("concurrent-{index}.bin"));
            fs::write(&path, format!("content-{index}"))
                .expect("concurrent source must be written");
            path
        })
        .collect();
    let policy = SandboxPolicy {
        recovery: RecoveryPolicy::Enabled(RecoveryLimits {
            directory: recovery.clone(),
            maximum_bytes: 1_048_576,
            maximum_items: 16,
            retention: Duration::from_secs(24 * 60 * 60),
        }),
        ..SandboxPolicy::default()
    };
    let mut arguments = vec![OsString::from("--recovery-concurrent-children-fixture")];
    arguments.extend(sources.iter().map(|path| path.as_os_str().to_os_string()));
    let mut handle = sandbox
        .start(SandboxRequest {
            program: component_root.join("bolt-sandbox-native-tests.exe"),
            arguments,
            cwd: work,
            environment: BTreeMap::new(),
            policy,
            timeout: Some(Duration::from_secs(15)),
        })
        .expect("concurrent recovery fixture must start");
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (_stdout, stderr, events, result) = collect_execution(handle, stdout, stderr, events);

    let remaining: Vec<_> = sources
        .iter()
        .filter(|path| path.exists())
        .cloned()
        .collect();
    assert!(
        remaining.is_empty(),
        "remaining={remaining:?} result={result:?} events={events:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let mut contents: Vec<_> = recovery_files(&recovery)
        .iter()
        .map(|path| fs::read(path).expect("artifact must be readable"))
        .collect();
    contents.sort();
    assert_eq!(
        contents,
        (0..4)
            .map(|index| format!("content-{index}").into_bytes())
            .collect::<Vec<_>>()
    );
    let mut artifact_ids: Vec<u64> = events
        .iter()
        .filter_map(|event| match &event.event {
            SandboxEvent::RecoveryArtifactCreated(artifact) => Some(artifact.artifact_id),
            _ => None,
        })
        .collect();
    artifact_ids.sort_unstable();
    assert_eq!(artifact_ids, vec![1, 2, 3, 4]);
    assert!(!contains_partial_directory(&recovery));
    assert!(matches!(
        result.terminal,
        ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
    ));
    fs::remove_dir_all(fixture_root).expect("concurrent fixture must clean up");
}

fn contains_partial_directory(root: &Path) -> bool {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("recovery directory must be readable") {
            let path = entry.expect("recovery entry must be readable").path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".partial"))
                {
                    return true;
                }
                pending.push(path);
            }
        }
    }
    false
}

#[test]
fn perf_001_public_warm_startup_stays_below_one_hundred_milliseconds() {
    let Some((sandbox, component_root)) = configured_sandbox() else {
        return;
    };
    let request = SandboxRequest {
        program: component_root.join("bolt-sandbox-native-tests.exe"),
        arguments: vec![OsString::from("--cli-fixture")],
        cwd: component_root,
        environment: BTreeMap::new(),
        policy: SandboxPolicy::default(),
        timeout: Some(Duration::from_secs(5)),
    };
    let mut samples = Vec::new();
    for _ in 0..8 {
        let started = Instant::now();
        let mut handle = sandbox
            .start(request.clone())
            .expect("performance fixture must start");
        let startup = started.elapsed();
        let stdout = handle.take_stdout().expect("stdout is available");
        let stderr = handle.take_stderr().expect("stderr is available");
        let events = handle.take_events().expect("events are available");
        let (_stdout, _stderr, _events, result) = collect_execution(handle, stdout, stderr, events);
        assert!(matches!(
            result.terminal,
            ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(23)
        ));
        samples.push(startup);
    }
    let warm = &samples[1..];
    let maximum = warm.iter().copied().max().expect("warm samples exist");
    assert!(
        maximum < Duration::from_millis(100),
        "warm startup exceeded 100 ms: samples={warm:?}"
    );
}
