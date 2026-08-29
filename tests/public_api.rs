use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

use bolt_sandbox::{
    ChildProcessPolicy, FilesystemPolicy, MAX_TIMEOUT, MIN_TIMEOUT, NetworkPolicy, ProcessExit,
    ProcessExitReason, RecoveryPolicy, RegistryPolicy, RequestField, SandboxError, SandboxEvent,
    SandboxPolicy, SandboxRequest,
};

fn minimal_request(program: &Path, cwd: &Path) -> SandboxRequest {
    SandboxRequest {
        program: program.to_path_buf(),
        arguments: vec![OsString::from("--version")],
        cwd: cwd.to_path_buf(),
        environment: BTreeMap::new(),
        policy: SandboxPolicy::default(),
        timeout: Some(Duration::from_secs(5)),
    }
}

#[test]
fn req_001_minimal_absolute_request_is_valid() {
    let program = std::env::current_exe().expect("test executable path must be available");
    let cwd = std::env::current_dir().expect("test working directory must be available");
    let request = minimal_request(&program, &cwd);

    assert_eq!(request.validate(), Ok(()));
}

#[test]
fn req_002_relative_program_is_rejected_before_launch() {
    let cwd = std::env::current_dir().expect("test working directory must be available");
    let request = minimal_request(Path::new("relative-program.exe"), &cwd);

    assert!(matches!(
        request.validate(),
        Err(SandboxError::InvalidRequest {
            field: RequestField::Program,
            ..
        })
    ));
}

#[test]
fn req_003_relative_cwd_is_rejected_before_launch() {
    let program = std::env::current_exe().expect("test executable path must be available");
    let request = minimal_request(&program, Path::new("relative-cwd"));

    assert!(matches!(
        request.validate(),
        Err(SandboxError::InvalidRequest {
            field: RequestField::CurrentDirectory,
            ..
        })
    ));
}

#[test]
fn req_008_default_policy_is_explicit_and_fail_closed_for_children() {
    let policy = SandboxPolicy::default();

    assert_eq!(policy.filesystem, FilesystemPolicy::default());
    assert_eq!(policy.registry, RegistryPolicy::default());
    assert_eq!(policy.network, NetworkPolicy::Unrestricted);
    assert_eq!(policy.child_processes, ChildProcessPolicy::Inherit);
    assert_eq!(policy.recovery, RecoveryPolicy::Disabled);
}

#[test]
fn req_013_public_event_contract_exposes_ready_without_native_types() {
    let event = SandboxEvent::Ready;

    assert_eq!(event, SandboxEvent::Ready);
}

#[test]
fn evt_001_public_process_exit_is_typed_without_native_status_types() {
    let event = SandboxEvent::ProcessExited(ProcessExit {
        process_id: 1234,
        exit_code: Some(7),
        reason: ProcessExitReason::Exited,
    });

    assert_eq!(
        event,
        SandboxEvent::ProcessExited(ProcessExit {
            process_id: 1234,
            exit_code: Some(7),
            reason: ProcessExitReason::Exited,
        })
    );
}

#[test]
fn req_001_request_preserves_os_native_arguments_and_environment() {
    let program = std::env::current_exe().expect("test executable path must be available");
    let cwd = std::env::current_dir().expect("test working directory must be available");
    let mut request = minimal_request(&program, &cwd);
    request.arguments = vec![OsString::from(""), OsString::from("空 格")];
    request
        .environment
        .insert(OsString::from("BOLT_TEST_KEY"), OsString::from("值"));

    assert_eq!(request.arguments[1], OsString::from("空 格"));
    assert_eq!(
        request.environment.get(&OsString::from("BOLT_TEST_KEY")),
        Some(&OsString::from("值"))
    );
}

#[test]
fn policy_types_are_constructible_without_native_dependencies() {
    let _ = SandboxPolicy {
        filesystem: FilesystemPolicy::default(),
        registry: RegistryPolicy::default(),
        network: NetworkPolicy::Denied,
        child_processes: ChildProcessPolicy::Deny,
        recovery: RecoveryPolicy::Disabled,
    };

    let _: Option<PathBuf> = None;
}

#[test]
fn req_007_public_timeout_bounds_match_the_documented_contract() {
    assert_eq!(MIN_TIMEOUT, Duration::from_millis(1));
    assert_eq!(MAX_TIMEOUT, Duration::from_secs(24 * 60 * 60));
}
