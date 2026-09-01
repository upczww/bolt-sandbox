use std::{
    collections::BTreeMap,
    ffi::OsString,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use bolt_sandbox::{
    AttributedSandboxEvent, ChildInjectionFailure, ChildInjectionFailureReason, ChildProcessPolicy,
    CommandId, DEFAULT_STREAM_CAPACITY, DEFAULT_VIOLATION_AGGREGATE_CAPACITY, EventStream,
    ExecutionAttribution, ExecutionHandle, ExecutionId, ExecutionOptions, ExecutionResult,
    FilesystemOperation, FilesystemPolicy, FilesystemViolation, IpCidr, MAX_TIMEOUT,
    MAX_VIOLATION_AGGREGATE_CAPACITY, MIN_TIMEOUT, NetworkAllowList, NetworkPolicy, NetworkTarget,
    NetworkViolation, PolicyGeneration, PortRange, ProcessExit, ProcessExitReason,
    ProcessOperation, ProcessViolation, RecoveryPolicy, RegistryPolicy, RequestField, Sandbox,
    SandboxConfig, SandboxError, SandboxEvent, SandboxPolicy, SandboxRequest, ViolationAggregate,
    WorkspaceChange, WorkspaceControlError, WorkspaceMode, WorkspaceTransactionId,
};

fn assert_attributed_stream<T: Iterator<Item = AttributedSandboxEvent>>() {}

#[test]
fn attr_001_public_command_id_is_fixed_nonzero_and_can_start_an_execution() {
    assert!(CommandId::new([0; 16]).is_none());
    let command_id = CommandId::new([0xA5; 16]).expect("nonzero command ID must be valid");
    assert_eq!(command_id.as_bytes(), &[0xA5; 16]);

    let _: fn(&Sandbox, SandboxRequest, CommandId) -> Result<ExecutionHandle, SandboxError> =
        Sandbox::start_with_command_id;
}

#[test]
fn attr_003_public_events_carry_execution_command_and_policy_generation() {
    assert!(ExecutionId::new([0; 16]).is_none());
    assert!(PolicyGeneration::new(0).is_none());
    let attribution = ExecutionAttribution {
        execution_id: ExecutionId::new([0x11; 16]).expect("execution ID must be valid"),
        command_id: CommandId::new([0x22; 16]).expect("command ID must be valid"),
        policy_generation: PolicyGeneration::new(1).expect("generation must be nonzero"),
    };
    let event = AttributedSandboxEvent {
        attribution,
        event: SandboxEvent::Ready,
    };

    assert_eq!(event.attribution, attribution);
    assert_eq!(event.event, SandboxEvent::Ready);

    assert_attributed_stream::<EventStream>();
}

#[test]
fn ws_002_projected_mode_is_explicit_and_fails_before_component_fallback() {
    assert_eq!(ExecutionOptions::default().workspace, WorkspaceMode::Direct);

    let cwd = std::env::current_dir().expect("test cwd must exist");
    let program = std::env::current_exe().expect("test executable must exist");
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: cwd.clone(),
        credential_environment_variables: Vec::new(),
        stream_capacity: DEFAULT_STREAM_CAPACITY,
        violation_aggregate_capacity: DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .expect("configuration root must be valid");

    assert!(matches!(
        sandbox.start_with_options(
            minimal_request(&program, &cwd),
            ExecutionOptions {
                workspace: WorkspaceMode::Projected,
                ..ExecutionOptions::default()
            }
        ),
        Err(SandboxError::InitializationFailed {
            stage: bolt_sandbox::InitializationStage::Workspace
        })
    ));
}

#[test]
fn ws_014_public_transaction_control_stays_in_trusted_sandbox() {
    assert_ne!(WorkspaceMode::Staged, WorkspaceMode::Direct);
    assert!(WorkspaceTransactionId::new([0; 16]).is_none());
    let _: fn(
        &Sandbox,
        WorkspaceTransactionId,
    ) -> Result<Vec<WorkspaceChange>, WorkspaceControlError> = Sandbox::query_workspace_changes;
    let _: fn(
        &Sandbox,
        WorkspaceTransactionId,
    ) -> Result<Vec<WorkspaceChange>, WorkspaceControlError> = Sandbox::commit_workspace;
    let _: fn(&Sandbox, WorkspaceTransactionId) -> Result<(), WorkspaceControlError> =
        Sandbox::discard_workspace;
    let _: fn(&Sandbox, WorkspaceTransactionId) -> Result<(), WorkspaceControlError> =
        Sandbox::revert_workspace;
}

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
fn req_013_typed_security_events_are_public_without_native_status_types() {
    let filesystem = SandboxEvent::FilesystemViolation(FilesystemViolation {
        process_id: 7,
        operation: FilesystemOperation::Write,
        path: PathBuf::from(r"C:\denied.txt"),
    });
    let network = SandboxEvent::NetworkViolation(NetworkViolation {
        process_id: 7,
        operation: bolt_sandbox::NetworkOperation::Resolve,
        target: NetworkTarget::Domain("example.com".to_owned()),
    });
    let child = SandboxEvent::ChildInjectionFailed(ChildInjectionFailure {
        parent_process_id: 7,
        child_process_id: 8,
        reason: ChildInjectionFailureReason::InjectionFailed,
    });
    let process = SandboxEvent::ProcessViolation(ProcessViolation {
        process_id: 7,
        operation: ProcessOperation::CreateWithToken,
    });

    assert!(matches!(filesystem, SandboxEvent::FilesystemViolation(_)));
    assert!(matches!(network, SandboxEvent::NetworkViolation(_)));
    assert!(matches!(child, SandboxEvent::ChildInjectionFailed(_)));
    assert!(matches!(process, SandboxEvent::ProcessViolation(_)));
}

#[test]
fn evt_004_public_violation_aggregate_preserves_first_event_and_count() {
    let first = SandboxEvent::FilesystemViolation(FilesystemViolation {
        process_id: 7,
        operation: FilesystemOperation::Write,
        path: PathBuf::from(r"C:\denied.txt"),
    });
    let aggregate = ViolationAggregate {
        event: first.clone(),
        duplicate_count: 3,
    };

    assert_eq!(aggregate.event, first);
    assert_eq!(aggregate.duplicate_count, 3);
    assert_eq!(DEFAULT_VIOLATION_AGGREGATE_CAPACITY, 1_024);
    const {
        assert!(MAX_VIOLATION_AGGREGATE_CAPACITY >= DEFAULT_VIOLATION_AGGREGATE_CAPACITY);
    }
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

#[test]
fn req_013_network_policy_types_are_constructible_without_protocol_leakage() {
    let policy = NetworkPolicy::AllowList(NetworkAllowList {
        domains: vec!["example.com".into()],
        addresses: vec![IpCidr {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix_length: 24,
        }],
        ports: vec![PortRange {
            start: 443,
            end: 443,
        }],
    });

    assert!(matches!(policy, NetworkPolicy::AllowList(_)));
}

fn assert_send<T: Send>() {}

#[test]
fn req_013_public_execution_types_are_thread_transferable() {
    assert_send::<ExecutionHandle>();
    assert_send::<ExecutionResult>();
}

#[test]
fn req_001_public_start_rejects_invalid_request_before_component_access() {
    let cwd = std::env::current_dir().expect("test working directory must be available");
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: cwd.clone(),
        credential_environment_variables: Vec::new(),
        stream_capacity: DEFAULT_STREAM_CAPACITY,
        violation_aggregate_capacity: DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .expect("absolute component root must configure the sandbox");
    let request = minimal_request(Path::new("relative-program.exe"), &cwd);

    assert!(matches!(
        sandbox.start(request),
        Err(SandboxError::InvalidRequest {
            field: RequestField::Program,
            ..
        })
    ));
}

#[test]
fn evt_006_zero_violation_aggregate_capacity_is_rejected() {
    let cwd = std::env::current_dir().expect("test working directory must be available");
    let result = Sandbox::new(SandboxConfig {
        component_root: cwd,
        credential_environment_variables: Vec::new(),
        stream_capacity: DEFAULT_STREAM_CAPACITY,
        violation_aggregate_capacity: 0,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    });

    assert!(matches!(
        result,
        Err(SandboxError::InvalidConfiguration {
            field: bolt_sandbox::ConfigurationField::ViolationAggregateCapacity,
            ..
        })
    ));
}
