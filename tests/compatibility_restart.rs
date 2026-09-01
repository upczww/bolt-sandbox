use std::{collections::BTreeMap, ffi::OsString, fs, path::PathBuf, time::Duration};

use bolt_sandbox::{
    CompatibilityApprovalScope, CompatibilityCommandOutcome, CompatibilityDecision,
    CompatibilityDecisionCache, CompatibilityGrantContext, CompatibilityGrantResolver,
    CompatibilityRestartError, DEFAULT_STREAM_CAPACITY, DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
    ExecutionOptions, ExecutionTerminal, ProcessExitReason, Sandbox, SandboxConfig, SandboxPolicy,
    SandboxRequest, WorkspaceControlError, WorkspaceMode,
};

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end test proves failure, approval, discard, and restart ordering"
)]
fn compat_028_to_030_approved_restart_discards_old_transaction_and_runs_once() {
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let fixture = std::env::temp_dir().join(format!("bolt-compat-restart-{}", std::process::id()));
    let source = fixture.join("source");
    let external = fixture.join("sdk.txt");
    fs::create_dir_all(&source).expect("source workspace must exist");
    fs::write(&external, "sdk\n").expect("external read fixture must exist");
    let program = component_root.join("bolt-sandbox-native-tests.exe");
    let request = SandboxRequest {
        program: program.clone(),
        arguments: vec![
            OsString::from("--compatibility-read-fixture"),
            external.clone().into_os_string(),
        ],
        cwd: source.clone(),
        environment: BTreeMap::new(),
        policy: SandboxPolicy::default(),
        timeout: Some(Duration::from_secs(10)),
    };
    let sandbox = Sandbox::new(SandboxConfig {
        component_root,
        credential_environment_variables: Vec::new(),
        stream_capacity: DEFAULT_STREAM_CAPACITY,
        violation_aggregate_capacity: DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .expect("sandbox must configure");
    let options = ExecutionOptions {
        workspace: WorkspaceMode::Staged,
        ..ExecutionOptions::default()
    };

    let first = sandbox
        .start_with_options(request.clone(), options)
        .expect("initial denied execution must start")
        .wait()
        .expect("initial denied execution must finish");
    assert!(matches!(
        first.terminal,
        ExecutionTerminal::Process(ref exit)
            if exit.reason == ProcessExitReason::Exited && exit.exit_code != Some(0)
    ));
    let first_transaction = first
        .workspace_transaction
        .expect("staged failure must retain a transaction");
    let resolver = CompatibilityGrantResolver::new(CompatibilityGrantContext {
        executable_path: program,
        executable_sha256: [0x51; 32],
        workspace: source,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        maximum_grants: 16,
    })
    .expect("resolver context must be valid");
    let proposal = match resolver.resolve(
        CompatibilityCommandOutcome::Failed,
        &first.violation_aggregates,
        first.dropped_distinct_violations,
    ) {
        bolt_sandbox::CompatibilityResolution::NeedsAuthorization(proposal) => proposal,
        other => panic!("denied external read must propose authorization: {other:?}"),
    };
    let mut decisions = CompatibilityDecisionCache::new(8).expect("cache must configure");
    decisions
        .record(
            &proposal,
            CompatibilityDecision::Approved,
            CompatibilityApprovalScope::Once,
        )
        .expect("approval must record");

    let plan = resolver
        .prepare_restart(&proposal, request.clone(), &first, options, &mut decisions)
        .expect("approved failed execution must prepare one restart");
    assert!(matches!(
        resolver.prepare_restart(&proposal, request, &first, options, &mut decisions),
        Err(CompatibilityRestartError::ApprovalUnavailable)
    ));
    let second = plan
        .start(&sandbox)
        .expect("approved restart must start")
        .wait()
        .expect("approved restart must finish");
    assert!(
        matches!(
            second.terminal,
            ExecutionTerminal::Process(ref exit)
                if exit.reason == ProcessExitReason::Exited && exit.exit_code == Some(0)
        ),
        "approved restart failed: terminal={:?} violations={:?}",
        second.terminal,
        second.violation_aggregates
    );
    assert_eq!(
        sandbox.query_workspace_changes(first_transaction),
        Err(WorkspaceControlError::NotFound)
    );
    sandbox
        .discard_workspace(
            second
                .workspace_transaction
                .expect("approved staged restart must return a transaction"),
        )
        .expect("approved restart transaction must discard");
    let _ = fs::remove_dir_all(&fixture);
}
