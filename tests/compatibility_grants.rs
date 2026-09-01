use std::path::PathBuf;

use bolt_sandbox::{
    CompatibilityApplyError, CompatibilityApprovalScope, CompatibilityCapability,
    CompatibilityCommandOutcome, CompatibilityDecision, CompatibilityDecisionCache,
    CompatibilityGrant, CompatibilityGrantContext, CompatibilityGrantResolver,
    CompatibilityNoPromptReason, CompatibilityPromptAction, CompatibilityResolution,
    FilesystemOperation, FilesystemViolation, RegistryOperation, RegistryViolation, SandboxEvent,
    SandboxPolicy, ViolationAggregate,
};

fn context() -> CompatibilityGrantContext {
    CompatibilityGrantContext {
        executable_path: PathBuf::from(r"C:\Tools\compiler.exe"),
        executable_sha256: [0x42; 32],
        workspace: PathBuf::from(r"C:\agent-work\task"),
        mandatory_filesystem_denies: vec![PathBuf::from(r"C:\Users\agent\.ssh")],
        mandatory_registry_denies: vec![String::from(r"HKCU\SOFTWARE\Microsoft\Credentials")],
        maximum_grants: 16,
    }
}

fn filesystem_violation(operation: FilesystemOperation, path: &str) -> ViolationAggregate {
    ViolationAggregate {
        event: SandboxEvent::FilesystemViolation(FilesystemViolation {
            process_id: 41,
            operation,
            path: PathBuf::from(path),
        }),
        duplicate_count: 0,
    }
}

#[test]
fn compat_016_successful_command_never_prompts_for_harmless_probe() {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let resolution = resolver.resolve(
        CompatibilityCommandOutcome::Succeeded,
        &[filesystem_violation(
            FilesystemOperation::Read,
            r"C:\SDK\optional.cfg",
        )],
        0,
    );

    assert_eq!(
        resolution,
        CompatibilityResolution::NoPrompt(CompatibilityNoPromptReason::CommandSucceeded)
    );
}

#[test]
fn compat_017_failed_command_proposes_one_exact_read_only_grant() {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let resolution = resolver.resolve(
        CompatibilityCommandOutcome::Failed,
        &[
            filesystem_violation(FilesystemOperation::Read, r"C:\SDK\toolchain\stdlib.lib"),
            ViolationAggregate {
                duplicate_count: 7,
                ..filesystem_violation(FilesystemOperation::Read, r"c:\sdk\toolchain\stdlib.lib")
            },
        ],
        0,
    );
    let CompatibilityResolution::NeedsAuthorization(proposal) = resolution else {
        panic!("failed command must produce a proposal");
    };

    assert_eq!(proposal.grants.len(), 1);
    assert_eq!(
        proposal.grants[0],
        CompatibilityGrant::FilesystemReadOnly(PathBuf::from(r"C:\SDK\toolchain\stdlib.lib"))
    );
    assert_eq!(proposal.duplicate_violations, 7);
    assert!(!proposal.proposal_id.is_empty());
}

#[test]
fn compat_018_sensitive_and_external_write_requests_are_never_ordinary_grants() {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let resolution = resolver.resolve(
        CompatibilityCommandOutcome::Failed,
        &[
            filesystem_violation(FilesystemOperation::Read, r"C:\Users\agent\.ssh\config"),
            filesystem_violation(FilesystemOperation::Write, r"C:\host\output.dll"),
        ],
        0,
    );
    let CompatibilityResolution::CapabilityUnavailable(unavailable) = resolution else {
        panic!("ineligible authority must not be proposed");
    };

    assert!(unavailable.grants.is_empty());
    assert!(
        unavailable
            .capabilities
            .contains(&CompatibilityCapability::MandatorySensitiveResource)
    );
    assert!(
        unavailable
            .capabilities
            .contains(&CompatibilityCapability::HostWrite)
    );
}

#[test]
fn compat_019_incomplete_violation_evidence_never_guesses_a_grant() {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let resolution = resolver.resolve(
        CompatibilityCommandOutcome::Failed,
        &[filesystem_violation(
            FilesystemOperation::Read,
            r"C:\SDK\toolchain\stdlib.lib",
        )],
        1,
    );
    let CompatibilityResolution::CapabilityUnavailable(unavailable) = resolution else {
        panic!("dropped evidence must suppress authorization proposals");
    };

    assert!(unavailable.grants.is_empty());
    assert_eq!(
        unavailable.capabilities,
        [CompatibilityCapability::IncompleteEvidence]
    );
}

fn read_proposal() -> bolt_sandbox::CompatibilityGrantProposal {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let CompatibilityResolution::NeedsAuthorization(proposal) = resolver.resolve(
        CompatibilityCommandOutcome::Failed,
        &[filesystem_violation(
            FilesystemOperation::Read,
            r"C:\SDK\toolchain\stdlib.lib",
        )],
        0,
    ) else {
        panic!("fixture must produce a proposal");
    };
    proposal
}

#[test]
fn compat_022_rejected_proposal_is_not_prompted_repeatedly() {
    let proposal = read_proposal();
    let mut cache = CompatibilityDecisionCache::new(32).expect("valid cache");
    assert_eq!(cache.action(&proposal), CompatibilityPromptAction::Prompt);

    cache
        .record(
            &proposal,
            CompatibilityDecision::Rejected,
            CompatibilityApprovalScope::Workspace,
        )
        .expect("rejection must record");
    assert_eq!(
        cache.action(&proposal),
        CompatibilityPromptAction::SuppressRejected
    );
}

#[test]
fn compat_023_once_approval_is_consumed_by_exactly_one_restart() {
    let proposal = read_proposal();
    let mut cache = CompatibilityDecisionCache::new(32).expect("valid cache");
    cache
        .record(
            &proposal,
            CompatibilityDecision::Approved,
            CompatibilityApprovalScope::Once,
        )
        .expect("approval must record");

    assert_eq!(
        cache.action(&proposal),
        CompatibilityPromptAction::UseApproved
    );
    assert!(cache.consume_approval(&proposal));
    assert_eq!(cache.action(&proposal), CompatibilityPromptAction::Prompt);
    assert!(!cache.consume_approval(&proposal));
}

#[test]
fn compat_024_workspace_approval_reuses_only_identical_tool_and_grants() {
    let proposal = read_proposal();
    let mut cache = CompatibilityDecisionCache::new(32).expect("valid cache");
    cache
        .record(
            &proposal,
            CompatibilityDecision::Approved,
            CompatibilityApprovalScope::Workspace,
        )
        .expect("approval must record");
    assert_eq!(
        cache.action(&proposal),
        CompatibilityPromptAction::UseApproved
    );
    assert!(cache.consume_approval(&proposal));
    assert_eq!(
        cache.action(&proposal),
        CompatibilityPromptAction::UseApproved
    );

    let mut changed = proposal;
    changed.executable_sha256[0] ^= 1;
    assert_eq!(cache.action(&changed), CompatibilityPromptAction::Prompt);
}

#[test]
fn compat_025_approved_grants_create_a_new_minimal_policy() {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let proposal = read_proposal();
    let original = SandboxPolicy::default();
    let applied = resolver
        .apply_approved(&proposal, &original)
        .expect("valid read proposal must apply");

    assert!(original.filesystem.read_only.is_empty());
    assert_eq!(
        applied.filesystem.read_only,
        [PathBuf::from(r"C:\SDK\toolchain\stdlib.lib")]
    );
}

#[test]
fn compat_026_forged_or_sensitive_proposal_cannot_be_applied() {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let mut proposal = read_proposal();
    proposal.grants = vec![CompatibilityGrant::FilesystemReadOnly(PathBuf::from(
        r"C:\Users\agent\.ssh\config",
    ))];

    assert_eq!(
        resolver.apply_approved(&proposal, &SandboxPolicy::default()),
        Err(CompatibilityApplyError::InvalidProposal)
    );
}

#[test]
fn compat_027_registry_approval_is_exact_read_only_not_recursive() {
    let resolver = CompatibilityGrantResolver::new(context()).expect("valid context");
    let CompatibilityResolution::NeedsAuthorization(proposal) = resolver.resolve(
        CompatibilityCommandOutcome::Failed,
        &[ViolationAggregate {
            event: SandboxEvent::RegistryViolation(RegistryViolation {
                process_id: 52,
                operation: RegistryOperation::Query,
                key: String::from(r"HKLM\SOFTWARE\Vendor\Tool\Metadata"),
            }),
            duplicate_count: 0,
        }],
        0,
    ) else {
        panic!("registry read must produce a proposal");
    };
    let applied = resolver
        .apply_approved(&proposal, &SandboxPolicy::default())
        .expect("exact registry proposal must apply");

    assert!(applied.registry.read_only.is_empty());
    assert_eq!(
        applied.registry.exact_read_only,
        [String::from(r"HKLM\SOFTWARE\Vendor\Tool\Metadata")]
    );
}
