use std::path::PathBuf;

use bolt_sandbox::{
    CompatibilityCapability, CompatibilityCommandOutcome, CompatibilityGrant,
    CompatibilityGrantContext, CompatibilityGrantResolver, CompatibilityNoPromptReason,
    CompatibilityResolution, FilesystemOperation, FilesystemViolation, SandboxEvent,
    ViolationAggregate,
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
