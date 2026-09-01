use std::{path::PathBuf, process::Command};

#[test]
fn compat_014_agent_tool_matrix_configuration_is_complete_and_safe() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("pwsh")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "scripts/verify-agent-tool-matrix.ps1",
            "-Configuration",
            "config/agent-tool-scenarios.json",
        ])
        .current_dir(&repository)
        .output()
        .expect("tool-matrix verifier must launch");

    assert!(
        output.status.success(),
        "tool matrix contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn compat_015_required_available_agent_tools_execute_from_configuration() {
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT") else {
        return;
    };
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("pwsh")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "scripts/test-agent-tool-matrix.ps1",
            "-Configuration",
            "config/agent-tool-scenarios.json",
            "-ComponentRoot",
        ])
        .arg(component_root)
        .current_dir(&repository)
        .output()
        .expect("configured Agent tool matrix must launch");

    assert!(
        output.status.success(),
        "configured Agent tool matrix failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
