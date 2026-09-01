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

