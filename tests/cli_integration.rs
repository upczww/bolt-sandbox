use std::{path::PathBuf, process::Command};

#[test]
fn cli_003_binary_delegates_execution_and_preserves_streams_and_exit_code() {
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"))
        .arg("run")
        .arg("--component-root")
        .arg(&component_root)
        .arg("--cwd")
        .arg(&component_root)
        .arg("--timeout-ms")
        .arg("5000")
        .arg("--")
        .arg(component_root.join("bolt-sandbox-native-tests.exe"))
        .arg("--cli-fixture")
        .output()
        .expect("CLI must launch");

    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"cli-out");
    let stderr = String::from_utf8(output.stderr).expect("CLI diagnostics are UTF-8");
    assert!(stderr.contains("cli-err"));
    assert!(stderr.contains("sandbox-event ready"));
    assert!(stderr.contains("sandbox-event process-exited"));
    assert!(!stderr.contains("bolt-sandbox-native-tests.exe"));
}
