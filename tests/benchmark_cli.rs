#![cfg(windows)]

use std::process::Command;

fn benchmark() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bolt-sandbox-benchmark"))
}

#[test]
fn perf_014_benchmark_requires_explicit_component_root_and_sample_counts() {
    let output = benchmark().output().expect("benchmark process must run");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}

#[test]
fn perf_014_zero_sample_count_is_rejected_before_component_access() {
    let output = benchmark()
        .args([
            "--component-root",
            r"C:\does-not-need-to-exist",
            "--warmup",
            "1",
            "--samples",
            "0",
            "--filesystem-iterations",
            "1",
        ])
        .output()
        .expect("benchmark process must run");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid benchmark arguments"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("does-not-need-to-exist"));
}
