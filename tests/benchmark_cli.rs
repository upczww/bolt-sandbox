#![cfg(windows)]

use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

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

#[test]
fn perf_003_read_workload_fixture_reports_internal_time_and_cleans_up() {
    let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("bolt-read-benchmark-{}-{id}", std::process::id()));
    let output = benchmark()
        .args(["--filesystem-read-fixture"])
        .arg(&root)
        .arg("16")
        .output()
        .expect("benchmark fixture must run");

    assert!(
        output.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .is_ok()
    );
    assert!(!root.exists());
    if root.exists() {
        fs::remove_dir_all(root).expect("failed fixture must clean up");
    }
}
