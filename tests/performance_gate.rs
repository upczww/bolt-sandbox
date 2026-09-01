#![cfg(windows)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

const VALID_BUDGET: &str = r#"{
  "schemaVersion": 1,
  "minimumWarmupSamples": 1,
  "minimumMeasuredSamples": 7,
  "maximumWarmStartupMilliseconds": 100,
  "maximumFilesystemOverheadPercent": 5,
  "maximumPrivateBytes": 268435456,
  "maximumPrivateBytesGrowth": 16777216,
  "maximumHandles": 512,
  "maximumHandleGrowth": 8,
  "maximumThreads": 32,
  "maximumThreadGrowth": 2
}"#;

const VALID_EVIDENCE: &str = r#"{
  "schemaVersion": 1,
  "environmentValid": true,
  "warmupSamples": 1,
  "startupMilliseconds": [40, 41, 42, 39, 43, 40, 41],
  "filesystemControlMilliseconds": [100, 101, 99, 100, 100, 101, 99],
  "filesystemSandboxMilliseconds": [104, 104, 103, 104, 104, 105, 103],
  "privateBytes": [104857600, 105906176, 106954752, 108003328, 109051904, 110100480, 111149056],
  "handles": [80, 80, 81, 80, 81, 80, 81],
  "threads": [8, 8, 8, 8, 8, 8, 8]
}"#;

fn fixture_directory() -> PathBuf {
    let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("bolt-performance-gate-{}-{id}", std::process::id()))
}

fn run_gate(root: &Path, budget: &str, evidence: &str) -> Output {
    fs::create_dir_all(root).expect("fixture directory must be created");
    let budget_path = root.join("budget.json");
    let evidence_path = root.join("evidence.json");
    fs::write(&budget_path, budget).expect("budget fixture must be written");
    fs::write(&evidence_path, evidence).expect("evidence fixture must be written");
    let output = Command::new("pwsh")
        .args([
            "-NoProfile",
            "-File",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/verify-performance-evidence.ps1"
            ),
            "-BudgetPath",
        ])
        .arg(&budget_path)
        .arg("-EvidencePath")
        .arg(&evidence_path)
        .output()
        .expect("performance verifier must run");
    fs::remove_dir_all(root).expect("fixture directory must be removed");
    output
}

#[test]
fn perf_011_missing_resource_budget_fails_as_not_configured() {
    let budget = VALID_BUDGET.replace("  \"maximumHandleGrowth\": 8,\n", "");
    let output = run_gate(&fixture_directory(), &budget, VALID_EVIDENCE);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("NOT_CONFIGURED"));
}

#[test]
fn perf_010_out_of_budget_evidence_fails_closed() {
    let evidence = VALID_EVIDENCE.replace(
        "[104, 104, 103, 104, 104, 105, 103]",
        "[109, 109, 108, 109, 109, 110, 108]",
    );
    let output = run_gate(&fixture_directory(), VALID_BUDGET, &evidence);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("OUT_OF_BUDGET"));
}

#[test]
fn perf_010_complete_in_budget_evidence_passes() {
    let output = run_gate(&fixture_directory(), VALID_BUDGET, VALID_EVIDENCE);

    assert!(
        output.status.success(),
        "verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("PASS"));
}
