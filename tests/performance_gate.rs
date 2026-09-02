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
  "filesystemPathControlMilliseconds": [100, 101, 99, 100, 100, 101, 99],
  "filesystemPathSandboxMilliseconds": [130, 131, 129, 130, 130, 131, 129],
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

#[test]
fn perf_014_collector_rejects_missing_inputs_without_creating_evidence() {
    let root = fixture_directory();
    fs::create_dir_all(&root).expect("fixture directory must be created");
    let evidence = root.join("evidence.json");
    let output = Command::new("pwsh")
        .args([
            "-NoProfile",
            "-File",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/measure-windows-performance.ps1"
            ),
            "-ComponentRoot",
            r"C:\missing-components",
            "-EvidencePath",
        ])
        .arg(&evidence)
        .output()
        .expect("performance collector must run");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("benchmark input"));
    assert!(!evidence.exists());
    fs::remove_dir_all(root).expect("fixture directory must be removed");
}

#[test]
fn perf_010_local_release_runs_collector_and_fail_closed_verifier() {
    let release = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/release-windows-local.ps1"
    ))
    .expect("local release script must be readable");

    assert!(release.contains("measure-windows-performance.ps1"));
    assert!(release.contains("verify-performance-evidence.ps1"));
    assert!(release.contains("performance-evidence-x64.json"));
    assert!(release.contains("package-windows.ps1"));
    assert!(release.contains("-RequireSigned:$RequireSigned"));
    assert!(release.contains("test-agent-tool-matrix.ps1"));
    assert!(release.contains("-SandboxExecutable $releaseCli"));
}

#[test]
fn bundled_compatibility_profile_is_packaged_and_manifested() {
    let package = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/package-windows.ps1"
    ))
    .expect("package script must be readable");
    let build = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/build-windows.ps1"
    ))
    .expect("build script must be readable");
    let manifest = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/write-component-manifest.ps1"
    ))
    .expect("manifest script must be readable");
    let profile = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/bolt-sandbox-compatibility.profile"
    ));

    assert!(package.contains("bolt-sandbox-compatibility.profile"));
    assert!(build.contains("bolt-sandbox-compatibility.profile"));
    assert!(manifest.contains("bolt-sandbox-compatibility.profile"));
    assert!(
        profile
            .expect("bundled compatibility profile must exist")
            .starts_with("BSC1\n")
    );
}
