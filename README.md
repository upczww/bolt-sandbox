# Bolt Sandbox

Bolt Sandbox is the Windows sandbox component for Bolt Agent. Its initial goal
is to provide Trae-style, low-latency process confinement without recursively
modifying ACLs, installing a kernel driver, or starting a virtual machine.

The implementation plan is documented in
[docs/architecture/windows-sandbox.md](docs/architecture/windows-sandbox.md).
It combines BuildXL's filesystem coverage, Trae's component boundaries, and
WorkBuddy's registry, network-stack, audit, and recovery behavior without
copying closed-source product code.

The test-driven delivery baseline is documented in
[docs/testing/test-plan.md](docs/testing/test-plan.md), with the complete case
inventory in [docs/testing/test-catalog.md](docs/testing/test-catalog.md) and
fixture contracts in [docs/testing/fixtures.md](docs/testing/fixtures.md). The
[requirements traceability matrix](docs/testing/requirements-matrix.md) maps
each architecture obligation to its catalog evidence, while the
[native API coverage inventory](docs/testing/api-coverage.md) prevents broad
“all relevant APIs” requirements from hiding an untested entry point.

## Status

Implementation includes the trusted Rust request, policy, IPC, launch-preparation,
and lifecycle boundaries. The native build produces an x64 fail-closed launcher
plus x86 and x64 hook DLLs sharing a versioned policy protocol. Native policy
envelopes are length-, version-, SHA-256-, and structure-validated. Suspended
process injection, architecture-matched descendant inheritance, Job Object
lifecycle control, required process mitigations, and the BuildXL-adapted
filesystem enforcement families are implemented and under acceptance hardening.
Native network, registry, recovery, packaging, and production-hardening work
remains.

## Development

Prerequisites: Rust 1.85 or newer, PowerShell 7, Visual Studio Build Tools with
the C++ workload, CMake, and a Windows SDK. Coverage also
requires `cargo-llvm-cov 0.9.0`, a separate nightly toolchain, and its matching
LLVM tools:

```powershell
rustup toolchain install nightly --profile minimal --component llvm-tools-preview
cargo +stable install cargo-llvm-cov --version 0.9.0 --locked
```

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
pwsh -NoProfile -File scripts/test-rust-coverage.ps1
pwsh -NoProfile -File scripts/verify-hook-manifest.ps1
pwsh -NoProfile -File scripts/audit-filesystem-evidence.ps1
pwsh -NoProfile -File scripts/audit-registry-evidence.ps1
pwsh -NoProfile -File scripts/build-windows.ps1
pwsh -NoProfile -File scripts/test-windows.ps1 -Suite Unit -Architecture x64
pwsh -NoProfile -File scripts/test-windows.ps1 -Suite Unit -Architecture x86
pwsh -NoProfile -File scripts/verify-test-traceability.ps1
```

## Intended Deliverables

Bolt Agent should integrate through the Rust `bolt-sandbox` library when it
needs typed requests, events, and lifecycle control. The `bolt-sandbox.exe`
CLI delegates to that same library for standalone testing and non-Rust callers.

```powershell
cargo build --release --bin bolt-sandbox
target\release\bolt-sandbox.exe run `
  --component-root C:\path\to\components `
  --cwd C:\repo `
  --timeout-ms 30000 `
  --read-write C:\package-cache `
  --read-only C:\sdk `
  --deny C:\sensitive `
  --network denied `
  --child-processes inherit `
  -- C:\tools\program.exe argument
```

Filesystem options are `--read-write`, `--read-only`, `--deny`,
`--metadata-read`, and `--inherit-user`. Registry equivalents are
`--registry-no-access`, `--registry-read-only`, `--registry-inherit-user`, and
`--registry-read-write`. Recovery requires all three of `--recovery-dir`,
`--recovery-max-bytes`, and `--recovery-max-items`. The CLI inherits the host
environment, while the library strips its configured credential variables
before launch. Event diagnostics contain fixed categories and process IDs but
do not print command arguments, environment values, or paths.

The runtime is distributed as a component set rather than a single binary:

- `bolt-sandbox.exe`, the optional Agent-facing CLI.
- `bolt-sandbox-launcher.exe` and `bolt-sandbox-launcher-x86.exe`, the private
  architecture-matched suspended-process launchers.
- `bolt-sandbox-x64.dll` and `bolt-sandbox-x86.dll`, the injected hook DLLs.

The selected Agent-facing interface and the four private runtime artifacts
must be versioned, integrity-checked, and shipped as one compatible release.
The private artifacts may later be embedded in the CLI for packaging
convenience, but remain separate runtime components after secure extraction.
