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

Implementation has started with the trusted Rust boundary. The crate currently
provides public request, policy, event, and structured error contracts; validates
program and working-directory inputs; and privately compiles the working
directory into a recursive read-write root. Native launcher and hook components
have not been introduced yet.

## Development

Prerequisites: Rust 1.85 or newer and PowerShell 7 on Windows. Coverage also
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
pwsh -NoProfile -File scripts/verify-test-traceability.ps1
```

The Windows-native build and integration scripts will become available with the
launcher/injection phase.

## Intended Deliverables

Bolt Agent should integrate through the Rust `bolt-sandbox` library when it
needs typed requests, events, and lifecycle control. A `bolt-sandbox.exe` CLI
will provide the same behavior for standalone testing and non-Rust callers.

The runtime is distributed as a component set rather than a single binary:

- `bolt-sandbox.exe`, the optional Agent-facing CLI.
- `bolt-sandbox-launcher.exe`, the private suspended-process launcher.
- `bolt-sandbox-x64.dll` and `bolt-sandbox-x86.dll`, the injected hook DLLs.

The selected Agent-facing interface and the three private runtime artifacts
must be versioned, integrity-checked, and shipped as one compatible release.
The private artifacts may later be embedded in the CLI for packaging
convenience, but remain separate runtime components after secure extraction.
