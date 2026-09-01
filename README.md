# Bolt Sandbox

[English](README.md) | [简体中文](README.zh-CN.md)

Bolt Sandbox is a low-latency, general-purpose Windows process sandbox designed
for AI coding agents, automation workers, build tools, and other programs that
need to execute untrusted or model-generated commands with explicit host-owned
policy.

It starts the target suspended, installs architecture-matched user-mode hooks
before application code runs, applies an immutable policy to the complete
process tree, and returns typed events, byte-preserving output streams, and a
deterministic terminal result. It does not recursively rewrite workspace ACLs,
start a virtual machine, or require a kernel driver.

> [!IMPORTANT]
> Bolt Sandbox is a user-mode containment boundary for conventional Windows
> applications and accidental or model-generated violations. It is not a
> kernel security boundary and does not claim to contain a deliberately
> malicious native executable using direct syscalls, hook removal, process
> tampering, privileged brokers, kernel drivers, or operating-system exploits.
> Use an AppContainer/BaseContainer or VM backend when hostile-binary
> containment is required.

## Why this project exists

AI agents routinely run package managers, compilers, test runners, shells, Git,
and user-provided tools. A useful sandbox for that workload needs more than a
single-process allow/deny check:

- startup must be fast enough for interactive agent loops;
- descendants must inherit the same boundary before their user code runs;
- filesystem, registry, process, and network decisions must be consistent;
- stdout, stderr, events, cancellation, timeout, and crash cleanup must not
  deadlock each other;
- secrets must not be copied into child environments, policy payloads, events,
  logs, or inadequately protected recovery storage; and
- missing components, malformed protocols, failed injection, or lost audit
  channels must fail closed—never fall back to an unsandboxed launch.

Bolt Sandbox provides that Windows-native execution boundary as a Rust library
with an optional thin CLI.

## Capabilities

| Area | What Bolt Sandbox provides |
| --- | --- |
| Filesystem | Read/write, read-only, metadata-only, inherited-user, and deny rules; normalized Win32/NT paths; links, reparse points, handle operations, rename/delete/truncate, mapping, async I/O, and shell API coverage. |
| Process tree | Suspended launch and pre-entry-point injection; x64 and x86 targets and descendants; Job Object cleanup; timeout and cancellation; breakaway, elevation, mitigation weakening, and unsupported token transitions fail closed. |
| Network | `Unrestricted`, `Denied`, and domain/IP/port allow-list modes; DNS binding; IPv4/IPv6; Winsock, WinHTTP, and WinInet coverage; unsupported UDP/raw/custom paths are denied in restrictive modes. |
| Registry | NT and Win32 open/query/enumerate/create/set/delete/rename enforcement; WOW64 views; symbolic-link and handle behavior; mandatory sensitive-key denies; remote and transactional operations are denied initially. |
| Recovery | Optional bounded backup before allowed destructive file operations; byte/item/retention quotas; atomic artifacts; child attribution; recovery namespace inaccessible to the target. Secret-tagged paths are not backed up without a future encrypted store. |
| Events and streams | Typed ordered events; bounded native queue; Rust duplicate aggregation; independent binary stdout/stderr streams; receiver-loss reporting; deterministic terminal ordering. |
| Component trust | Versioned x64/x86 component set, SHA-256 manifest, optional host-pinned manifest digest, file-identity leases, trusted-directory ACL verification, Authenticode checks, and atomic packaging. |
| Hardening | Mandatory credential-path/key denies, child credential stripping, process mitigations, fail-closed protocol handling, deterministic parser mutation campaigns, resource budgets, and release performance gates. |

## How it works

```text
Agent / host application
        |
        | typed SandboxRequest + host-owned policy
        v
Rust control plane
  validate -> strip credentials -> compile/seal policy -> verify components
        |
        | private launcher-start v2 request
        v
Architecture-matched launcher
  create Job -> create protected event pipe -> start target suspended
  -> inject hook -> verify authenticated Ready -> resume
        |
        +---- stdout / stderr / typed events ----> Rust lifecycle controller
        |
        v
Target and descendants
  filesystem + registry + process + network enforcement
```

Rust owns the public API, policy compilation, component verification, recovery,
event aggregation, and lifecycle result. Native code owns the minimal Windows
launcher, Detours-based interception, and bounded event emission. BuildXL path
handling and Microsoft Detours are imported at pinned revisions with retained
licenses; no closed-source product code is copied.

## Current status and performance

The implementation includes the Rust library and CLI, x64/x86 launchers and
hook DLLs, filesystem/process/network/registry enforcement, bounded recovery,
component manifests, ACL-hardened packaging, deterministic Rust and native
protocol mutation tests, and a signed-release workflow.

The checked release budgets currently require:

- warm sandbox startup below 100 ms;
- hook initialization below 50 ms;
- steady-state filesystem overhead below 5%; and
- configured absolute and growth limits for private bytes, handles, and
  threads.

On the current representative workstation, recorded local release evidence
observed roughly 40 ms warm startup and 4% steady-state filesystem overhead.
A separate path-churn workload (metadata/open/read/close every iteration) is
always recorded because final-identity validation has a meaningful fixed cost;
it is not hidden inside the steady-state number. Measurements vary by machine
and must be regenerated for a release.

## Using Bolt Sandbox from an agent

### 1. Ship the runtime component set

An agent must deploy these files together in one access-controlled, versioned
directory:

- `bolt-sandbox.exe` — optional CLI adapter;
- `bolt-sandbox-launcher.exe` — x64 launcher;
- `bolt-sandbox-launcher-x86.exe` — x86 launcher;
- `bolt-sandbox-x64.dll` — x64 hook;
- `bolt-sandbox-x86.dll` — x86 hook;
- `bolt-sandbox-dns-proxy.exe` — trusted x64 DNS/TCP policy proxy used only by
  `AllowList`; and
- `bolt-sandbox-compatibility.profile` — manifest-bound read-only and
  metadata-read compatibility grants; and
- `bolt-sandbox-components.manifest` — version, length, and SHA-256 identity for
  the compatible set.

Do not copy individual DLLs between releases. Production hosts should pin the
manifest SHA-256, require valid Authenticode signatures, and keep the component
directory non-writable by sandbox targets.

### 2. Prefer the Rust library

The Rust API is the preferred integration for an agent implemented in Rust. The
crate is currently consumed from the repository or a pinned Git revision:

```toml
[dependencies]
bolt-sandbox = { git = "https://github.com/upczww/bolt-sandbox", rev = "<commit>" }
```

Minimal integration:

```rust,no_run
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, time::Duration};

use bolt_sandbox::{
    ChildProcessPolicy, DEFAULT_STREAM_CAPACITY,
    DEFAULT_VIOLATION_AGGREGATE_CAPACITY, NetworkPolicy, Sandbox,
    SandboxConfig, SandboxPolicy, SandboxRequest,
};

fn main() {
    let component_root = PathBuf::from(r"C:\Program Files\Bolt\sandbox\0.1.0");
    let workspace = PathBuf::from(r"C:\agent-work\task-123");

    let sandbox = Sandbox::new(SandboxConfig {
        component_root,
        credential_environment_variables: vec![
            OsString::from("OPENAI_API_KEY"),
            OsString::from("ANTHROPIC_API_KEY"),
            OsString::from("GITHUB_TOKEN"),
        ],
        stream_capacity: DEFAULT_STREAM_CAPACITY,
        violation_aggregate_capacity: DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: vec![PathBuf::from(r"C:\host-secrets")],
        mandatory_registry_denies: vec![
            String::from(r"HKCU\SOFTWARE\Example\Credentials"),
        ],
        // Set Some([u8; 32]) in production to pin the trusted manifest.
        component_manifest_sha256: None,
    })
    .expect("valid sandbox configuration");

    let mut policy = SandboxPolicy::default();
    // The cwd is granted recursive read/write automatically.
    policy.filesystem.read_only.push(PathBuf::from(r"C:\SDK"));
    policy.filesystem.deny.push(PathBuf::from(r"C:\Users\Alice\.ssh"));
    policy.registry.read_only.push(String::from(r"HKCU\SOFTWARE\Example"));
    policy.network = NetworkPolicy::Denied;
    policy.child_processes = ChildProcessPolicy::Inherit;

    let mut handle = sandbox.start(SandboxRequest {
        program: PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe"),
        arguments: vec![
            OsString::from("-NoProfile"),
            OsString::from("-Command"),
            OsString::from("cargo test"),
        ],
        cwd: workspace,
        environment: std::env::vars_os().collect::<BTreeMap<_, _>>(),
        policy,
        timeout: Some(Duration::from_secs(120)),
    })
    .expect("sandbox execution starts");

    // Drain all three channels concurrently. Waiting without draining can
    // intentionally trigger bounded loss/backpressure behavior.
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (stdout, stderr, events, result) = std::thread::scope(|scope| {
        let out = scope.spawn(|| stdout.flatten().collect::<Vec<_>>());
        let err = scope.spawn(|| stderr.flatten().collect::<Vec<_>>());
        let evt = scope.spawn(|| events.collect::<Vec<_>>());
        let result = handle.wait();
        (
            out.join().expect("stdout reader"),
            err.join().expect("stderr reader"),
            evt.join().expect("event reader"),
            result,
        )
    });
    let result = result.expect("sandbox execution completes");

    println!("stdout bytes: {}", stdout.len());
    println!("stderr bytes: {}", stderr.len());
    println!("public events: {}", events.len());
    println!("violation aggregates: {}", result.violation_aggregates.len());
    println!("terminal: {:?}", result.terminal);
}
```

Agent integration guidance:

1. The host, not the prompt or child, constructs `SandboxPolicy`.
2. Use a fresh task workspace as `cwd`; it receives recursive read/write.
3. Add only narrow external grants required by the toolchain.
4. Put broker/model credential names in
   `credential_environment_variables`; the library strips matching child
   variables case-insensitively.
5. Keep mandatory secret paths and registry keys in `SandboxConfig`, outside
   request-controlled policy.
6. Drain stdout, stderr, and events concurrently, then inspect
   `ExecutionResult`, receiver-loss flags, violation aggregates, and terminal
   reason.
7. Treat initialization or infrastructure failure as task failure. Never retry
   by launching the command directly.

`ExecutionHandle::cancel()` requests whole-Job cancellation. A request timeout
also terminates the complete descendant tree and then drains terminal streams.

### 3. Use the CLI from non-Rust agents

The CLI delegates to the same library and is suitable for another agent
runtime, an MCP tool implementation, or a standalone broker:

```powershell
bolt-sandbox.exe run `
  --component-root C:\Bolt\sandbox\0.1.0 `
  --manifest-sha256 <64-hex-trusted-manifest-digest> `
  --cwd C:\agent-work\task-123 `
  --timeout-ms 120000 `
  --read-only C:\SDK `
  --read-write C:\package-cache `
  --deny C:\host-secrets `
  --registry-read-only HKCU\SOFTWARE\Example `
  --network denied `
  --child-processes inherit `
  -- C:\tools\program.exe argument1 argument2
```

Filesystem options are `--read-write`, `--read-only`, `--deny`,
`--metadata-read`, and `--inherit-user`. Registry options are
`--registry-no-access`, `--registry-read-only`, `--registry-inherit-user`, and
`--registry-read-write`. Recovery requires all four options:
`--recovery-dir`, `--recovery-max-bytes`, `--recovery-max-items`, and
`--recovery-retention-seconds`.

Network modes are `unrestricted`, `denied`, and `allow-list`. Allow-list rules
use repeatable `--allow-domain`, `--allow-cidr`, and `--allow-port` options; a
port may be a single value or an inclusive range:

```powershell
bolt-sandbox.exe run `
  --component-root C:\Bolt\sandbox\0.1.0 `
  --cwd C:\agent-work\task-123 `
  --network allow-list `
  --allow-domain example.org `
  --allow-domain *.example.net `
  --allow-cidr 192.0.2.0/24 `
  --allow-port 443 `
  --allow-port 8000-8080 `
  -- C:\Windows\System32\curl.exe --noproxy * https://example.org
```

At least one allow-list rule is required. Domain authorization is bound to the
resolved IP and requesting process for the DNS TTL; the requested TCP port is
checked independently. Unsupported restrictive-mode transports fail closed.

The CLI inherits the host environment and relies on its configured credential
name list to strip known broker/model secrets. Its diagnostics print fixed
categories and process IDs, not command arguments, environment values, or
paths. Library integration is preferable when the agent needs typed events,
custom credential names, cancellation, or aggregate results.

## Policy semantics

- Rules are normalized, canonicalized, deduplicated, length/count bounded, and
  serialized into an immutable SHA-256-protected native payload.
- More-specific grants may refine broader grants, but explicit and mandatory
  denies take precedence.
- Child input cannot request compatibility grants or weaken mandatory denies.
- Compatibility grants come from the Manifest-bound
  `bolt-sandbox-compatibility.profile`, not tool-specific paths in code. Version
  1 supports filesystem read-only, filesystem metadata-read, and registry
  read-only grants only.
- Profile bases are generic host roots such as `system-root`, `program-dir`,
  `cwd-anchor`, and `user-profile`; concrete Node, Python, Git, Cargo, and
  Rustup paths remain profile data.
- `NetworkPolicy::Unrestricted` preserves normal OS-authorized behavior;
  `Denied` and `AllowList` enforce restrictive network interception.
- `ChildProcessPolicy::Inherit` permits supported descendants only after the
  matching hook and policy are installed. `Deny` blocks child creation.
- Recovery failure never changes the original allow/deny decision. It emits a
  typed failure while an otherwise allowed destructive operation proceeds.

See the [architecture document](docs/architecture/windows-sandbox.md) for the
complete precedence, protocol, lifecycle, and threat-model contracts.

## Build and test

Prerequisites:

- Windows 10/11 or Windows Server;
- Rust 1.85 or newer;
- PowerShell 7;
- Visual Studio Build Tools 2019+ with Desktop C++ workload;
- CMake and a Windows SDK.

```powershell
# Rust quality gates
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets

# Traceability, upstream inputs, and native x64/x86 builds
pwsh scripts/verify-test-traceability.ps1
pwsh scripts/test-third-party.ps1
pwsh scripts/build-windows.ps1 -Configuration Release -Architecture All

# Native suites
pwsh scripts/test-windows.ps1 -Suite Unit -Architecture x64 -Configuration Release
pwsh scripts/test-windows.ps1 -Suite Unit -Architecture x86 -Configuration Release

# Real Agent runtime scenarios (declared runtimes are mandatory)
pwsh scripts/test-agent-scenarios.ps1 `
  -ComponentRoot target\native\x64\Release `
  -PythonPath C:\trusted-runtimes\python\python.exe
```

Optional Rust coverage requires `cargo-llvm-cov 0.9.0`, a nightly toolchain,
and matching LLVM tools:

```powershell
rustup toolchain install nightly --profile minimal --component llvm-tools-preview
cargo +stable install cargo-llvm-cov --version 0.9.0 --locked
pwsh scripts/test-rust-coverage.ps1
```

## Packaging and signing

```powershell
# Development package
pwsh scripts/package-windows.ps1 -Version 0.1.0

# Local strict signing-path test with an ephemeral, non-exportable certificate
pwsh scripts/test-signing-pipeline.ps1
```

The packager signs/verifies final bytes before writing the component manifest,
removes inherited ACL entries, rejects reparse points, grants mutation only to
the packaging identity, SYSTEM, and Administrators, verifies the final ACL, and
atomically renames staging into place.

The `Signed Windows release` workflow expects
`WINDOWS_SIGNING_PFX_BASE64`, `WINDOWS_SIGNING_PFX_PASSWORD`, and an HTTPS
RFC3161 timestamp URL. A publicly trusted release requires a real CA-issued
code-signing certificate; the ephemeral local test is not a production
signature.

## Known limitations

- The runtime is Windows-only; Linux and macOS require different enforcement
  backends.
- Windows ARM64/ARM64EC is not supported yet.
- AppContainer/BaseContainer, registry virtualization, and kernel-driver
  enforcement are deferred.
- Remote and transactional registry operations are denied rather than
  virtualized.
- Restrictive network modes deny unsupported UDP, raw-socket, QUIC, and custom
  stacks.
- Encrypted recovery for secret-tagged files is deferred; initial mode refuses
  to back them up.
- Elevated host tokens are rejected; Bolt Sandbox is intended to run
  unelevated.
- User-mode hooks do not provide hostile-binary containment guarantees.

## Project documentation

- [Windows architecture and security model](docs/architecture/windows-sandbox.md)
- [BuildXL import and adaptation boundaries](docs/architecture/buildxl-import.md)
- [Test strategy](docs/testing/test-plan.md)
- [Complete behavior catalog](docs/testing/test-catalog.md)
- [Requirements traceability matrix](docs/testing/requirements-matrix.md)
- [Native API coverage](docs/testing/api-coverage.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## License

Bolt Sandbox is licensed under the MIT License. Vendored third-party code keeps
its upstream license and pinned provenance; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
