# Bolt Sandbox Test Plan

Status: baseline for test-driven implementation

This document turns the externally visible behavior in
`docs/architecture/windows-sandbox.md` into a test-first delivery contract. The
case inventory is in `test-catalog.md`; reusable programs, paths, servers, and
fault injectors are defined in `fixtures.md`; stable requirement-to-case
coverage is maintained in `requirements-matrix.md`.
The concrete native entry-point inventory is maintained in `api-coverage.md`.
Real Agent runtime and toolchain workflows are maintained in
`agent-scenario-matrix.md`.

## 1. Test objectives

The suite must prove that Bolt Sandbox:

1. permits only operations authorized by the compiled policy;
2. applies the same policy to every supported descendant process;
3. fails closed before user code runs when confinement cannot be established;
4. reports bounded, ordered, non-secret-bearing events without blocking hooks;
5. ships mutually compatible, integrity-checked x64 and x86 components; and
6. stays within the published startup and steady-state performance budgets.

The suite is a user-mode containment acceptance suite. Direct system calls,
hook removal, privileged brokers, kernel exploits, and hostile code injection
are limitation-demonstration tests, not claims of kernel-grade isolation.

## 2. Sources and traceability

| Requirement area | Architecture sections | Case prefixes |
| --- | --- | --- |
| Request and policy compilation | 5.1, 6.1, 11, 12.2 | `REQ`, `POL`, `SEC` |
| Cross-runtime policy semantics | 5.1, 5.3, 12.2 | `SEM` |
| Filesystem | 6, 14.1 | `FS` |
| Child processes and lifecycle | 5.2, 7, 14.2 | `PROC`, `LIFE` |
| Network | 8, 14.3 | `NET` |
| Registry | 9, 14.4 | `REG` |
| IPC and events | 5.3, 10 | `IPC`, `EVT` |
| Hook runtime robustness | 5.3, 10, 14.5 | `HOOK` |
| Recovery | 6.3, 14.4 | `REC` |
| Component/dependency boundaries | 5, 12.2 | `BND` |
| Security and bypass behavior | 11, 14.5 | `SEC`, `BYP` |
| Packaging and compatibility | 12.3, 15 | `PKG`, `COMPAT` |
| Performance | 15 | `PERF` |
| Third-party compliance | 3, 13 phase 0, 15 | `LIC` |

Every normative statement in the architecture must receive a stable ID and map
to at least one case in `requirements-matrix.md`. When requirements change,
update the matrix and catalog in the same change.
A case may not be removed merely because the implementation cannot pass it;
defer it with a tracked milestone and rationale instead.

## 3. Test layers

### 3.1 Rust unit tests

Run on every supported developer host where possible. These cover request
validation, policy precedence, canonical serialized payloads, redaction,
framing, checksums, sequence handling, architecture selection, timeout logic,
quota accounting, and event aggregation. Use table-driven tests and generated
path/policy inputs. Unit tests must not require injected DLLs.

### 3.2 Native unit and contract tests

Build separately for x64 and x86. These cover path and registry normalization,
access classification, protocol decoding, bounded queues, hook decision logic,
and the Rust/native protocol golden vectors. Imported upstream code receives
characterization tests before adaptation.

### 3.3 Windows integration tests

Launch a fresh sandbox for each test. Exercise real Win32 and NT operations via
small deterministic fixture executables. Assert operation result, Win32/NT
error, side effects on disk/registry/network, emitted event, and descendant
cleanup. Integration tests must use disposable roots and test-owned registry
keys. They must never depend on the developer's real credentials or profile.

### 3.4 Tool compatibility tests

Run `cmd`, PowerShell, Node, Python, Git, `cargo`, and representative build
scripts through the sandbox. Pin or record tool versions. Missing optional
tools cause an explicit environment failure, not a silently skipped test.

### 3.5 Security, fuzz, and bypass tests

Fuzz untrusted policy input and IPC frames. Attempt alternate API families,
links/reparse points, inherited handles, detached descendants, event pressure,
DLL unload/overwrite, and direct system calls. Tests for documented user-mode
limitations must use an explicit oracle such as `EXPECTED_LIMITATION`; they
must not be reported as enforcement passes.

### 3.6 Performance tests

Use warm and cold samples, a native unsandboxed control, fixed fixtures, and a
representative workstation profile recorded with results. Report distributions
and confidence intervals; do not gate on a single timing sample.

## 4. Case contract

Each executable test must preserve the catalog ID in its name or metadata and
must report its requirement IDs, layer, priority, delivery stage, environment
cells, fixture version, and cleanup result. It must assert all applicable
observations:

- process exit status and timeout state;
- API return and `GetLastError`/NTSTATUS;
- filesystem, registry, and network side effects;
- event kind, normalized resource, operation, decision, process identity, and
  sequence behavior;
- absence of secrets in child state, payloads, events, and diagnostics; and
- process-tree cleanup after completion or failure.

An allow test is not complete unless the intended side effect occurred. A deny
test is not complete unless the side effect did not occur and the expected
violation was observed. Error codes are contract assertions once stabilized,
but policy denial must never be confused with fixture or setup failure.

### Deterministic oracle rule

Each concrete parameterized subcase must have exactly one terminal state, one
expected API/NT status, and one side-effect/event contract. Wording such as
“allow or deny”, “supported where possible”, “according to the implementation”,
or “documented behavior” is not an executable oracle. If Windows capability,
policy mode, or input class legitimately changes the outcome, encode those as
separate parameter rows with separate expected values. An unresolved product
choice blocks that case at specification review; it may not be decided by the
implementation under test.

### Executable case metadata

The catalog stays readable by grouping related parameter rows, but the future
test manifest expands every row into concrete subcases. Each subcase records:

```text
case_id, subcase_id, requirement_ids, layer, priority, delivery_stage,
environment_cells, fixture_versions, input_vector, expected_terminal_state,
expected_return/status, expected_side_effects, expected_events,
redaction_contract, cleanup_contract
```

The runner rejects duplicate IDs, missing required fields, wildcard expected
results, and a `pass` result that lacks any required observation.

## 5. Isolation and determinism

- Create a unique test root, named pipe namespace, recovery root, registry key,
  loopback server, and execution identifier per test.
- Use only explicit absolute paths after setup. Resolve and log the test-owned
  roots before destructive cleanup.
- Restore registry and network state in fixture teardown, even after failure.
- Do not use public internet services for enforcement tests. Use loopback and a
  test-controlled IPv4/IPv6 endpoint; use a sealed network lab only for direct
  outbound tests.
- Run timing tests separately from correctness tests.
- Serialize tests that mutate process-global hooks or machine-observable state.
- Keep random seeds and minimized fuzz failures as artifacts.

## 6. TDD execution model

Work one vertical behavior at a time:

1. Select catalog IDs and create only the fixture support necessary for them.
2. Add the executable tests and run the exact target.
3. Accept RED only when the test compiles and fails because the required
   behavior is missing, or when a new reference to the missing public contract
   produces the intended compile-time failure.
4. Commit the validated RED checkpoint.
5. Implement the minimum behavior, rerun the same target, and commit GREEN.
6. Refactor while the focused and affected suites remain green.

Infrastructure failure, missing SDKs, malformed fixtures, and unrelated build
errors are not valid RED evidence. Until a build manifest and public contract
exist, this repository can define the catalog but cannot claim runtime RED.

## 7. Planned suite layout

```text
src/**                         Rust unit tests beside modules
native/**/tests/              x64/x86 native unit tests
tests/common/                 integration harness and assertions
tests/fixtures/               source for deterministic helper programs
tests/contracts/              Rust/native protocol golden vectors
tests/filesystem.rs           FS cases
tests/process_tree.rs         PROC and LIFE cases
tests/network.rs              NET cases
tests/registry.rs             REG cases
tests/ipc.rs                  IPC and EVT cases
tests/recovery.rs             REC cases
tests/failure_modes.rs        fail-closed cases
tests/bypass.rs               BYP and limitation cases
tests/compatibility.rs        COMPAT cases
benches/                      PERF workloads
fuzz/                         parsers, framing, and normalization targets
scripts/test-windows.ps1      orchestrated Windows matrix
scripts/verify-test-traceability.ps1
                              requirement/case/API manifest validation
```

## 8. Delivery order and gates

| Stage | First RED suites | Exit gate |
| --- | --- | --- |
| Test harness/API contract | `REQ`, `POL`, protocol `IPC` | Deterministic unit runner and golden vectors work on CI |
| Injection proof | `PROC-001..010`, `IPC-001..010`, `LIFE-001..006` | Supported tools start only after `Ready`; failure is closed |
| Filesystem | all `FS`, related `SEC`/`BYP` | Acceptance and normal-API escape suites pass |
| Process tree | remaining `PROC`/`LIFE` | Mixed-architecture descendants cannot normally escape |
| Network | all `NET` | All three modes and hostname/IP binding pass |
| Registry/recovery | all `REG`/`REC` | Mandatory denies and bounded recovery pass |
| Hardening/release | fuzz, `PKG`, `COMPAT`, `PERF`, `LIC` | Every release gate in architecture section 15 has evidence |

### Planned commands

These commands become mandatory as their manifests/scripts are introduced:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
pwsh scripts/test-rust-coverage.ps1
pwsh scripts/build-windows.ps1
pwsh scripts/test-windows.ps1 -Suite Unit
pwsh scripts/test-windows.ps1 -Suite Integration -Architecture x64
pwsh scripts/test-windows.ps1 -Suite Integration -Architecture x86
pwsh scripts/test-windows.ps1 -Suite Security
pwsh scripts/test-windows.ps1 -Suite Compatibility
pwsh scripts/test-windows.ps1 -Suite Performance -Configuration Release
pwsh scripts/verify-licenses.ps1
pwsh scripts/verify-test-traceability.ps1
```

`scripts/test-windows.ps1` must accept one or more case IDs/prefixes so the same
focused target can be shown failing at RED and passing at GREEN. It must return
nonzero for failed cases, missing required fixtures/tools, unsupported required
matrix cells, leaks, and malformed/missing result records. Full runs emit JUnit
plus a machine-readable manifest containing case ID, component versions/hashes,
host and child architecture, Windows/tool versions, duration, seed, result, and
artifact references.

The initial bootstrap sequence is:

1. create the Rust manifest and a test-harness smoke test;
2. define public request/policy/event/error contracts through `REQ-001`,
   `REQ-008`, `REQ-013`, `POL-001`, and `EVT-001` compile-time/runtime RED;
3. establish Rust/native golden framing through `IPC-004`, `IPC-015`, and
   `IPC-016` before launcher behavior;
4. build the startup-marker fixture and drive `PROC-001`, `IPC-012`, and
   `SEC-004` to RED before implementing injection; and
5. add later catalog slices only when their deterministic fixtures and oracles
   exist, keeping every selected case independently runnable.

## 9. Coverage and quality gates

- Rust and independently authored native decision logic: at least 90% line and
  85% branch coverage; the repository-wide floor is 80%.
- `scripts/test-rust-coverage.ps1` enforces Rust totals of at least 90% lines,
  85% branches, 80% regions, and 80% functions using the pinned
  `cargo-llvm-cov` version and nightly branch instrumentation.
- All policy precedence, fail-closed, mandatory-deny, and secret-redaction
  branches require direct tests regardless of percentage.
- No skipped, disabled, quarantined, or flaky tests on a release branch.
- Unit suite target: under 30 seconds; slower suites are partitioned by layer.
- Fuzz smoke jobs run on every change; extended fuzz and compatibility matrices
  run nightly and before release.
- Each release gate links to CI artifacts containing versions, architecture,
  case IDs, logs with redaction checks, and performance measurements.

## 10. Environment matrix

At minimum, run on every Windows version officially supported by Bolt Agent:

- x64 host: x64 parent/x64 child, x64 parent/x86 child, x86 parent/x86 child,
  and x86 parent/x64 child where Windows permits it;
- NTFS fixtures with long paths enabled and disabled as supported;
- standard unelevated user; a separate negative test verifies elevated launch
  is rejected or explicitly outside the supported configuration;
- clean profile and profile containing non-secret synthetic compatibility data;
- release builds for performance and debug/instrumented builds for diagnostics.

ARM64/ARM64EC cases remain deferred and must be reported as unsupported, never
silently treated as x64 success.

## 11. Definition of done for a requirement

A requirement is complete only when its catalog cases are executable, have
valid RED and GREEN history, pass in the required environment matrix, carry no
unresolved flake, and produce reviewable evidence. A passing unit mock does not
replace an integration test for a hooked Windows operation.
