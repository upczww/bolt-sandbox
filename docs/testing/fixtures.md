# Test Fixture Specification

Fixtures are deterministic test programs and resources, not production code.
Each executable accepts a machine-readable request on an inherited private
handle and returns a machine-readable observation. Secrets and policies must
not be placed on its command line or in its environment.

## Filesystem fixtures

- `fs_probe_x64.exe` and `fs_probe_x86.exe`: invoke one selected Win32 or NT
  filesystem API for open, create, read, write, enumerate, metadata, delete,
  rename, replace, hard-link, symlink, junction/reparse, ADS, short-name,
  writable/image mapping, shell operation, open-by-ID, change notification,
  overlapped/IOCP submission and cancellation, and handle disposition scenarios.
- `path_tree`: test-owned roots `grant-rw`, `grant-ro`, `deny`, `outside`, and
  `sensitive`, with unique marker contents and links crossing every boundary.
- Every mutating operation writes a nonce so stale state cannot satisfy an
  assertion. Teardown verifies resolved paths stay under the test root.
- Optional host capabilities are supplied only to the test harness through
  `BOLT_TEST_UNC_ROOT` and `BOLT_TEST_CASE_SENSITIVE_ROOT`. The first value is
  an existing writable UNC share root; the second is an existing local
  directory with `FILE_CS_FLAG_CASE_SENSITIVE_DIR` enabled. Missing variables
  are recorded as `not_present` and do not silently substitute a local path.
- When either capability variable is present, the fixture validates the real
  capability before claiming evidence. UNC tests compare ordinary `\\server`
  and extended `\\?\UNC\server` aliases and verify share-side contents.
  Case-sensitive tests create two existing targets that differ only by case,
  require distinct file IDs, and verify that an allow rule for one identity
  cannot authorize the denied identity. The same conflicting policy must be
  rejected on a case-insensitive directory.
- Volume-alias fixtures exercise `\\.\`, `\\?\Volume{GUID}\`, `\??\`, and
  direct `\Device\HarddiskVolume...` paths against DOS-path policy rules. The
  volume GUID and native-device probes run in an isolated Job with a shared
  stage word and a three-second watchdog; timeout terminates the whole Job and
  reports the last completed stage instead of blocking the suite.

## Process fixtures

- `spawn_probe_x64.exe` and `spawn_probe_x86.exe`: exercise each supported
  process-creation family (`CreateProcess`, `CreateProcessAsUser`,
  `CreateProcessWithToken`, `CreateProcessWithLogon`, `ShellExecuteEx`, and
  NT/Rtl native creation), nested trees, inherited handles, detached flags,
  job-breakaway attempts, suspended children, and architecture transitions.
- `startup_marker.exe`: atomically records its first user-code instruction;
  fail-closed tests assert this marker was never created.
- `tree_heartbeat.exe`: emits process identity and liveness through a private
  test channel so timeout and cleanup tests can prove all descendants stopped.
- Fixture source is built for both architectures from the same behavioral
  contract. Architecture is included in every observation.
- `mitigation_probe.exe`: queries the effective process mitigation policy and
  attempts only documented weakening operations against the test process.

## Network fixtures

- Dual-stack loopback DNS stub with deterministic A, AAAA, CNAME, rebinding,
  TTL, NXDOMAIN, delayed, and malformed replies.
- Dual-stack TCP/UDP servers on dynamically reserved ports, an HTTP redirect
  server, an HTTP CONNECT proxy, and a sink that records connection identity.
- `net_probe_x64.exe` and `net_probe_x86.exe`: Winsock `connect`, `WSAConnect`,
  `ConnectEx`, sync/async DNS, WinHTTP, and WinInet operations.
- External direct-connect scenarios run only in an isolated test network with
  a test-owned endpoint. Correctness must not depend on public DNS or internet.

## Registry fixtures

- All mutable keys live below a unique `HKCU\Software\BoltSandboxTests\<id>`.
- `registry_probe_x64.exe` and `registry_probe_x86.exe`: NT create, open, query,
  enumerate, set, delete value, delete key, and rename operations, plus selected
  Win32 wrappers for end-to-end compatibility.
- Sensitive-key tests use synthetic broker/configuration keys recognized by a
  test-only compiled policy; they never access actual credentials.

## IPC and fault fixtures

- Golden frames for every protocol version and event type, including boundary
  lengths and valid checksums, shared by Rust and native tests.
- Mutators for truncation, oversize lengths, unknown versions/types, checksum
  corruption, duplicate/out-of-order/wrapped sequence numbers, slow readers,
  disconnects, queue saturation, namespace squatting, replay, process/sender
  spoofing, handle duplication, and security-descriptor inspection.
- Launcher fault switches are available only in test builds: missing DLL,
  wrong architecture, invalid mapping/pipe handle, handshake timeout, hook init
  error, child-injection error, signature/hash/version mismatch, and crash at
  defined lifecycle points.

## Recovery fixtures

- Files at zero, boundary, and over-quota sizes; sparse files; locked files;
  links; secret-tagged files; concurrent destructive operations; and expired
  artifacts.
- A test backup store exposes controllable permission, capacity, encryption,
  indexing, and cleanup failures without touching user recovery locations.
- A hostile hook client requests arbitrary backup destinations and direct store
  access; the harness proves that only trusted Rust coordination has write
  authority.

## Hook robustness fixtures

- Test-only fault points cover loader-lock-sensitive startup, recursion from
  normalization/event/diagnostic code, allocation failure, SEH, thread exit,
  partial hook installation, initialization/shutdown races, and queue counter
  wraparound. Fault points are compiled out of production artifacts and this is
  verified by `BND-008`.
- `hook_transparency_probe` records API return values, NTSTATUS, `LastError`,
  WSA error, callbacks, and completions against sandboxed and unsandboxed
  controls. Only explicit policy decisions may differ.

## Packaging attack fixtures

- A test-owned extraction root can be raced with file replacement, hard links,
  symlinks, junctions, mount points, ACL changes, version mixing, manifest
  rollback, and file locks. Every resolved destructive target is verified to
  remain under this root before cleanup.
- Search-order directories contain signed/unsigned lookalike DLLs with startup
  markers. No marker may run unless its exact file identity is in the signed
  release manifest and trusted component root.

## Secret canaries

Use unique synthetic canaries for command input, environment, policy fields,
file contents, registry values, and broker state. After each applicable test,
scan captured stdout/stderr, events, diagnostics, dumps permitted by the test,
policy serialization, child observations, and recovery metadata. Report only a
hash and source label when a leak is found; never echo the canary itself.

## Compatibility tools

Record exact executable path, signer/hash where appropriate, architecture, and
version for `cmd`, PowerShell, Node, Python, Git, Rust/Cargo, curl, and build
scripts. Test commands operate only in the disposable fixture tree and local
network. Tool discovery happens before the run; unavailable required tools make
the environment ineligible rather than reducing the case count.

## Observation schema

Every probe returns at least:

```text
case_id, fixture_version, process_id, architecture, api_family, operation,
raw_input, normalized_target, return_value, win32_error, ntstatus,
side_effect_nonce, child_ids, start_time, end_time
```

The harness augments this with sandbox events, process exit state, filesystem
and registry snapshots, server observations, recovery records, and redaction
scan results. Raw paths are retained only for test-owned data and are redacted
in published CI artifacts.

Every executable case also carries this metadata:

```text
case_id, requirement_ids, layer, priority, delivery_stage,
required_environment_cells, fixture_versions, deterministic_seed,
expected_terminal_state, expected_error/status, cleanup_contract
```

The result record contains the same identifiers plus component versions and
hashes, host/tool versions, actual observations, artifact references, cleanup
result, and immutable evidence digest. A missing required field is a harness
failure, not a skipped case.
