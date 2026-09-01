# Bolt Windows Sandbox Architecture

## 1. Objective

Build a Windows process sandbox with behavior close to Trae's sandbox while
reusing mature open-source technology. The sandbox is intended to contain
commands and programs launched by an AI coding agent.

The first release must provide:

- Recursive filesystem read and write policies based on normalized paths.
- A writable current work directory and explicit additional grants.
- Child-process policy inheritance.
- Network allow, deny, and unrestricted modes.
- Scoped registry read and write policies for sensitive user configuration.
- Optional recovery backup for destructive filesystem operations.
- Immediate structured violation events.
- Low startup latency suitable for every Bash tool invocation.
- x86 and x64 child-process support on x64 Windows.
- Fail-closed behavior when policy installation or child injection fails.

This is a user-mode command containment boundary. It is not presented as a
kernel security boundary against deliberately malicious native executables.

## 2. Constraints

- Do not recursively mutate filesystem ACLs.
- Do not require Windows Sandbox, Hyper-V, containers, or a kernel driver.
- Do not require administrator privileges for normal operation.
- Do not embed secrets in command lines, environment variables, policy files,
  audit events, or error messages.
- Do not depend on the complete BuildXL runtime or its C# orchestration layer.
- Do not silently run an unsandboxed command when sandbox initialization fails.
- Keep policy and lifecycle ownership in Rust.
- Native hook DLLs may use C or C++ where mature Windows tooling requires it.

## 3. Open-Source Foundation

### 3.1 Microsoft Detours

Use Microsoft Detours under the MIT license for:

- Starting a target process with an injected DLL before application code runs.
- Inline API interception and trampoline management.
- x86/x64 helper-process patterns.
- Reference implementations for process and Winsock tracing.

Do not implement a new instruction decoder or inline-hook engine in Rust.

Source: <https://github.com/microsoft/Detours>

### 3.2 BuildXL DetoursServices

Extract and adapt the minimum required portions of BuildXL's MIT-licensed
Windows sandbox for:

- Comprehensive Win32 and NT filesystem API coverage.
- Path canonicalization and access classification.
- Handle-based rename, delete, truncate, and link handling.
- Child-process monitoring and mixed-architecture support.
- Access reporting and policy enforcement patterns.

Do not import BuildXL scheduling, build graph, C# engine, or BuildXL-specific
manifest protocol. Preserve upstream license notices and record extracted files
and revisions in `THIRD_PARTY_NOTICES.md`.

Sources:

- <https://github.com/microsoft/BuildXL>
- <https://github.com/microsoft/BuildXL/tree/main/Public/Src/Sandbox/Windows/DetoursServices>

### 3.3 Reference-Only Projects

ClawdSecbot demonstrates the desired combination of MinHook, filesystem rules,
Winsock rules, DNS rules, and recursive child injection. Its GPL-3.0 source must
not be copied into Bolt Sandbox unless the project license is intentionally
changed. It is also not sufficiently complete to serve as the security base.

Source: <https://github.com/secnova-ai/ClawdSecbot>

Sandboxie Plus provides a useful comparison for bypass tests and policy
semantics, but its driver-based architecture and GPL license do not match this
project's deployment constraints.

Source: <https://github.com/sandboxie-plus/Sandboxie>

### 3.4 Closed-Source Product Findings

Trae and WorkBuddy are behavioral references only. Their binaries and policies
must not be copied or redistributed.

Static analysis indicates that both products use the same general enforcement
class: a native launcher injects a user-mode DLL that hooks Win32, NT Native,
process creation, and network APIs. Descendant processes receive the same hook,
and an SDK or IPC layer returns audit events to the host application. Neither
product showed evidence of a sandbox-specific kernel driver, AppContainer,
BaseContainer, or VM boundary.

Useful Trae design traits:

- Clear separation between launcher, SDK, injected hook DLL, and IPC helper.
- Explicit read-only, inherited-user, network-allow, and network-deny rules.
- Separate x86 and x64 injection support.
- NT Native filesystem interception rather than only high-level Win32 hooks.

Useful WorkBuddy design traits observed in version 5.3.14:

- `no_access` and `inherit_user` filesystem semantics with deny-by-default write
  behavior.
- Explicit protection for credential locations such as `.ssh` and `.gnupg`.
- Hooks for NT registry APIs in addition to filesystem APIs.
- Network interception spanning Winsock, WinHTTP, and WinInet entry points.
- Separate filesystem and network audit event readers.
- Optional recycle-bin backup before destructive operations.
- Compatibility grants for common package-manager and compiler cache paths.

Weakness shared by both products:

- A deliberately malicious native executable can bypass function-entry hooks by
  issuing direct system calls, restoring hooks, or delegating work to a trusted
  process outside the sandbox.
- User-mode hooks are therefore a fast agent-safety boundary, not a hostile-code
  security boundary.

Bolt Sandbox adopts the useful policy and lifecycle behavior but does not copy
closed-source code. BuildXL and Detours remain the implementation foundation.

### 3.5 Combined Design Decisions

| Capability | Source of the strongest design | Bolt decision |
| --- | --- | --- |
| Filesystem API coverage | BuildXL | Adapt comprehensive Win32 and NT coverage |
| Component isolation | Trae | Keep launcher, hook DLL, SDK boundary, and IPC separate |
| Path policy semantics | Trae and WorkBuddy | Support deny, read-only, read-write, and inherited-user grants |
| Credential protection | WorkBuddy | Add non-overridable sensitive-path denies by default |
| Registry protection | WorkBuddy | Add scoped NT registry policy after filesystem parity |
| Network coverage | WorkBuddy | Cover Winsock, DNS, WinHTTP, and WinInet, backed by a proxy when strict |
| Mixed architecture | BuildXL and Trae | Ship and verify x86 and x64 hook DLLs |
| Destructive recovery | WorkBuddy | Offer bounded backup as defense in depth, never as enforcement |
| Audit reliability | Trae and WorkBuddy | Use one versioned event protocol with typed event categories |
| Strong hostile-code isolation | None of these products | Add a future AppContainer/BaseContainer backend |

Compatibility grants must be explicit policy generated by the trusted Rust
layer. Bolt Sandbox must not dynamically grant access merely because a child
process requested it. An `auto_grant` feature that silently weakens policy is
out of scope.

## 4. Architecture

```text
Bolt Agent
    |
    | Rust API, or bolt-sandbox.exe for command-line integration
    v
bolt-sandbox library
    |-- policy compiler
    |-- process lifecycle manager
    |-- IPC server and event decoder
    |-- architecture selector
    |
    v
bolt-sandbox-launcher.exe or bolt-sandbox-launcher-x86.exe
    |
    | DetourCreateProcessWithDlls, suspended startup
    v
target process
    |-- bolt-sandbox-x64.dll or bolt-sandbox-x86.dll
    |-- filesystem hooks
    |-- registry hooks
    |-- process creation hooks
    |-- Winsock, DNS, WinHTTP, and WinInet hooks
    |-- named-pipe event client
    |
    +---- child process: suspended, inject, verify, resume
```

The Rust library is the public integration boundary. The launcher and DLLs are
private implementation artifacts shipped alongside the application. The CLI is
a thin adapter over the same library and must not contain a second policy or
lifecycle implementation.

## 5. Component Boundaries

### 5.1 Rust Library

Responsibilities:

- Validate and normalize requested policy.
- Generate an immutable per-execution policy payload.
- Create an unpredictable, access-controlled named pipe.
- Select x86 or x64 launcher and hook DLL.
- Start, monitor, time out, and terminate the process tree.
- Stream stdout, stderr, exit status, and sandbox events independently.
- Reject execution if the launcher, DLL, IPC channel, or policy handshake fails.
- Redact secrets before diagnostics leave the trusted process.

Proposed public API:

```rust
pub struct SandboxRequest {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub policy: SandboxPolicy,
    pub timeout: Option<Duration>,
}

pub struct SandboxPolicy {
    pub filesystem: FilesystemPolicy,
    pub registry: RegistryPolicy,
    pub network: NetworkPolicy,
    pub child_processes: ChildProcessPolicy,
    pub recovery: RecoveryPolicy,
}

pub enum SandboxEvent {
    Ready,
    FilesystemViolation(FilesystemViolation),
    RegistryViolation(RegistryViolation),
    NetworkViolation(NetworkViolation),
    RecoveryArtifactCreated(RecoveryArtifact),
    ChildInjectionFailed(ChildInjectionFailure),
    ProcessViolation(ProcessViolation),
    ProcessExited(ProcessExit),
}
```

The API must not expose Detours or BuildXL-specific types.

Request protocol version 1 uses these timeout bounds:

- `None` means no host deadline.
- An explicit timeout is accepted from 1 millisecond through 24 hours,
  inclusive. Zero and values above 24 hours are rejected before launch.
- The library exposes the minimum and maximum as typed constants, and runtime
  deadline measurement uses a monotonic clock.

Request protocol version 1 also applies these pre-launch resource budgets:

- at most 4,096 arguments and 4,096 environment variables;
- at most 32,767 UTF-16 code units in the final Windows command line,
  including its terminating NUL;
- at most 32,767 UTF-16 code units in any one environment name or value; and
- at most 524,288 UTF-16 code units (1 MiB) in the complete sorted Unicode
  environment block, including its double-NUL terminator.

Every maximum is inclusive. A maximum-plus-one input is rejected before native
allocation or process launch, and errors identify only the field and reason.

The Rust launch-preparation transaction produces no launcher input until request
validation, credential stripping, Windows command-line and environment-block
encoding, policy compilation/sealing, target image inspection, and architecture
selection have all succeeded. It generates the execution IPC identity only
after those deterministic checks succeed, so an invalid request consumes no
entropy; CSPRNG failure returns no partial launch preparation. Its result owns
the identity and encoded buffers and retains the already opened program handle
for later file-identity binding; errors expose only typed stages and never
partial buffers, command data, environment values, nonce bytes, or policy
contents.

### 5.2 Launcher

Responsibilities:

- Validate handles and IPC endpoint inherited from the Rust parent.
- Start the entry process suspended.
- Inject the correct hook DLL before user code runs.
- Wait for a positive hook initialization handshake.
- Resume only after successful policy installation.
- Return a structured initialization failure otherwise.

The launcher must not parse agent prompts, settings files, or application
configuration.

Target creation always uses `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; the global
inheritable bit alone never grants a handle to the target. The list contains
only validated policy, event, release, and configured proxy-channel handles.
Ambient files and preconnected sockets are excluded before the suspended image
can execute user code.

The Rust startup coordinator permits only this action order: create suspended,
assign the target to the execution Job, inject the architecture-matched hook,
await authenticated `Ready`, then resume. A callback cannot skip or reorder a
state. Failure before confirmed process creation returns directly; failure from
Job assignment through resume emits one idempotent whole-Job termination action
and reaches failed state only after termination completes. Once running, later
infrastructure failure is handled by the lifecycle controller rather than being
misclassified as an initialization failure.

### 5.3 Hook DLL

Responsibilities:

- Load the immutable policy from a private inherited mapping or pipe.
- Normalize paths before every policy decision.
- Intercept filesystem, registry, process creation, Winsock, DNS, WinHTTP, and
  WinInet entry points.
- Inject the matching DLL into children before they execute.
- Emit bounded, structured events without blocking application threads.
- Deny an operation when policy evaluation cannot be completed safely.

The DLL must not write policy or audit data to world-readable temporary files.

### 5.4 Immutable Policy Payload

Policy payload protocol version 1 uses a deterministic little-endian binary
encoding. The 44-byte envelope contains, in order, the four-byte `BLP1` magic,
a 16-bit version, a 16-bit header length, a 32-bit body length, and a 32-byte
SHA-256 digest. The digest covers the envelope bytes preceding the digest and
the complete body. The body explicitly records child-process behavior and the
canonical filesystem, network, and registry sections; collection order and
ASCII casing do not change the resulting bytes.

The body is limited to 1,048,576 bytes. Both sealing and verification enforce
the limit with checked arithmetic. Verification rejects an unknown version,
invalid header size, oversized or non-exact body length, and digest mismatch
before native policy installation. After digest verification, a bounded,
allocation-free reader validates every section length and wire discriminant and
requires exact body consumption. The digest detects corruption or mutation;
the private mapping ACL and read-only child view prevent an untrusted process
from replacing the body and recomputing the unkeyed digest. The launcher resumes
no process until the mapping and digest have both been verified.

## 6. Filesystem Enforcement

### 6.1 Policy Semantics

Use explicit grants:

- `read_write`: recursively readable and writable paths.
- `read_only`: recursively readable paths.
- `deny`: explicit deny rules that override grants.
- `metadata_read`: narrowly defined system metadata needed to start programs.
- `inherit_user`: preserve the invoking user's access only for explicitly named
  compatibility paths; it never overrides an explicit deny.

The current work directory is the primary `read_write` grant. Parent directories
must not become readable merely because a child path is granted. The runtime may
permit the minimum path traversal metadata required by Windows while denying
content enumeration and file reads outside granted roots.

Filesystem policy protocol version 1 accepts at most 1,024 request rules in
each of `read_write`, `read_only`, `deny`, `metadata_read`, and `inherit_user`,
with at most 2,048 request rules in total. Counts are checked before
normalization or deduplication. A normalized absolute path is limited to 32,767
UTF-16 code units and embedded NUL is rejected before policy sealing so Win32
cannot execute a truncated identity. These maxima are inclusive;
maximum-plus-one fails before policy sealing or process launch with bounded
field-only diagnostics. The
trusted current-directory grant and host-supplied mandatory denies are not
request rules, but remain subject to path and serialized-payload limits.

### 6.2 Required Coverage

At minimum, cover:

- File and directory create/open/read/write/delete.
- Copy, move, rename, replace, and atomic replacement.
- Directory enumeration and metadata probing.
- Handle-based rename, deletion disposition, and truncation.
- Hard links, symbolic links, junctions, and reparse points.
- Memory-mapped writable files.
- Shell file operations used by PowerShell and Explorer-compatible tools.
- Win32 and corresponding NT Native API paths.

The stateless Windows `NUL` device is a distinct safe capability: exact DOS/NT
aliases preserve discard/EOF behavior, while console, pipe, mailslot, and
arbitrary device namespaces remain denied. `CONIN$`/`CONOUT$` are available
only when a trusted creation request assigns a new isolated console; this
capability is integrity-checked in the runtime payload and is never inferred
from an executable name. Default redirected sessions expose no host console.

Every path must be resolved and checked after normalization. Reparse-point and
link targets must be validated to prevent escaping through an allowed path.

### 6.3 Sensitive Paths and Recovery

Default policy denies access to credential-bearing locations such as `.ssh`,
`.gnupg`, browser credential stores, application secret stores, and broker
state. The host may add stricter denies but cannot remove mandatory denies from
an untrusted request.

An optional recovery layer may preserve files before delete, truncate, replace,
or destructive rename operations. Recovery must be:

- Bounded by size, item count, and retention period.
- Stored outside the sandbox-visible namespace.
- Indexed by execution and original normalized path.
- Best-effort defense in depth; backup failure never converts a denied operation
  into an allowed operation.
- Disabled for files identified as secrets unless the backup store provides
  equivalent access control and encryption.

Recovery protocol version 1 requires an absolute, NUL-free trusted storage
directory and nonzero byte/item quotas. The wire types' full nonzero ranges
(`1..=u64::MAX` bytes and `1..=u32::MAX` items) are representable; runtime
reservations use checked additions and commit neither counter when arithmetic or
either quota check fails. Recovery configuration remains in trusted Rust state
and is not serialized into the untrusted hook policy payload.

The trusted configuration also requires a nonzero retention duration no longer
than 365 days. Each execution directory owns an `active.lock` file opened
without delete sharing for the full execution lifetime and a versioned creation
timestamp. Cleanup considers only ordinary `bolt-*` directories with valid
metadata, skips fresh entries, and removes an expired entry only after deleting
its inactive lock succeeds. Reparse points, malformed metadata, inaccessible
entries, and active locks are skipped rather than blocking sandbox startup.
Artifact content and binary path metadata are written under a temporary
artifact directory and committed together by a same-directory rename; failures
remove the temporary directory and consume no quota.

Secret-bearing locations remain mandatory denies and are therefore never
eligible recovery sources unless a future explicitly protected encrypted-store
mode is added. The initial recovery mode does not claim encrypted secret backup.

Recovery is not a substitute for policy enforcement.

## 7. Child Processes

- Intercept all relevant process creation families, not only `CreateProcessW`.
- Force child startup to suspended state when policy inheritance is enabled.
- Select the child DLL based on actual architecture.
- Confirm hook initialization before resuming the child.
- Place all descendants in a Job Object for lifecycle cleanup.
- Terminate the child when mandatory injection fails.
- Emit a structured failure event containing no sensitive command data.

Every intercepted process-creation family rejects an explicit Job breakaway
request before image resolution or child creation, clears caller-visible
process outputs, and emits a typed `Breakaway` process violation. Direct
`NtCreateUserProcess` breakaway flags follow the same rule.

Out-of-process COM activation is an external delegation boundary. The hook
rejects `CLSCTX_LOCAL_SERVER` and `CLSCTX_REMOTE_SERVER` uniformly through
`CoCreateInstance`, `CoCreateInstanceEx`, and `CoGetClassObject`, clears every
caller-visible interface output, and emits a path-free `ExternalDelegation`
event. In-process COM remains available, including the policy-wrapped
`IFileOperation` path.

Shell file association and custom-verb activation are also external delegation
boundaries because Windows may satisfy them through an existing host broker or
an association-selected process outside the confined tree. `ShellExecuteExW`
therefore accepts only a direct executable image with the default `open` verb,
converts that request to the ordinary confined process-creation path, and never
delegates it back to the Shell. Elevation, file associations, class/ID-list
activation, and custom verbs fail closed with a path-free
`ExternalDelegation` event before external code runs.

Injected processes also intercept `SetInformationJobObject`. A Job whose process
list contains the current confined process cannot be reconfigured, even if a
caller obtains a handle with `JOB_OBJECT_SET_ATTRIBUTES`; the attempt returns
`ERROR_ACCESS_DENIED` and emits `MitigationWeakening`. Unrelated Jobs remain
configurable for compatibility.

The initial release supports x64 and x86 on x64 Windows. ARM64 and ARM64EC are a
separate compatibility milestone.

The private launcher also owns the final inheritable handle to the execution
Job while a session is active. Its supervision protocol contains only the Job,
target-ready, host-ready, release, shutdown, and trusted-host process handles;
target paths, command lines, environment data, and secrets never appear in the
launcher command line. Before acknowledging readiness it verifies
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and waits for the target-ready signal with
the same five-second startup bound. It then waits for trusted-host release and
monitors both explicit shutdown and host-process death. If the launcher exits
or crashes before or after readiness, its final Job handle closes and Windows
terminates the still-suspended target or the complete running descendant tree.

The descendant adapter retains the validated policy bytes and creates a fresh,
non-inheritable read-only mapping for every child before duplicating that mapping,
the event channel, private handshake, and configured network-proxy channel
handles into a forcibly suspended child. It never reuses the publicly inherited
parent policy-handle value, so closing and replacing that handle cannot alter or
deny a descendant policy. The proxy authentication key and loopback endpoints remain in
the integrity-checked runtime payload, so an inherited allow-list policy cannot
silently degrade to an unproxied channel. It uses a private descendant readiness
event so the public session has exactly one `Ready` frame, and restores
caller-requested `CREATE_SUSPENDED` semantics before returning.
Readiness waits observe both the private Ready event and the child process handle
with a five-second bound, so loader or mitigation failure is detected immediately
instead of waiting for a handshake timeout. The parent emits a PID-only typed
`ChildInjectionFailed` frame (`UnsupportedArchitecture`, `PolicyUnavailable`,
`InjectionFailed`, `HandshakeFailed`, or `MitigationFailed`) before aborting the
created process. Trusted test payloads may request only a fail-closed mitigation
failure for the next descendant; unknown values and nonzero reserved bytes are
rejected during payload decoding.
For a machine-type mismatch it selects the matching x86/x64 DLL and uses the
Microsoft Detours helper payload and ordinal-1 injection flow. The helper is
started from an absolute Windows system directory with a minimal internal
environment, so target-controlled `PATH`, `WINDIR`, and other environment state
cannot redirect it or receive secrets.

Runtime handles are transferred with capability-specific access, never ambient
inheritance. Policy mappings carry `FILE_MAP_READ`; event clients carry
`FILE_WRITE_DATA`; target and descendant release events carry only
`SYNCHRONIZE`; descendant-ready events carry only `EVENT_MODIFY_STATE`. The
trusted host retains the separate release-control handle. Pipe server, Job,
launcher, host-process, and unrelated inheritable handles are absent from the
target handle list. A write-only client endpoint cannot be upgraded to read,
used with `ImpersonateNamedPipeClient`, or used to create a second server/client
session; duplicate Ready frames are rejected by the session state machine.

Launcher selection parses the target file identity's PE headers rather than
assuming the host architecture or trusting its filename. The parser requires a
complete 64-byte DOS header, `MZ` and `PE\0\0` signatures, a checked in-range
`e_lfanew`, and a complete COFF machine field. Protocol version 1 accepts only
`IMAGE_FILE_MACHINE_I386` and `IMAGE_FILE_MACHINE_AMD64`; ARM64 and every unknown
machine value produce an explicit unsupported-architecture result. Detection
operates on the already opened target handle and reads exactly the 64-byte DOS
header plus the six-byte PE signature/machine prefix; it never allocates or
loads according to the executable's total size.

## 8. Network Enforcement

Supported modes:

- `Unrestricted`: all outbound traffic is allowed.
- `Denied`: outbound traffic is denied except required loopback IPC.
- `AllowList`: only configured domains, IP ranges, and ports are allowed.

`Denied` has no TCP or UDP loopback exception. Its required private runtime IPC
is the authenticated inherited event pipe; that handle remains usable while
ordinary sibling IPv4/IPv6 listeners are unreachable from the target.

Runtime proxy configuration must exactly match the selected mode:
`AllowList` requires the authenticated DNS request/response handles, key,
bounded frame size, and IPv4/IPv6 TCP broker ports; `Unrestricted` and `Denied`
must not carry that configuration. A mismatch aborts DLL initialization before
Ready and before the executable entry point.

Protocol version 1 accepts at most 1,024 domain rules, 1,024 CIDR rules, and
1,024 port ranges, with at most 2,048 network rules in total. These limits are
checked on untrusted input before normalization or duplicate removal. Equivalent
rules compile to one deterministic canonical decision.

Enforcement uses two layers:

1. Hook Winsock, DNS, WinHTTP, and WinInet APIs to enforce policy and report
   violations across common Windows networking stacks.
2. In allow-list mode, route supported traffic through a local policy proxy and
   block direct outbound connections to prevent DNS-to-IP bypass.

WinHTTP and WinInet explicit-proxy sessions enforce two independent decisions:
the requested origin domain and port must be allowed before the request handle
is created, and the proxy server address and port must pass the Winsock policy
when the transport connects. The origin is not resolved locally in this mode;
the application proxy owns that resolution. Numeric IPv4 and IPv6 host strings
are parsed locally by address-info APIs and are still authorized only when the
subsequent endpoint connection passes the address and port rules.
Because policy protocol version 1 has no interface-scope field, any IPv6 socket
endpoint with a nonzero zone/scope ID is rejected rather than silently reduced
to its 128-bit address. IPv4-mapped IPv6 values remain IPv6 identities and do
not inherit IPv4 CIDR grants. Exact hostname rules do not treat a trailing dot
or operating-system localhost aliases as equivalent names.

The local TCP broker also inspects a bounded first HTTP request line when a
client initiates a stream with `CONNECT `. The authority host/address and port
must independently pass policy before any CONNECT bytes reach the upstream
proxy. Malformed or over-4-KiB CONNECT prefaces fail closed. Server-first
protocols and streams whose initial bytes do not match CONNECT remain
transparent.

Required API coverage includes `connect`, `WSAConnect`, `ConnectEx`, synchronous
and asynchronous DNS resolution, IPv4, and IPv6. UDP and custom protocol support
must be explicitly tested and documented rather than implicitly allowed.
Strict modes wrap the `WSASendMsg` extension returned by `WSAIoctl` and reject
RIO multiple-extension tables and unknown provider extension GUIDs. Combined
with denied `sendto` and `WSASendTo`, this keeps unsupported UDP, raw, QUIC, and
provider-specific address-bearing send paths fail closed. Unrestricted mode
passes extension discovery and native errors through unchanged.

Hostname authorization must bind resolved addresses to the authorized hostname
for a bounded lifetime. An IP appearing in an allow-listed DNS response must not
become globally authorized for unrelated processes or sessions.

The trusted DNS broker validates answer ownership before creating bindings. It
follows at most 16 canonical CNAME hops, rejects loops and conflicting aliases,
and accepts only A/AAAA records owned by the final chain name. Unrelated answer
records, zero-TTL records, malformed names, and responses exceeding 64 unique
addresses create no bindings. System resolution is wrapped by a two-second
single-worker deadline; a timeout permanently fail-closes that broker resolver
instance so repeated requests cannot create unbounded stuck threads.

## 9. Registry Enforcement

Registry support follows filesystem parity and uses explicit rules:

- `no_access`: deny reads, writes, enumeration, deletion, and value queries.
- `read_only`: permit queries and enumeration but deny mutation.
- `inherit_user`: preserve normal user permissions for named compatibility keys.
- `read_write`: permit normal user-authorized access to named keys.

Trusted compatibility metadata additionally supports `read_only_key` for one
exact key without granting descendants, and `hide_key` for privacy-preserving
reads that emit a violation but return not-found; hidden-key writes still fail
with access denied. This permits narrow OS version and runtime policy queries
without exposing values such as the user's persistent environment.

Protocol version 1 accepts at most 1,024 rules in each registry category and
2,048 registry rules in total. A normalized absolute key name is limited to 255
UTF-16 code units, matching the Windows registry key-name limit. Counts and
lengths are checked before duplicate removal or rule allocation.

At minimum, intercept create/open/query/set/delete/rename operations at the NT
Native API layer. Mandatory denies protect credential and application security
configuration. Registry virtualization is not required; policy enforcement and
audit events are sufficient for the initial release.

## 10. IPC and Event Reliability

- Use a unique named pipe per sandbox execution.
- Restrict the pipe security descriptor to the current user and participating
  processes.
- Frame messages with version, type, length, sequence number, and checksum.
- Use a bounded non-blocking queue inside the DLL.
- Never block a hooked filesystem or network API on slow event consumption.
- Aggregate repeated violations in the Rust layer, not inside policy decisions.
- Preserve the first occurrence and count dropped duplicate events.
- Treat handshake loss as an initialization failure.

The filesystem hook set is machine-declared in
[`native/hook/filesystem/hooks-manifest.json`](../../native/hook/filesystem/hooks-manifest.json).
Every Windows build compares that manifest with the exact `DetourAttach` pairs,
API coverage claims, architecture/module metadata, and catalog IDs. Hook
installation remains one all-or-nothing transaction; after Ready, an exported
runtime count must equal all required entries plus capabilities marked
`if_present` on that Windows version.

Execution setup obtains 32 bytes in one operating-system CSPRNG request. The
first 16 bytes form a lowercase-hex opaque suffix for
`\\.\pipe\bolt-sandbox-<id>`; the remaining 16 bytes are an independent
handshake nonce and never appear in the endpoint name. Random-source failure
aborts setup without a timestamp, process-ID, counter, or other predictable
fallback. The identity type does not expose nonce-bearing debug output.

Private launcher-start protocol version 2 carries both 16-byte values in its
SHA-256-bound 112-byte header. The launcher validates a nonzero endpoint ID and
nonce before allocating the Job or target, uses only the endpoint ID to create
the protected event-pipe name, and passes only the nonce into the authenticated
`Ready` handshake. Launcher-start v1 is rejected before target creation. Event,
policy, and compatible-component protocol version 1 remain independently
versioned and unchanged.

The Rust violation aggregator has a nonzero configured unique-entry capacity.
Its identity key includes the complete typed event, so process, operation, and
resource differences never collapse. At capacity, a new distinct violation
increments a saturating dropped-distinct counter without replacing an existing
first occurrence; duplicates of retained entries continue incrementing their
saturating duplicate counters. Non-violation lifecycle events bypass this
aggregator.

Event protocol version 1 reserves frame kinds 1 through 9 for `Ready`,
filesystem violation, registry violation, network violation, recovery artifact,
child-injection failure, process exit, and process violation, respectively.
Kind 9 is `EventsDropped` and carries the emitting process identity plus a
nonzero saturating count. The DLL emits it after queue pressure subsides; it is
not itself aggregated as a violation.
Process-violation payloads contain only process identity and a fixed operation
discriminant (`CreateWithToken`, `CreateWithLogon`, or `Elevation`); usernames,
credentials, executable paths, Shell verbs, and command lines are
never serialized. Filesystem and recovery
paths use length-prefixed UTF-16 so Windows paths are not lossily converted;
network sockets use binary IPv4/IPv6 addresses and ports rather than formatted
strings. Event paths are limited to 32,767 UTF-16 code units and UTF-8 text
fields to 4,096 bytes. Decoders reject unknown discriminants, over-limit fields,
invalid UTF-8, truncation, and trailing payload bytes.

The native pipe allocates fixed 128 KiB inbound and outbound buffers per
execution. This exceeds one maximum-size filesystem event frame and leaves
bounded progress space for preceding records during orderly flush. The DLL
still owns only 64 preallocated event records; increasing transport headroom
does not make hook queues unbounded or permit hooked application threads to wait
on a slow consumer.

The Rust event-channel driver owns the session decoder and routes transport
state by lifecycle phase. Protocol failure or disconnect before the execution
enters `Running` remains a typed initialization failure and issues no runtime
Job action. After `Running`, either condition is converted to the matching
infrastructure terminal and its one-shot Job action. EOF after an authenticated
`ProcessExited` frame is classified as clean rather than as channel loss. Each
successfully decoded frame is returned together with its lifecycle action;
`ProcessExited` is atomically routed through the lifecycle controller and
returns `BeginDrain`, while `Ready` and nonterminal security events return no
lifecycle action. This prevents the transport caller from forgetting terminal
state bookkeeping.

Example event:

```json
{
  "version": 1,
  "sequence": 42,
  "kind": "filesystem_violation",
  "operation": "write",
  "path": "C:\\Users\\alice\\secret.txt",
  "decision": "deny",
  "process_id": 1234
}
```

## 11. Security Model

The first release protects against accidental or model-generated boundary
violations by conventional applications and command-line tools.

It does not claim to resist an intentionally malicious executable that uses:

- Direct system calls that bypass hooked user-mode APIs.
- Hook removal, process tampering, or arbitrary code injection.
- A privileged service, kernel driver, or already elevated process.
- Operating-system vulnerabilities.

Mandatory defense-in-depth:

- Run without elevation.
- Strip broker and model credentials from child environments.
- Apply a Job Object and appropriate process mitigation policies.
- Deny access to credential directories and application secrets.
- Fail closed when the sandbox cannot be established.
- Keep dangerous host capabilities behind brokered APIs.

The initial compatibility-safe process mitigation profile is applied inside
the creation attribute list for the initial target and supported
`CreateProcessW/A` descendants before any image code is loaded. The hook verifies the same profile
after the complete hook set is installed but before `Ready` or descendant
readiness is signaled; token-changing and native process APIs retain this
pre-Ready fail-closed verification when Windows cannot accept the owned
creation attribute list. Caller-owned opaque `STARTUPINFOEX` attribute lists are
preserved byte-for-byte and receive the same pre-Ready verification rather than
being rebuilt with dropped attributes. The required irreversible bits
are:

- legacy extension-point disablement; and
- image-load rejection for remote and low-integrity images, with System32
  preference.

Initialization queries the existing policy, only adds required bits, and then
queries it again. A query, application, or verification failure fails sandbox
initialization before user code. Strict invalid-handle termination,
dynamic-code prohibition, Microsoft-only signing, Win32k disablement, and
child-process prohibition are not part of this profile because they would
break transacted-API compatibility probes, Detours injection, JIT-based tools,
shell behavior, or the architecture's confined-child contract. They may only
be added by a separately tested stricter backend/profile.

After readiness, calls to `SetProcessMitigationPolicy` remain available for
additional hardening. Requests for the extension-point or image-load policies
are rejected before reaching Windows when they omit any mandatory bit, and a
typed `MitigationWeakening` process violation is emitted. Malformed buffers and
all unrelated policy classes pass to Windows so native validation and compatible
self-hardening semantics are preserved.

The compatibility matrix runs every tool below this same mitigation profile
with an exact standard-handle list, disposable redirected state, and a
PID-bound denied probe. On x86, Winsock may restore selected export entrypoints
while `WSAStartup` initializes provider dispatch; immediately after successful
startup the hook rewrites those entrypoints back to the existing Detours
trampolines, without a runtime Detours transaction.

If resistance to malicious native binaries becomes a requirement, add an
AppContainer/BaseContainer backend instead of attempting to make DLL hooks a
kernel-grade boundary.

## 12. Repository Layout and Dependency Rules

### 12.1 Layout

```text
bolt-sandbox/
|-- Cargo.toml
|-- build.rs
|-- README.md
|-- THIRD_PARTY_NOTICES.md
|-- docs/
|   |-- architecture/
|   |   `-- windows-sandbox.md
|   |-- security/
|   `-- decisions/
|-- src/
|   |-- lib.rs
|   |-- request.rs
|   |-- policy/
|   |   |-- filesystem.rs
|   |   |-- registry.rs
|   |   |-- network.rs
|   |   `-- compiler.rs
|   |-- runtime/
|   |   |-- process.rs
|   |   |-- architecture.rs
|   |   |-- job.rs
|   |   `-- timeout.rs
|   |-- ipc/
|   |   |-- protocol.rs
|   |   |-- framing.rs
|   |   `-- pipe.rs
|   |-- recovery/
|   |-- event.rs
|   |-- error.rs
|   `-- bin/
|       `-- bolt-sandbox.rs
|-- native/
|   |-- launcher/
|   |-- hook/
|   |   |-- filesystem/
|   |   |-- registry/
|   |   |-- network/
|   |   `-- process/
|   |-- protocol/
|   |-- common/
|   |-- third_party/
|   `-- CMakeLists.txt
|-- tests/
|   |-- fixtures/
|   |-- common/
|   |-- filesystem.rs
|   |-- registry.rs
|   |-- network.rs
|   |-- process_tree.rs
|   |-- recovery.rs
|   |-- failure_modes.rs
|   `-- bypass.rs
`-- scripts/
    |-- build-windows.ps1
    |-- test-windows.ps1
    `-- verify-licenses.ps1
```

Generated binaries must not be committed. Rust and native build output belongs
under `target/` or a CMake build directory.

### 12.2 Boundaries and Dependencies

- `src/lib.rs` is the only public Rust entry point. It re-exports requests,
  policies, events, and structured errors without exposing IPC, Detours, or
  BuildXL types.
- Policy input and compiled policy are distinct types. Only the trusted Rust
  compiler creates the immutable payload consumed by native code.
- The CLI in `src/bin/` depends on the library and contains no duplicate policy
  or process-lifecycle logic.
- The launcher remains small: validate inherited resources, start suspended,
  inject the architecture-matched DLL, verify readiness, and resume or fail.
- Hook areas are separated by capability but share path normalization, protocol,
  and bounded audit infrastructure from `native/common/`.
- Native components depend only on the versioned protocol, never on Rust
  implementation details. Protocol compatibility is tested across x86 and x64.
- Recovery is coordinated by trusted Rust code. Hook DLLs must not independently
  choose or write arbitrary backup locations.
- Tests are organized by externally visible security behavior. Every capability
  covers allowed, denied, inherited, initialization-failure, and bypass cases.

Start with one Rust crate to keep compilation and API evolution simple. Split a
`bolt-sandbox-protocol` crate only when independent fuzzing, reuse, or versioned
release of the protocol justifies the additional boundary.

### 12.3 Interfaces and Distribution

The preferred Bolt Agent integration is the Rust library because it provides
typed requests, streaming events, and direct process-lifecycle control. A thin
`bolt-sandbox.exe` command-line adapter supports standalone testing and callers
from other languages. Its conceptual interface is:

```powershell
bolt-sandbox.exe run --policy policy.json --cwd C:\repo -- command args...
```

The production package contains:

- `bolt-sandbox.exe`, when the CLI integration is required.
- `bolt-sandbox-launcher.exe` and `bolt-sandbox-launcher-x86.exe`, private
  architecture-matched implementation artifacts.
- `bolt-sandbox-x64.dll` and `bolt-sandbox-x86.dll`.

Both launchers and both DLLs must share a compatible protocol version and be
shipped, signed, integrity-checked, and updated as one unit. Packaging may embed
the launcher and DLLs in the Agent-facing executable, but execution still
requires architecture-specific DLLs to be extracted into a per-version,
access-controlled directory. Extraction must be atomic, verify hashes before
use, avoid shared writable temporary directories, and remove stale versions
only when no sandbox process is using them.

## 13. Delivery Plan

### Phase 0: Upstream and License Audit, 2-3 Days

- Pin Detours and BuildXL revisions.
- Identify the minimum source subset and transitive native dependencies.
- Record license notices and modification boundaries.
- Define a reproducible Windows build environment.

Exit condition: legal and technical reuse boundaries are documented.

### Phase 1: Injection Proof of Concept, 1 Week

- Build x64 launcher and hook DLL.
- Start a process suspended and inject before entry point execution.
- Establish the private IPC handshake.
- Return stdout, stderr, exit code, and a `Ready` event to Rust.

Exit condition: `cmd`, PowerShell, Node, Python, and Git start through the
sandbox with measured startup latency.

### Phase 2: Filesystem Policy, 2-3 Weeks

- Adapt BuildXL path handling and filesystem hooks.
- Implement work-directory read/write and external deny behavior.
- Cover links, reparse points, handle operations, and memory mapping.
- Report structured violations.

Exit condition: the filesystem acceptance and bypass suites pass.

### Phase 3: Process Tree, 1-2 Weeks

- Add x86 helper and x86 hook DLL.
- Cover process creation variants.
- Verify injection before child resume.
- Add Job Object lifecycle management and timeout termination.

Exit condition: mixed x86/x64 descendant trees cannot escape policy through
normal process creation APIs.

### Phase 4: Network Policy, 1-2 Weeks

- Add Winsock, DNS, WinHTTP, and WinInet interception.
- Implement unrestricted, denied, and allow-list modes.
- Add local proxy enforcement and DNS/IP binding where required.

Exit condition: network tests pass for PowerShell, curl, Node, Python, and Git.

### Phase 5: Registry and Recovery, 1-2 Weeks

- Add scoped NT registry enforcement and typed audit events.
- Add mandatory protection for sensitive registry keys.
- Add bounded recovery backup for configured destructive filesystem operations.
- Verify that compatibility grants cannot override mandatory denies.

Exit condition: registry and recovery acceptance suites pass without weakening
the filesystem boundary.

### Phase 6: Production Hardening, 2-4 Weeks

- Fuzz policy parsing and IPC framing.
- Test crashes, timeouts, pipe backpressure, and injection failures.
- Run compatibility and bypass suites on supported Windows releases.
- Add signed release artifacts and reproducible CI builds.
- Measure startup, memory, and command throughput overhead.

Exit condition: no unsandboxed fallback exists and all release gates pass.

Estimated total with two experienced engineers: 7-12 calendar weeks, or about
14-24 engineer-weeks. Registry enforcement and recovery are independently
shippable after the core Trae-equivalent boundary is stable.

## 14. Test Strategy

The executable test program is specified by
[`docs/testing/test-plan.md`](../testing/test-plan.md), the behavioral inventory
by [`docs/testing/test-catalog.md`](../testing/test-catalog.md), and reusable
fixture contracts by [`docs/testing/fixtures.md`](../testing/fixtures.md). These
documents derive from this architecture. Stable requirement-to-case mappings
are maintained in
[`docs/testing/requirements-matrix.md`](../testing/requirements-matrix.md).
Required native operation families and representative entry points are tracked
in [`docs/testing/api-coverage.md`](../testing/api-coverage.md).
Conflicts are resolved by changing the architecture decision first and updating
the mapped cases in the same change.

### 14.1 Filesystem Acceptance

- Read and write inside the work directory.
- Deny reads and writes outside all grants.
- Deny parent enumeration when only a child directory is granted.
- Verify relative paths, UNC paths, device paths, alternate data streams, short
  names, case variations, and long paths.
- Verify hard-link, symlink, junction, reparse-point, rename, replace, delete,
  truncate, and memory-mapped write escapes.

### 14.2 Process Acceptance

- Test `cmd`, PowerShell, Node, Python, Git, Rust compiler, and build scripts.
- Test x64 parent to x86 child and x86 parent to x64 child.
- Test nested descendants, detached processes, background services, timeouts,
  crashes, and forced termination.
- Assert that injection failure terminates the affected process.

### 14.3 Network Acceptance

- Validate IPv4, IPv6, domain names, redirects, proxies, and direct IP access.
- Validate synchronous and asynchronous DNS.
- Confirm allow-listed domains do not authorize unrelated destinations.
- Confirm child processes inherit the same network policy.

### 14.4 Registry and Recovery Acceptance

- Verify query, enumeration, create, set, rename, and delete behavior for each
  registry rule type.
- Confirm mandatory sensitive-key denies override compatibility grants.
- Verify recovery for delete, truncate, replace, and destructive rename.
- Confirm recovery quotas and retention cleanup cannot block hooked operations.
- Confirm secret files are not copied into an inadequately protected backup.

### 14.5 Security and Reliability

- Attempt Native API and alternate process-creation bypasses.
- Include a direct-syscall fixture that documents and continuously demonstrates
  the expected limitation of standard mode.
- Attempt DLL unload and hook overwrite; document unsupported malicious cases.
- Saturate the event channel and confirm target processes do not deadlock.
- Kill the Rust parent, launcher, IPC endpoint, and target independently.
- Scan all logs and events for secrets.

## 15. Release Gates

A release is blocked unless:

- Sandbox initialization is fail-closed.
- Supported filesystem operations have explicit tests.
- Mandatory filesystem and registry denies cannot be weakened by child input.
- Child injection failures cannot resume unconfined children.
- The policy cannot be weakened by untrusted child input.
- No secret reaches child environment, command line, policy, event, or log data.
- All supported Windows and architecture combinations pass CI.
- Launcher and hook DLL signatures, hashes, and protocol versions are verified
  before execution.
- Startup latency and memory overhead remain within an agreed budget.
- Third-party notices and pinned source revisions are complete.

Initial performance targets:

- Warm sandbox startup overhead: under 100 ms on a representative workstation.
- Hook initialization handshake: under 50 ms.
- Steady-state filesystem overhead: target below 5% for common development
  workloads, measured rather than assumed.
- No unbounded queues or per-operation disk logging in hook paths.

## 16. Decisions

Accepted:

- Rust owns public APIs, policy, process lifecycle, and events.
- The Rust library is the preferred Agent interface; an optional CLI is a thin
  adapter for standalone and cross-language use.
- Releases are a compatible component set containing x64/x86 launchers and
  x86/x64 hook DLLs, even when packaging presents a single executable to the
  user.
- Begin with one Rust crate and split the protocol only when reuse, fuzzing, or
  independent versioning requires it.
- Detours and selected BuildXL native code provide the Windows hook foundation.
- Native DLLs are permitted; a pure-Rust hook engine is not a project goal.
- Network access is unrestricted by default initially, with configurable denied
  and allow-list modes available.
- WorkBuddy-style registry protection, broader Windows network-stack coverage,
  and bounded destructive-operation recovery are adopted as staged additions.
- Compatibility grants are trusted static policy, never request-driven automatic
  authorization.
- Hook-based isolation is clearly documented as user-mode containment.
- An elevated host token is unsupported in the initial release and is rejected
  before target creation. Shell elevation and job-breakaway child creation are
  denied before child user code.
- `CreateProcessAsUser` is supported only for an explicitly supported
  non-elevated token class. `CreateProcessWithToken` and
  `CreateProcessWithLogon` are denied in the initial release rather than
  risking an uninstrumented token boundary.
- Loss or integrity failure of the authenticated event/IPC channel after
  readiness terminates the execution Job Object. Audit loss never leaves a
  silently running process tree. The lifecycle records event-channel loss and
  protocol-integrity failure as distinct infrastructure terminal states,
  requests whole-Job termination at most once, and completes after stdout,
  stderr, and the failed event channel reach EOF. It does not fabricate a
  `ProcessExited` event when the authenticated channel can no longer provide
  one.
- A network rule `*.example.com` matches one or more subdomain labels, not the
  apex or suffix lookalikes. Unsupported network stacks are denied in `Denied`
  and `AllowList`; `Unrestricted` preserves normal user-authorized behavior.
- Transactional and remote registry operations are denied as unsupported in the
  initial release.
- Recovery failure does not alter the original filesystem decision: an allowed
  destructive operation proceeds with a typed recovery-failure event, while a
  denied operation remains denied. Secret-tagged recovery requires equivalent
  ACLs and encryption at rest.
- Library stdout and stderr are byte streams. If a receiver disappears, trusted
  code drains and discards within configured memory bounds so lifecycle cleanup
  cannot deadlock; the loss is reported as typed stream state. Each stream uses
  an independent fixed-capacity byte buffer, preserves bytes without decoding,
  distinguishes capacity overflow from receiver disconnection, counts discarded
  bytes with saturation, and commits EOF exactly once. Disconnecting a receiver
  discards already buffered and future bytes without affecting the other stream.
  The lifecycle completion result independently flags lost stdout, stderr, and
  public event receivers; recording receiver loss is idempotent and does not
  itself cancel the execution.
- Lifecycle terminal state uses the earliest atomically committed monotonic
  trigger. An exact-tick tie resolves cancellation before timeout before natural
  exit, and terminal cleanup/event emission occurs exactly once. The host-side
  controller emits at most one whole-Job termination action and does not enter
  `Completed` until stdout EOF, stderr EOF, the typed terminal `ProcessExited`
  event, and event-channel EOF have all been observed for process terminal
  states. A post-readiness event-channel failure instead completes with its
  typed infrastructure terminal after stream/channel EOF. Event EOF without a
  process terminal event or a committed infrastructure failure is not a
  successful exit. A
  committed timeout accepts only a `TimedOut` terminal reason and cancellation
  only `Terminated`; a mismatched event is rejected without consuming the
  terminal slot. An authenticated natural `ProcessExited` frame may arrive
  before the Windows process wait handle is observed; while `Running`, that
  frame atomically commits the natural-exit drain transition, and the later
  wait signal is idempotent.
- Component verification binds execution/loading to the verified file identity
  and trusted directory, preventing replacement and DLL search-order races
  between verification and load.
- Release configuration names required process mitigations and absolute/growth
  budgets for memory, handles, and threads. A missing mitigation or performance
  budget blocks release rather than becoming an implicit pass.

Deferred:

- Windows ARM64 and ARM64EC.
- AppContainer/BaseContainer hardened backend.
- Kernel-driver enforcement.
- Registry virtualization.
- Full hostile-binary containment guarantees.
