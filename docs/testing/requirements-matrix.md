# Architecture Requirements Traceability Matrix

Status values in this file describe specification coverage only:

- `Specified`: one or more catalog cases define observable acceptance criteria.
- `Deferred`: architecture explicitly excludes the capability from the initial
  release and cases verify that it is reported as unsupported.
- `RED`, `GREEN`, and `Verified` are reserved for future machine-generated CI
  evidence and must not be entered manually in this planning-phase document.

Every normative architecture change must add/update a stable requirement ID and
its mapped case IDs in the same commit. Every executable test must report both
its catalog case ID and requirement IDs in machine-readable results.

## Public boundary and policy ownership

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-API-001 | Rust library is the public integration boundary | REQ-013, BND-005 | Specified |
| ARC-API-002 | Public API exposes typed requests, events, lifecycle, and errors without Detours/BuildXL types | REQ-013, EVT-001, BND-005 | Specified |
| ARC-API-003 | CLI is a thin adapter over the library | REQ-014, BND-006, PKG-008 | Specified |
| ARC-API-004 | Rust validates and normalizes requests/policies | REQ-001..012, POL-001..027 | Specified |
| ARC-API-005 | Policy input and compiled immutable policy are distinct | POL-010..011, BND-005, SEM-008..011 | Specified |
| ARC-API-006 | Policy and lifecycle ownership remains in trusted Rust | POL-007..010, REC-018..019, BND-004..007 | Specified |
| ARC-API-007 | stdout, stderr, events, and exit status stream independently | LIFE-001..003, LIFE-009..013 | Specified |
| ARC-API-008 | Diagnostics leaving trusted process redact secrets | REQ-006, EVT-008..009, SEC-006..007 | Specified |

## Cross-runtime semantic consistency

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-SEM-001 | Rust reference and x86/x64 native engines agree on filesystem identity, access classification, precedence, and decisions | SEM-001..004, SEM-010..012 | Specified |
| ARC-SEM-002 | Rust reference and x86/x64 native engines agree on registry semantics | SEM-005, SEM-008..011 | Specified |
| ARC-SEM-003 | Compiler/proxy and native hooks agree on network rules and DNS binding scope | SEM-006..011 | Specified |
| ARC-SEM-004 | Unknown and boundary protocol/policy values cannot change meaning across ABI/architecture | SEM-008..009, IPC-015..016 | Specified |

## Platform and deployment constraints

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-CON-001 | No recursive filesystem ACL mutation | SEC-016 | Specified |
| ARC-CON-002 | No VM, Hyper-V, container, or kernel-driver dependency | SEC-015, BND-008, LIC-004 | Specified |
| ARC-CON-003 | Normal operation requires no administrator privilege | SEC-005, SEC-015 | Specified |
| ARC-CON-004 | Secrets never enter command line, environment, policy, events, diagnostics, or logs | REQ-004..006, EVT-009, SEC-006..007, SEC-017 | Specified |
| ARC-CON-005 | No full BuildXL runtime/C# orchestration dependency | BND-004, LIC-002 | Specified |
| ARC-CON-006 | No unsandboxed fallback on initialization failure | IPC-010..014, SEC-001..005, GATE-001 | Specified |
| ARC-CON-007 | x86 and x64 children are supported on x64 Windows | PROC-001..006, COMPAT-008 | Specified |
| ARC-CON-008 | ARM64/ARM64EC is explicitly unsupported in initial release | PROC-015, COMPAT-009 | Deferred |

## Launcher, hook, and component boundaries

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-CMP-001 | Launcher validates inherited handles and IPC endpoint | IPC-010..012, IPC-021..024 | Specified |
| ARC-CMP-002 | Entry process starts suspended and resumes only after policy/hook readiness | PROC-001..002, IPC-012 | Specified |
| ARC-CMP-003 | Launcher selects and injects architecture-matched DLL | PROC-001..006, PROC-030 | Specified |
| ARC-CMP-004 | Launcher returns structured initialization failures | PROC-014..015, SEC-001..004 | Specified |
| ARC-CMP-005 | Launcher does not parse prompts, settings, or application configuration | BND-001..002 | Specified |
| ARC-CMP-006 | Hook loads immutable policy from private inherited channel | POL-010, IPC-011, IPC-021..023, SEC-008 | Specified |
| ARC-CMP-007 | Hook normalizes before every decision and denies undecidable operations | FS-011..026, SEM-003..004, HOOK-002, HOOK-005..006 | Specified |
| ARC-CMP-008 | Hook emits bounded structured events without blocking application threads | EVT-004..012, HOOK-011..012 | Specified |
| ARC-CMP-009 | Hook writes no policy/audit data to world-readable temporary files | BND-003, BND-008 | Specified |
| ARC-CMP-010 | Native components depend only on versioned protocol, not Rust internals | IPC-015, BND-004 | Specified |
| ARC-CMP-011 | Required hooks install completely before readiness | HOOK-001, HOOK-003, HOOK-009 | Specified |
| ARC-CMP-012 | Hook execution is reentrant, exception-safe, and shutdown-safe | FS-064, HOOK-001..012 | Specified |

## Filesystem policy and enforcement

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-FS-001 | Cwd is recursive read-write and supports explicit additional grants | POL-001, FS-001..003 | Specified |
| ARC-FS-002 | `deny` overrides all grants; mandatory denies cannot be removed | POL-003, POL-007, POL-024, FS-005..006, FS-049..050 | Specified |
| ARC-FS-003 | `read_only`, `read_write`, `metadata_read`, and `inherit_user` have defined non-elevating semantics | POL-002..006, FS-003..010 | Specified |
| ARC-FS-004 | Granting a child does not expose its parent | POL-002, FS-010, FS-042..043 | Specified |
| ARC-FS-005 | Create/open/read/write/delete/copy/move/rename/replace are enforced | FS-001..009, FS-029..041 | Specified |
| ARC-FS-006 | Enumeration and metadata probing are enforced | FS-010, FS-042..044, FS-061 | Specified |
| ARC-FS-007 | Handle-based rename/delete/truncate/link and access amplification are enforced | FS-026..036, FS-045..047, FS-060 | Specified |
| ARC-FS-008 | Hard links, symlinks, junctions, and reparse targets cannot escape | FS-021..028, FS-035, BYP-005..006 | Specified |
| ARC-FS-009 | Writable mappings and image/section variants cannot bypass writes/reads | FS-037..038, FS-062 | Specified |
| ARC-FS-010 | Win32, NT Native, shell, relative/UNC/device/ADS/short/long/case paths are covered | FS-011..020, FS-041, FS-051..054 | Specified |
| ARC-FS-011 | Final-object/path race and asynchronous operations remain enforced | FS-024, FS-048, FS-057..060, BYP-005..006 | Specified |
| ARC-FS-012 | Credential-bearing filesystem paths are mandatory denies | FS-049..050, SEC-017 | Specified |
| ARC-FS-013 | Ordinary OS errors and thread error state remain transparent | FS-055, FS-063, HOOK-010 | Specified |

## Child processes and lifecycle

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-PROC-001 | Relevant Win32, shell, and NT process creation families are intercepted | PROC-009, PROC-025..029, BYP-002 | Specified |
| ARC-PROC-002 | Children are forced suspended, injected, verified, then resumed | PROC-003..009, PROC-025 | Specified |
| ARC-PROC-003 | Actual child architecture chooses x86/x64 hook | PROC-004..006, PROC-030 | Specified |
| ARC-PROC-004 | Injection failure terminates child before user code and emits redacted event | PROC-014, SEC-004 | Specified |
| ARC-PROC-005 | All descendants join Job Object and remain monitored | PROC-007, PROC-011..013, PROC-018..019, PROC-023..024, LIFE-003..007 | Specified |
| ARC-PROC-006 | Child input cannot weaken or dynamically grant policy | POL-009, PROC-016..017, PROC-034 | Specified |
| ARC-PROC-007 | Required process mitigations are applied and cannot be weakened | PROC-031..034 | Specified |
| ARC-PROC-008 | Timeout/cancellation/crash terminate the entire tree deterministically | LIFE-003..008, LIFE-014..015 | Specified |
| ARC-PROC-009 | stdout/stderr/event terminal ordering and backpressure are bounded | LIFE-001..002, LIFE-009..016, EVT-006..012 | Specified |
| ARC-PROC-010 | Executable paths and compatibility tools preserve launch semantics | PROC-010, PROC-022, COMPAT-001..019 | Specified |

## Network policy

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-NET-001 | Modes are `Unrestricted`, `Denied`, and `AllowList`; default is explicit `Unrestricted` | POL-015..016, NET-001..012 | Specified |
| ARC-NET-002 | Winsock, DNS, WinHTTP, and WinInet are enforced on x86/x64 | NET-003..006, NET-022, SEM-006 | Specified |
| ARC-NET-003 | `connect`, `WSAConnect`, `ConnectEx`, sync/async DNS, IPv4, and IPv6 are covered | NET-001..006, NET-022..024 | Specified |
| ARC-NET-004 | Strict allow-list routes supported traffic through proxy and blocks direct bypass | NET-008..009, NET-018..020, NET-026 | Specified |
| ARC-NET-005 | Hostname authorization binds address/port/session/process for bounded TTL | NET-013..017, NET-023, SEM-007 | Specified |
| ARC-NET-006 | DNS authorization never becomes global across names/processes/sessions | NET-014..016, NET-021, SEM-007 | Specified |
| ARC-NET-007 | UDP/custom/unsupported protocol behavior is explicit, never implicitly allowed | NET-004, NET-025 | Specified |
| ARC-NET-008 | Required runtime loopback exception cannot authorize arbitrary loopback | NET-007 | Specified |
| ARC-NET-009 | Invalid rules and policy limits fail validation | POL-016..019, POL-022, POL-026 | Specified |
| ARC-NET-010 | Inherited sockets cannot bypass policy and ordinary network errors remain transparent | NET-027..028, BYP-007..008, HOOK-010 | Specified |

## Registry policy

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-REG-001 | `no_access`, `read_only`, `inherit_user`, and `read_write` semantics are enforced | REG-001..007 | Specified |
| ARC-REG-002 | Mandatory sensitive-key denies override grants | POL-008, REG-008..009 | Specified |
| ARC-REG-003 | NT create/open/query/set/delete/rename operations are intercepted | REG-001..006, REG-013..016 | Specified |
| ARC-REG-004 | Aliases, WOW64 views, links, handles, and races cannot bypass policy | REG-010..014, REG-018, BYP-004 | Specified |
| ARC-REG-005 | Sandbox adds no user rights and preserves ordinary OS failures | REG-005..006, REG-019 | Specified |
| ARC-REG-006 | Registry events disclose no protected values | REG-020, EVT-009 | Specified |
| ARC-REG-007 | Registry virtualization is not claimed | REG-017, COMPAT-009 | Deferred |

## IPC and event reliability

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-IPC-001 | Unique unpredictable pipe per execution with restricted ACL | IPC-001..003, IPC-017, IPC-022..024 | Specified |
| ARC-IPC-002 | Frames include version, type, length, sequence, and checksum | IPC-004..009, IPC-015..016, IPC-023 | Specified |
| ARC-IPC-003 | Handshake loss/mismatch/replay/spoof and post-ready integrity failure fail closed | IPC-012..014, IPC-017..021, IPC-025 | Specified |
| ARC-IPC-004 | Queue is bounded/non-blocking and preserves first event/drop counts | EVT-004..007, EVT-010, HOOK-011 | Specified |
| ARC-IPC-005 | Rust aggregates duplicates outside policy decision path | EVT-004..005, FS-056, NET-029 | Specified |
| ARC-IPC-006 | Events are typed, ordered, process-attributed, and redacted | EVT-001..003, EVT-008..012 | Specified |
| ARC-IPC-007 | x86/x64 native and Rust protocol representations are compatible | IPC-015, SEM-008..009 | Specified |
| ARC-IPC-008 | Every event is attributed to one execution, opaque command ID, and nonzero immutable policy generation | ATTR-001..006, EVT-013 | Specified |

## Transactional Agent workspaces and interaction

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-WS-001 | Workspace behavior is selected through a trusted `WorkspaceBackend`; Direct preserves current semantics and automatic transactional selection never chooses Direct | WS-001..003, WS-025 | Specified |
| ARC-WS-002 | ProjFS is optional and never replaces filesystem/process/network/registry enforcement | WS-004..006, SEC-019 | Specified |
| ARC-WS-003 | Projected or staged execution cannot expose or write the source workspace, sibling transactions, or mandatory-deny content directly or through path aliases | WS-007..010, WS-021..024, BYP-005..008 | Specified |
| ARC-WS-004 | Projection/provider/IPC failure terminates or rejects execution without direct fallback | WS-011..013, GATE-001 | Specified |
| ARC-WS-005 | Query, commit, discard, and revert operate on a bounded per-session change journal | WS-014..017, REC-020..021 | Specified |
| ARC-WS-006 | Commit revalidates source identity and refuses external conflicts or partial application | WS-018..020, REC-022 | Specified |
| ARC-PTY-001 | PTY is an explicit capability and noninteractive pipe execution remains the default | PTY-001..003, COMPAT-011 | Specified |
| ARC-PTY-002 | PTY descendants remain in the Job with inherited policy and hooks | PTY-004..006, PROC-003..013 | Specified |
| ARC-PTY-003 | PTY handles cannot authorize arbitrary named-pipe or cross-process access | PTY-007..009, FS-053 | Specified |
| ARC-BRK-001 | Any prewarmed broker holds verified read-only state but creates fresh per-command authority | BRK-001..004 | Specified |
| ARC-BRK-002 | Broker loss, stale state, or policy mismatch fails closed and terminates associated Jobs | BRK-005..008 | Specified |
| ARC-BRK-003 | Broker deployment is evidence-gated and omitted when startup benefit is immaterial | BRK-009..010, PERF-015 | Specified |

## Recovery

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-REC-001 | Delete/truncate/replace/destructive rename can be backed up before mutation | REC-001..003 | Specified |
| ARC-REC-002 | Recovery is bounded by size/count/retention and indexed by execution/path | REC-006..008, REC-013..014, PERF-009 | Specified |
| ARC-REC-003 | Recovery is best effort and never weakens enforcement | REC-004..005, REC-009, REC-017 | Specified |
| ARC-REC-004 | Recovery store is outside sandbox namespace and initial mode never copies secret-tagged files without encrypted storage | REC-010, REC-012..016, REC-019 | Specified |
| ARC-REC-005 | Trusted Rust selects/writes recovery destination; hook cannot choose it | REC-018..019, BND-007 | Specified |
| ARC-REC-006 | A future protected encrypted store may back up secret-tagged files | REC-011 | Deferred |

## Security model and bypass disclosure

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-SEC-001 | Boundary protects conventional accidental/model-generated violations | FS, PROC, NET, REG acceptance groups | Specified |
| ARC-SEC-002 | Direct syscalls, hook tampering, privileged brokers, and hostile native code are not claimed contained | SEC-009..012, BYP-001..012 | Specified |
| ARC-SEC-003 | Dangerous host capabilities remain behind trusted broker APIs | PROC-020..021, SEC-012 | Specified |
| ARC-SEC-004 | Child environment strips broker/model credentials | REQ-006, SEC-017 | Specified |
| ARC-SEC-005 | Policy, events, queues, and diagnostics stay bounded under hostile input | REQ-012, IPC-005..009, EVT-006..009, SEC-014, SEC-018 | Specified |
| ARC-SEC-006 | Parent/launcher/target/IPC failures never leave silent unconfined descendants | LIFE-003..008, SEC-013 | Specified |
| ARC-SEC-007 | AppContainer/BaseContainer is future hardened backend | COMPAT-009, deferred section | Deferred |

## Distribution, licensing, compatibility, and performance

| Requirement ID | Architecture requirement | Catalog evidence | Status |
| --- | --- | --- | --- |
| ARC-DIST-001 | CLI, x64/x86 launchers, and x86/x64 DLLs ship as one compatible release | PKG-001, PKG-015 | Specified |
| ARC-DIST-002 | Signatures, hashes, and protocol versions are verified before execution | SEC-001..003, PKG-002, PKG-009..015 | Specified |
| ARC-DIST-003 | Embedded extraction is atomic, per-version, access-controlled, and not shared writable temp | PKG-003..006, PKG-010, PKG-016 | Specified |
| ARC-DIST-004 | Loaded image identity cannot change after verification or via DLL search order | PKG-009..014 | Specified |
| ARC-DIST-005 | Generated binaries/build directories are not committed | PKG-007 | Specified |
| ARC-LIC-001 | Detours/BuildXL revisions and native inputs are pinned | LIC-001, LIC-004 | Specified |
| ARC-LIC-002 | Notices, origins, modifications, and transitive dependencies are recorded | LIC-002, LIC-005 | Specified |
| ARC-LIC-003 | GPL and closed-source references are not copied | LIC-003, BYP-012, BND-008 | Specified |
| ARC-COMP-001 | Required tools and Windows/architecture matrix pass | COMPAT-001..019 | Specified |
| ARC-PERF-001 | Warm startup overhead target is under 100 ms | PERF-001, PERF-004, PERF-010 | Specified |
| ARC-PERF-002 | Hook handshake target is under 50 ms | PERF-002, PERF-004 | Specified |
| ARC-PERF-003 | Filesystem overhead target is below 5% for defined workloads | PERF-003, PERF-010 | Specified |
| ARC-PERF-004 | Memory, handles, threads, queues, logging, and recovery remain bounded | PERF-005..009, PERF-011..014 | Specified |
| ARC-PERF-005 | Missing/invalid benchmark evidence cannot pass release | PERF-010..014 | Specified |

## Matrix maintenance gate

CI must fail when any of the following is true:

1. an architecture requirement ID has no catalog case;
2. a catalog case cites no requirement ID after executable metadata exists;
3. an unknown or duplicate requirement/case ID appears;
4. a release-gate requirement has no result for a required environment cell;
5. a result says `pass` but lacks its required side-effect, event, redaction, or
   cleanup observations; or
6. a manually edited document claims `RED`, `GREEN`, or `Verified` without a
   matching immutable CI evidence record.
