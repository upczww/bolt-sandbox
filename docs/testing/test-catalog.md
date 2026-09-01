# Bolt Sandbox Test Catalog

Status: authoritative behavioral case inventory

Unless a row says otherwise, each integration case uses a fresh execution and
the disposable fixtures in `fixtures.md`. “Denied” means the API reports the
stable policy-denial error, no prohibited side effect occurs, and exactly one
first-occurrence violation is observable with the normalized target and correct
process identity. Repeated-event count behavior is tested separately.

## Request and policy compilation

| ID | Scenario | Expected observation |
| --- | --- | --- |
| REQ-001 | Submit the smallest valid request with an absolute program and cwd | Validation succeeds without changing caller input |
| REQ-002 | Program is empty, relative, missing, or a directory | Validation rejects before launcher start with a typed field error |
| REQ-003 | Cwd is empty, relative, missing, or not a directory | Validation rejects before launcher start with a typed field error |
| REQ-004 | Arguments contain spaces, quotes, empty values, Unicode, and trailing backslashes | Child receives the exact `OsString` argument sequence; diagnostics do not reconstruct a secret-bearing command line |
| REQ-005 | Environment contains empty, Unicode, case-colliding, malformed, and reserved names | Valid entries round-trip; invalid/colliding entries are deterministically rejected |
| REQ-006 | Environment contains configured broker/model credential names | Credentials are stripped before child creation and a redacted diagnostic is emitted |
| REQ-007 | Timeout is zero, boundary minimum, normal, maximum, or overflowing | Documented bounds are accepted; invalid values are rejected without launch |
| REQ-008 | Policy lists are empty | Compiler applies defaults, including cwd write grant and mandatory denies |
| REQ-009 | Input contains duplicate and differently cased equivalent paths | Compiled policy is canonical and deduplicated |
| REQ-010 | Equivalent policies are supplied in different order | Immutable payload bytes/hash are identical |
| REQ-011 | Unknown policy or request version is supplied | Typed unsupported-version error; nothing launches |
| REQ-012 | Oversized request, argument, environment, or rule count | Bounded validation rejects without unbounded allocation or secret echo |
| REQ-013 | Public API types are compiled by an external test crate | Only request, policy, event, lifecycle, and structured error types are public; no Detours/BuildXL/native protocol types leak |
| REQ-014 | CLI and library receive semantically identical requests | They produce the same compiled policy and externally visible lifecycle behavior |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| POL-001 | Cwd is not explicitly listed | Cwd becomes recursive `read_write` |
| POL-002 | Child is granted but its parent is not | Only traversal metadata needed for the child is available; parent enumeration/content read remains denied |
| POL-003 | `deny` overlaps `read_write`, `read_only`, or `inherit_user` | `deny` wins for the overlapping normalized target |
| POL-004 | `read_only` overlaps `read_write` at different depths | Most-specific valid grant wins except any explicit or mandatory deny |
| POL-005 | `metadata_read` is used for a system path | Required metadata/startup succeeds; content read, enumeration, and mutation remain denied |
| POL-006 | `inherit_user` names an accessible and an OS-denied path | Sandbox adds no rights; normal user authorization remains decisive |
| POL-007 | Untrusted broad grant overlaps a mandatory filesystem deny | Compilation succeeds with the canonical mandatory deny still dominant in the immutable payload |
| POL-008 | Untrusted broad grant overlaps a mandatory registry deny | Compilation succeeds with the canonical mandatory deny still dominant in the immutable payload |
| POL-009 | Child sends a request for a dynamic compatibility grant | Grant is ignored/denied and policy hash remains unchanged |
| POL-010 | A compiled payload is modified after compilation | Integrity check fails and launch is fail-closed |
| POL-011 | Separately compiled policies run concurrently | Execution identifiers, mappings, pipes, and decisions do not cross sessions |
| POL-012 | Normalized roots collide through case, separators, dot segments, or namespace aliases | One canonical precedence decision is produced |
| POL-013 | Policy contains a path that cannot be normalized safely | Compilation fails closed with a typed, redacted error |
| POL-014 | Policy contains unsupported architecture or capability | It is rejected explicitly, never downgraded silently |
| POL-015 | Network mode is omitted | Compiler selects `Unrestricted`, records it explicitly in the immutable payload, and does not infer a stricter/weaker mode from empty lists |
| POL-016 | `Denied` or `Unrestricted` is combined with allow-list entries | Compiler rejects the contradictory policy instead of silently discarding entries |
| POL-017 | Domain rule is empty, overlong, malformed, contains a scheme/path/port, invalid wildcard, trailing-dot ambiguity, or invalid IDN | Compiler rejects it with a field-scoped error and no launch |
| POL-018 | IPv4/IPv6 CIDR is malformed, non-canonical, has an invalid prefix, or contains zone syntax where forbidden | Compiler rejects it without truncation or permissive reinterpretation |
| POL-019 | Port/range is zero where unsupported, above 65535, reversed, overlapping, or duplicated | Invalid ranges are rejected; equivalent valid ranges canonicalize deterministically |
| POL-020 | Registry root/rule is empty, malformed, unsupported, duplicated, or mixes incompatible views | Invalid rules are rejected and valid equivalents canonicalize deterministically |
| POL-021 | Filesystem rule names a nonexistent absolute local path that is created after compilation | Compiler records its canonical lexical identity without granting its parent; the later object receives the same rule decision |
| POL-022 | Rule count, normalized path length, domain length, CIDR count, and serialized payload meet exact maxima and maxima+1 | Maxima compile; maxima+1 fail before allocation/launch with bounded diagnostics |
| POL-023 | Recovery quotas have zero, boundary, maximum, overflow, or internally inconsistent values | Supported boundary values compile; overflow and inconsistent values are rejected |
| POL-024 | Mandatory deny input is duplicated, nested, or textually aliased by an untrusted grant | Compiler emits one canonical non-removable deny and deterministic payload bytes |
| POL-025 | Child-process inheritance is disabled for a request that attempts to spawn descendants | Policy explicitly denies descendant creation rather than permitting an uninstrumented child |
| POL-026 | Unknown fields are present in a versioned JSON/CLI policy | Strict parser rejects unknown security-relevant fields; no typo is silently ignored |
| POL-027 | Filesystem rule names an unavailable remote/removable volume or an identity that cannot be resolved safely | Compilation rejects the rule before launch; no lexical fallback broadens it |

## Cross-runtime policy semantics

Every `SEM` case feeds the same canonical vector to the trusted Rust compiler
and the x86/x64 native decision engine. A pass requires identical normalized
resource identity, requested-access classification, winning rule, decision,
and reason code—not merely identical serialized bytes.

| ID | Scenario | Expected observation |
| --- | --- | --- |
| SEM-001 | Exact, ancestor, descendant, sibling, and no-match filesystem rules are evaluated | Rust reference oracle and both native architectures select the same winning rule |
| SEM-002 | `deny`, mandatory deny, `read_only`, `read_write`, `metadata_read`, and `inherit_user` overlap in every order | All engines apply identical precedence independent of input order |
| SEM-003 | Path aliases vary case, separators, dot segments, long/UNC/device prefixes, short names, and final reparse targets | All engines produce the same canonical identity and decision |
| SEM-004 | Every filesystem API fixture access mask/disposition/information class is classified | Rust model and native classifier agree on read, metadata, create, write, truncate, rename, link, and delete intent |
| SEM-005 | Registry roots, WOW64 views, aliases, handles, and rule overlaps are evaluated | Rust reference and x86/x64 native engines agree on identity, precedence, and access class |
| SEM-006 | Domain exact/wildcard, IDN, trailing-dot, IP/CIDR, IPv4-mapped IPv6, and port rules are evaluated | Rust proxy/compiler and native hook decisions agree on authorization scope |
| SEM-007 | DNS bindings vary execution, process, hostname, address, port, and TTL | Every component agrees when a binding is valid and when it expires |
| SEM-008 | Boundary-length and maximum-count policies are encoded/decoded on x86/x64 | Semantic result remains identical without packing, sign, or truncation differences |
| SEM-009 | Unknown enum/reason/access bits reach a native decoder | Native side rejects the policy/version; it never maps unknown input to allow |
| SEM-010 | Property generator creates valid overlapping policies and operations with fixed seeds | Differential run produces zero disagreement; minimized counterexample is retained on failure |
| SEM-011 | Policy rules are permuted and duplicates inserted | Canonical payload and every decision remain invariant |
| SEM-012 | Upstream BuildXL characterization vectors are adapted without BuildXL public types | Adapted native behavior matches approved Bolt semantics and licensing provenance |

## Filesystem policy and path handling

| ID | Scenario | Expected observation |
| --- | --- | --- |
| FS-001 | Create, write, close, reopen, and read a file under cwd | Content nonce persists and no violation is emitted |
| FS-002 | Create and enumerate nested directories under cwd | Entries and metadata are visible and correct |
| FS-003 | Read an existing file under a `read_only` root | Exact bytes are returned without a violation |
| FS-004 | Create, overwrite, append, truncate, delete, or rename under `read_only` | Each mutation is denied with no side effect |
| FS-005 | Read or enumerate under an explicit `deny` root | Denied even when another grant overlaps |
| FS-006 | Write, create, delete, or rename under an explicit `deny` root | Denied with original state intact |
| FS-007 | Read and write outside every grant | Both are denied and separately classified |
| FS-008 | Access an explicitly named `inherit_user` path allowed by Windows | Operation follows existing user ACL and requested access type |
| FS-009 | Access an `inherit_user` path denied by Windows ACL | OS denial is preserved; sandbox does not elevate |
| FS-010 | Traverse an ungranted parent while opening its granted child, then directly enumerate/read that parent | Traversal required for the child succeeds; direct parent enumeration and content read are denied |
| FS-011 | Use relative paths from cwd, nested cwd, and drive-relative syntax | Target is normalized before the same decision as its absolute equivalent |
| FS-012 | Use `.`/`..`, repeated separators, trailing dots/spaces, and mixed slash forms | Canonical target cannot escape or change precedence |
| FS-013 | Use case variants on a case-insensitive volume | All variants receive the same decision and canonical event path |
| FS-014 | Use long-path `\\?\` and non-prefixed forms at boundary lengths | Equivalent targets receive identical decisions without truncation |
| FS-015 | Use UNC and `\\?\UNC\` aliases to a test share | Equivalent paths receive identical decisions and server side effects agree |
| FS-016 | Use `\??\`, `\\.\`, volume GUID, and NT device paths | Target resolves to the final volume path before policy evaluation |
| FS-017 | Use an 8.3 short name alias for a denied target | Access is denied; event names the canonical target |
| FS-018 | Open an alternate data stream under allowed and denied files | Decision follows the base file plus stream semantics; no alias escape |
| FS-019 | Open the stateless `NUL` device, other reserved device names, and arbitrary non-filesystem device paths | `NUL` preserves discard/EOF semantics; console, pipe, mailslot, and arbitrary device namespaces remain denied and cannot inherit a filesystem path grant |
| FS-020 | Access a path containing Unicode normalization lookalikes | No textual normalization conflates distinct filesystem objects; final resolved target controls |
| FS-021 | Symlink inside allowed root points inside same root | Authorized operation succeeds |
| FS-022 | Symlink inside allowed root points outside/denied | Read and mutation through the link are denied |
| FS-023 | Junction/reparse point inside allowed root points outside/denied | Traversal and mutation escape are denied |
| FS-024 | Allowed link is swapped to denied target during access | Handle/final target validation prevents time-of-check/time-of-use escape |
| FS-025 | Reparse chain contains loop, excessive depth, malformed tag, or unsupported tag | Evaluation terminates within bounds and fails closed |
| FS-026 | Hard link under allowed root aliases a denied file | Content and mutation decision follows file identity/final target policy and prevents escape |
| FS-027 | Create a hard link from allowed to outside/denied | Link creation is denied and link count is unchanged |
| FS-028 | Create a symlink or junction inside `read_write` whose target is outside/denied | Creation is denied and no reparse object is created |
| FS-029 | Open allowed file, then rename it into denied root by path | Rename is denied and original remains intact |
| FS-030 | Open allowed file, then perform handle-based rename into denied root | NT handle operation is denied and original remains intact |
| FS-031 | Rename denied/outside source into allowed root | Source access remains denied; destination is absent |
| FS-032 | Atomic replace allowed destination with denied/outside source | Replace is denied and both originals remain intact |
| FS-033 | Replace and rename wholly within `read_write` | Atomic operation succeeds with correct resulting content |
| FS-034 | Set delete disposition by handle on allowed and denied files | Allowed file is deleted on close; denied file remains |
| FS-035 | Delete/rename a directory tree with mixed grants | Operation is denied if it would affect unauthorized descendants |
| FS-036 | Truncate via create disposition, `SetEndOfFile`, and NT file information | Allowed target changes; read-only/denied target remains byte-identical |
| FS-037 | Create writable memory mapping for allowed, read-only, and denied files | Only allowed mapping can persist modifications |
| FS-038 | Map read-only view of `read_only` file | Mapping succeeds and bytes match |
| FS-039 | Copy allowed source to allowed destination | Destination nonce and metadata contract are correct |
| FS-040 | Copy where source read or destination write is unauthorized | Copy is denied with no partial destination |
| FS-041 | Shell file copy/move/delete uses Explorer-compatible API | Same decisions and side-effect rules as direct APIs |
| FS-042 | Enumerate allowed, read-only, denied, outside, and parent-only directories | Entries are visible only where enumeration is granted |
| FS-043 | Probe metadata/attributes for allowed, metadata-only, and denied files | Only policy-authorized metadata is returned; no content disclosure |
| FS-044 | Change attributes, timestamps, security descriptor, compression, EFS state, or NTFS short name | Treated as mutation and allowed only under appropriate grant and user rights; no alias can be created through a denied inherited handle |
| FS-045 | Target startup handle list contains an unauthorized file handle | Launcher sanitizes/closes the handle before resume; fixture observes an invalid handle and no target access |
| FS-046 | Duplicate a permitted handle and request stronger access | Duplicate cannot amplify rights beyond original policy decision |
| FS-047 | Open with delete-on-close, temporary, backup-semantics, or POSIX flags | Flags do not bypass policy and cleanup matches the decision |
| FS-048 | Two processes race allowed and denied operations on same target | Each decision is atomic enough to prevent unauthorized side effects; events identify actor |
| FS-049 | Mandatory `.ssh`, `.gnupg`, browser-store, app-secret, and broker-state test paths overlap broad grant | Every sensitive target remains denied |
| FS-050 | Host adds stricter deny below cwd | Stricter deny takes effect recursively without weakening sibling cwd access |
| FS-051 | File/directory create uses Win32 APIs and corresponding NT Native APIs | Both API families produce equivalent decisions and events |
| FS-052 | Open uses relative object-manager path/root-directory handle | Final object is normalized and checked; no root-handle escape |
| FS-053 | Named pipe, mailslot, `CreatePipe`, and console pseudo-file access | Default allows only private IPC/runtime handles; explicit isolated mode rewrites local Win32 pipe names while remote/native ambient objects remain denied |
| FS-054 | Volume is case-sensitive or remote semantics differ | Test records capability and enforces identity-based policy without assuming NTFS casing |
| FS-055 | Allowed operation fails for an ordinary OS reason such as sharing violation | Original OS error is preserved and is not mislabeled as a policy violation |
| FS-056 | Violation is repeated through aliases | First event is preserved and duplicates aggregate under the canonical resource identity |
| FS-057 | Allowed and denied reads/writes use overlapped I/O with immediate and pending completion | Submission and completion preserve the original decision, byte count, status, and target identity |
| FS-058 | Pending overlapped operation is cancelled, times out, or completes after handle close | No use-after-free, stale policy state, duplicate event, or unauthorized side effect occurs |
| FS-059 | Allowed and denied operations complete through an I/O completion port or thread-pool I/O | Completion routing does not bypass enforcement and original completion data is preserved |
| FS-060 | Open-by-file-ID/object-ID addresses allowed and denied files | File identity is resolved before use; identifier-based access cannot bypass path policy |
| FS-061 | Directory change notification watches allowed, parent-only, and denied directories | Notifications disclose only authorized names/metadata and denied watches create no usable handle |
| FS-062 | Writable mapping uses flush, unmap, copy-on-write, image-section, and delayed-write paths | Only `read_write` mappings persist changes; copy-on-write never modifies source and denied/image loads cannot bypass read policy |
| FS-063 | Hooked call succeeds/fails while thread `LastError` contains a sentinel | Hook preserves the API's documented return/status and `LastError` semantics rather than leaking internal calls |
| FS-064 | Recursive hook path is triggered by normalization, event transport, symbol loading, or diagnostics | Reentrancy guard avoids recursion/deadlock while still enforcing the original target operation |

## Process startup, descendants, and lifecycle

| ID | Scenario | Expected observation |
| --- | --- | --- |
| PROC-001 | Launch a minimal x64 target | Target starts suspended, hook initializes, `Ready` precedes user marker, then target resumes |
| PROC-002 | Launch a minimal x86 target on x64 Windows | Matching x86 DLL is selected and the same handshake ordering holds |
| PROC-003 | x64 parent creates x64 child | Child inherits policy, is injected before user code, and joins the job |
| PROC-004 | x64 parent creates x86 child | x86 helper/DLL is selected before child resume |
| PROC-005 | x86 parent creates x86 child | Policy and event session remain inherited |
| PROC-006 | x86 parent creates x64 child | Matching x64 DLL is injected before user code and the child remains in the same policy session/job |
| PROC-007 | Build nested descendants to configured practical depth | Every descendant shares policy and job; no unconfined user marker appears |
| PROC-008 | Child requests `CREATE_SUSPENDED` | Sandbox preserves caller semantics after successful injection; caller controls final resume |
| PROC-009 | Parent uses each supported CreateProcess family and native process API | Every normal creation path is intercepted and confined |
| PROC-010 | Launch `cmd`, PowerShell, Node, Python, Git, and Cargo fixture workflows | Each starts, performs allowed work, and receives expected violations for denied probes |
| PROC-011 | Child requests detached, new process group, or no-window flags | It remains in the policy session and lifecycle job |
| PROC-012 | Child requests job breakaway | Process creation is denied before child user code and the parent remains in the job |
| PROC-013 | Parent exits normally while descendants run | Rust lifecycle manager keeps descendants confined and monitored until every descendant exits or the execution is cancelled/timed out |
| PROC-014 | Child injection fails | Child is terminated before its startup marker and structured failure event is emitted without command data |
| PROC-015 | Architecture detection fails or returns unsupported ARM64/ARM64EC | Launch fails closed with typed unsupported-architecture error |
| PROC-016 | Child mutates its environment or sends fake policy data | Compiled policy remains immutable and descendants cannot weaken it |
| PROC-017 | Child inherits/duplicates launcher, policy, or IPC handles unexpectedly | Rights are minimal; child cannot impersonate host, modify policy, or create a second session |
| PROC-018 | Rapid process churn and concurrent child creation | No child runs before injection; all created process IDs reach terminal accounting |
| PROC-019 | Target crashes before/after readiness | Distinct typed state and event are returned; all descendants/handles are cleaned |
| PROC-020 | Target tries to launch an elevated process or uses shell elevation | Elevation request is denied before elevated user code runs and a process violation is recorded |
| PROC-021 | Target delegates execution through scheduled task, service, WMI, COM broker, or shell outside the job | Direct delegation is denied; only a separately configured trusted broker API may execute an explicitly authorized operation |
| PROC-022 | Target launches from path containing spaces/Unicode/long path | Correct executable and arguments start without command-line ambiguity |
| PROC-023 | Same compatible hook/policy is initialized twice | Second initialization returns `AlreadyInitialized`, preserves the original policy/session, and installs no duplicate trampoline |
| PROC-024 | Multiple sandboxes launch identical programs concurrently | Process trees, events, policies, and cleanup remain session-isolated |
| PROC-025 | Parent uses `CreateProcessW/A` with every supported flag family | Child is forced suspended for injection, caller-visible flags are preserved, and child resumes only after readiness |
| PROC-026 | Parent uses `CreateProcessAsUserW/A` with a supported non-elevated test token | Child is injected into the same policy/job before user code and retains only the supplied user-authorized token rights |
| PROC-027 | Parent uses `CreateProcessWithTokenW` or `CreateProcessWithLogonW` | Token-changing creation is denied before user code in the initial release and emits a process violation |
| PROC-028 | Parent uses `ShellExecuteExW`, COM shell activation, or association launch | Direct executable `open` requests are converted to confined process creation; elevation, file association, custom-verb, and out-of-process COM delegation are denied before external code runs |
| PROC-029 | Parent uses `NtCreateUserProcess`/`RtlCreateUserProcess` fixture | Native path is intercepted and confined before user code |
| PROC-030 | PE header is malformed, architecture is ambiguous, WOW64 query fails, or image changes during selection | Architecture selection fails closed; no wrong-architecture injection attempt reaches user code |
| PROC-031 | Process mitigation query runs after target readiness | Required mitigation bits from the release profile are active in target and supported descendants |
| PROC-032 | Required mitigation application fails or target requests incompatible weakening | Launch fails before user code with a typed mitigation error |
| PROC-033 | Required compatibility tools run with the mitigation profile | Each tool remains functional without disabling mandatory mitigations dynamically |
| PROC-034 | Child attempts to change its job limits or required mitigation policy | Attempt cannot weaken lifecycle or mitigation controls and is recorded |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| LIFE-001 | Target exits 0, nonzero, exception, or termination status | Exact structured exit kind/code is returned after streams/events are drained |
| LIFE-002 | Target writes interleaved stdout and stderr | Bytes are complete, independently streamed, and not confused with events |
| LIFE-003 | Timeout expires with one process | Process is terminated, typed timeout returned, and no survivor remains |
| LIFE-004 | Timeout expires with nested/detached descendants | Entire job tree is terminated and every heartbeat stops |
| LIFE-005 | Caller cancels execution | Cancellation is bounded, idempotent, and cleans the process tree |
| LIFE-006 | Rust host dies unexpectedly | Kill-on-job-close terminates every descendant within the cleanup bound; no watchdog-dependent or orphaned process remains |
| LIFE-007 | Launcher dies before handshake or after target resume | Before handshake the target never runs; after resume the Rust host terminates the job and returns a typed infrastructure failure |
| LIFE-008 | Target ignores graceful termination | Forced termination occurs within the configured bound |
| LIFE-009 | stdout/stderr consumer is slow or disconnects | Host keeps memory within configured caps, drains/discards after disconnect, emits typed stream-loss state, and does not deadlock target termination |
| LIFE-010 | Process exits while final violation/event is in flight | Violation sequence precedes `ProcessExited`; execution completes only after both streams reach EOF and required events are drained |
| LIFE-011 | Target emits empty, binary, invalid UTF-8, Unicode, and split multibyte data on stdout/stderr | Library and CLI redirected handles preserve the exact byte sequences independently without decoding, corruption, or panic |
| LIFE-012 | Target fills stdout and stderr concurrently beyond pipe buffers | Both streams drain without cross-stream head-of-line deadlock, truncation, or byte reordering within a stream |
| LIFE-013 | Target closes one stream early and keeps the other open | Closed stream terminates once; remaining stream and lifecycle continue normally |
| LIFE-014 | Natural exit, timeout, and cancellation race around the same monotonic deadline | Earliest committed trigger wins; an exact-tick tie uses cancellation, then timeout, then exit precedence; cleanup and terminal event occur once |
| LIFE-015 | System wall clock moves forward/backward while timeout runs | Timeout uses a monotonic clock and fires after the configured elapsed duration |
| LIFE-016 | Caller drops stream/event receivers without cancelling execution | Host drains/discards within configured caps, target reaches its natural terminal state, final lifecycle result flags each lost receiver, and no handle leaks |

## Network policy

| ID | Scenario | Expected observation |
| --- | --- | --- |
| NET-001 | `Unrestricted` TCP connect by IPv4 and IPv6 | Test server accepts both; no violation is emitted |
| NET-002 | `Unrestricted` hostname via sync and async DNS | Resolution and connection succeed with normal OS behavior |
| NET-003 | `Denied` TCP via `connect`, `WSAConnect`, and `ConnectEx` | Each outbound attempt is denied before server acceptance |
| NET-004 | Target performs UDP send/connect in `Denied` mode | Target operation is denied; only the separately authenticated runtime endpoint in NET-007 is exempt |
| NET-005 | `Denied` DNS sync/async query | External resolution is denied; required loopback IPC remains functional |
| NET-006 | `Denied` WinHTTP and WinInet HTTP/HTTPS | Requests are denied without network side effect |
| NET-007 | `Denied` mode uses private runtime loopback endpoint/IPC and probes another loopback service | Only the exact authenticated runtime endpoint succeeds; arbitrary loopback TCP/UDP is denied |
| NET-008 | `AllowList` permits exact domain and port | DNS binding and proxied connection reach only the intended server |
| NET-009 | Allowed domain on wrong port or allowed port on wrong domain | Connection is denied |
| NET-010 | Allowed subdomain with exact-only rule | Denied unless wildcard semantics explicitly include it |
| NET-011 | Rule `*.example.com` tests apex, one/many labels, and lookalike suffix | One or more subdomain labels match; apex `example.com` and suffix-lookalike `evil-example.com` are denied |
| NET-012 | Allowed IPv4/IPv6 CIDR tests first, last, just-outside, and mapped addresses | Boundary membership is correct and canonical |
| NET-013 | Direct IP connect after allowed hostname resolution | Allowed only for the bound address, session, process scope, port, and TTL |
| NET-014 | Same IP is used for unrelated hostname/session/process | Prior DNS authorization does not become global authority |
| NET-015 | DNS response changes after TTL/rebinding | Expired address loses authorization; new address requires fresh bound resolution |
| NET-016 | DNS returns multiple A/AAAA records or CNAME chain | Only validated chain results are bound, within configured limits |
| NET-017 | DNS returns malformed, oversized, looped CNAME, NXDOMAIN, or timeout | Evaluation terminates safely without permissive fallback |
| NET-018 | HTTP redirect moves to allowed or denied destination | Every hop is checked; denied destination is never contacted |
| NET-019 | System/application proxy is configured | Proxy endpoint and ultimate destination are both policy-validated |
| NET-020 | Client attempts HTTP CONNECT or proxy bypass/direct socket | Unsupported direct path is blocked in strict allow-list mode |
| NET-021 | Child process performs allowed and denied network operations | It inherits exactly the parent policy and binding scope rules |
| NET-022 | x86 and x64 clients use all supported stacks | Winsock, DNS, WinHTTP, and WinInet decisions are architecture-equivalent |
| NET-023 | Concurrent DNS/connect races and socket reuse | Authorization cannot transfer to a different destination or expired binding |
| NET-024 | IPv6 zone IDs, IPv4-mapped IPv6, localhost aliases, and IDN domains | Inputs canonicalize without allow-list confusion |
| NET-025 | Raw sockets, custom protocols, QUIC, UDP, or unsupported stacks are attempted | `Denied` and `AllowList` reject every unsupported path; `Unrestricted` preserves normal user-authorized OS behavior |
| NET-026 | Network hook initialization fails in any mode, or local proxy initialization fails in `AllowList` | Sandbox initialization fails before target user code; no mode silently drops required enforcement coverage |
| NET-027 | Target startup handle list contains an arbitrary preconnected socket | Launcher sanitizes/closes it before resume; only an exact authenticated runtime channel may be inherited |
| NET-028 | Operation fails for normal network reason | Native error is preserved and not mislabeled as policy denial |
| NET-029 | Repeated denied packets/connects saturate events | Network calls remain bounded; first event and aggregate/drop counts remain available |

## Registry policy

| ID | Scenario | Expected observation |
| --- | --- | --- |
| REG-001 | Query value and enumerate key under `read_only` | Existing data is returned without violation |
| REG-002 | Set/create/delete value under `read_only` | Denied and registry snapshot remains identical |
| REG-003 | Create/delete/rename subkey under `read_only` | Denied with no structural change |
| REG-004 | Query, enumerate, mutate, delete, and rename under `no_access` | Every operation is denied without data disclosure |
| REG-005 | Read and mutate under `read_write` | Allowed subject to normal user registry permissions |
| REG-006 | Access explicitly named `inherit_user` key | Existing user authorization is preserved without elevation |
| REG-007 | Access outside all registry grants | Default decision matches policy and is explicitly tested for read and write |
| REG-008 | Mandatory credential/application-security key overlaps broad grant | Mandatory deny wins for reads, enumeration, and mutation |
| REG-009 | Host adds stricter sensitive-key deny | New deny is recursive and cannot be removed by child input |
| REG-010 | Use case variants, redundant separators, root aliases, and native paths | Canonical key receives one consistent precedence decision |
| REG-011 | Use WOW64 32-bit and 64-bit registry views | x86/x64 processes cannot bypass policy through view redirection |
| REG-012 | Use symbolic registry links or predefined/root handles | Final key identity is checked and boundary escape is denied |
| REG-013 | Open allowed handle, then rename/delete/set toward denied key | Handle-based NT operation is re-evaluated and denied |
| REG-014 | Duplicate/inherit a registry handle with stronger rights | Rights cannot amplify past policy |
| REG-015 | NT Native create/open/query/set/delete/rename APIs are used | All required operations are intercepted with correct events |
| REG-016 | Win32 registry wrappers perform the same operations | End-to-end decision matches NT Native path |
| REG-017 | Transactional or remote registry operation is attempted | Initial release denies it with typed `UnsupportedRegistryOperation`; no operation reaches the remote/transactional target |
| REG-018 | Concurrent key mutation and rename races | Unauthorized side effects never appear; event actor is correct |
| REG-019 | Ordinary OS ACL, missing key, or sharing error occurs on allowed path | Original error is preserved and no false violation is emitted; mixed-access opens on exact-read-only keys are attenuated to read-only without creating or mutating host state |
| REG-020 | Registry event contains names/data resembling secrets | Event includes only permitted key metadata and passes canary scan |

## IPC, events, and audit reliability

| ID | Scenario | Expected observation |
| --- | --- | --- |
| IPC-001 | Create two execution pipes | Names are unpredictable/unique and endpoints are not cross-connectable |
| IPC-002 | Current user and participating process connect | Authorized handshake succeeds |
| IPC-003 | Different user/session or unrelated process attempts pipe access | Security descriptor denies connection |
| IPC-004 | Valid frame at zero, normal, and maximum payload length | Rust and native decoders agree exactly |
| IPC-005 | Truncated header/body or declared length exceeds available bytes | Decoder rejects without overread, hang, or partial event |
| IPC-006 | Oversized length or allocation request | Rejected before unbounded allocation |
| IPC-007 | Pre-readiness frame checksum is corrupted | Frame is rejected, target never resumes, and initialization returns a typed protocol-integrity failure |
| IPC-008 | Unknown version | Handshake/event is rejected as incompatible, never guessed |
| IPC-009 | Unknown event type appears in an otherwise compatible version | Decoder rejects the frame as incompatible and terminates the affected session; it never skips a security event silently |
| IPC-010 | Invalid inherited mapping/pipe handle | Launcher rejects before target starts |
| IPC-011 | Policy mapping is writable by child | Test must fail; production descriptor requires immutable/read-only child view |
| IPC-012 | Handshake is absent, late, malformed, duplicated, or from wrong process | Target never resumes and typed initialization failure is returned |
| IPC-013 | IPC disconnects before readiness | Initialization fails closed |
| IPC-014 | IPC disconnects after readiness | Rust host terminates the process job and returns a typed event-channel-loss infrastructure failure |
| IPC-015 | Rust/native protocol golden vectors run on x86 and x64 | Bytes, endianness, packing, version, and checksums match |
| IPC-016 | Framing parser receives generated arbitrary bytes | No crash, undefined behavior, excessive allocation, or unbounded loop |
| IPC-017 | Unrelated process pre-creates/squats the predicted pipe name or mapping name | Unpredictable names plus authenticated creation prevent capture; launcher never connects to attacker-owned objects |
| IPC-018 | Valid handshake/frame from a completed execution is replayed into a new execution | Execution nonce/channel binding rejects replay before target resume/event acceptance |
| IPC-019 | Participating child opens a second pipe connection and emits forged `Ready`, violation, or exit frames | Per-process/channel role authentication rejects frames not valid for that sender |
| IPC-020 | Client/server impersonation and named-pipe remote-client flags are exercised | Server does not grant rights through impersonation; remote clients are rejected and identity returns to trusted token |
| IPC-021 | Pipe/mapping handles are inherited by an unintended descendant or duplicated to a sibling | Minimal rights and sender binding prevent policy mutation, host impersonation, or forged events |
| IPC-022 | Pipe security descriptor is inspected under standard user, different logon session, low integrity, and AppContainer-like token | Only the trusted host and explicitly participating processes possess the required rights |
| IPC-023 | Session nonce, sequence, checksum, process ID, and protocol header are individually tampered | Every tampered frame is rejected before typed-event construction and cannot advance sequence state |
| IPC-024 | Pipe name, mapping name, and security descriptor creation race under high concurrency | Every execution obtains one private channel without collision, fallback to a public namespace, or leaked handle |
| IPC-025 | Post-readiness frame has a bad checksum, impossible length, or invalid sender binding | Offending frame is rejected, Rust terminates the process job, and execution returns typed protocol-integrity failure |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| EVT-001 | Ready, each violation kind, recovery, child failure, and exit are emitted | All variants decode to typed public events without native-type leakage |
| EVT-002 | Events have consecutive sequence numbers | Consumer observes stable order per session |
| EVT-003 | Duplicate, gap, out-of-order, and wrapped sequence values arrive | Decoder emits typed `ProtocolSequenceError`, accepts no offending event, and terminates the affected session |
| EVT-004 | Repeated identical violations occur | First occurrence is preserved and duplicate count is aggregated in Rust |
| EVT-005 | Distinct violations share operation but not resource/process | They remain distinct aggregates |
| EVT-006 | DLL event queue reaches capacity | Hooked operation never blocks indefinitely; drop count and first event survive |
| EVT-007 | Consumer pauses until the queue reaches capacity, then resumes | Target continues; first occurrences and sequence integrity survive, duplicate drops are counted, and queue memory never exceeds its configured cap |
| EVT-008 | Event contains long paths, Unicode, malformed text, or binary-like data | Serialization is bounded/valid and redaction remains correct |
| EVT-009 | Secret canaries appear in arguments, environment, file/registry values, or network payload | No event or diagnostic contains any canary |
| EVT-010 | Process exits with queued events | Required violations are drained before terminal completion under the ordering contract |
| EVT-011 | Multiple processes emit concurrently | Per-event process identity is correct and framing is not interleaved/corrupted |
| EVT-012 | Diagnostic formatting itself fails | Safe fallback is typed/redacted and cannot panic across FFI |

## Hook runtime robustness

| ID | Scenario | Expected observation |
| --- | --- | --- |
| HOOK-001 | Hook initialization runs during DLL process attach under loader-lock-sensitive conditions | Heavy initialization is deferred safely; handshake occurs without loader-lock deadlock |
| HOOK-002 | Hooked API re-enters through path normalization, IPC, allocator, diagnostics, or another hooked API | Thread-local recursion handling terminates and never converts an undecidable operation into allow |
| HOOK-003 | Many internal threads race hook installation and process/thread attach/detach | No call observes a partially installed set; target user code starts only after the complete valid set is published |
| HOOK-004 | Thread exits, is cancelled, or raises SEH during a hooked operation | Per-thread state/locks are released and later operations remain enforceable |
| HOOK-005 | Native exception or Rust/native boundary error occurs inside policy evaluation | Exception does not cross FFI; operation fails closed and bounded failure evidence is emitted |
| HOOK-006 | Internal allocation fails at each hook-path allocation point | Decision fails closed without recursive diagnostics, heap corruption, or unbounded retry |
| HOOK-007 | Process forks equivalent rapid child startup while event queue and policy readers are busy | Hook state remains initialized and immutable in every child process context |
| HOOK-008 | Hooked API is called from DllMain, TLS callback, static initializer, or process shutdown | No loader-lock deadlock/use-after-shutdown occurs; unsafe undecidable operations are denied |
| HOOK-009 | Hook trampoline/prologue bytes and target modules are inspected after readiness | Every required API points to the approved hook and trampoline target; partial installation fails initialization |
| HOOK-010 | Normal successful and failed calls compare return value, NTSTATUS, `LastError`, WSA error, and callback behavior with an unsandboxed control | Hook is transparent except for explicit policy decisions and documented event timing |
| HOOK-011 | Bounded event queue wraps sequence/capacity counters over a long stress run | Counters do not overflow into memory corruption, blocking, or permissive decisions |
| HOOK-012 | Process shutdown races queued events, module detach, and handle closure | Shutdown is idempotent; no hook calls freed code/state and required terminal evidence is retained |

## Recovery

| ID | Scenario | Expected observation |
| --- | --- | --- |
| REC-001 | Delete an allowed normal file with recovery enabled | Backup precedes deletion, is indexed by execution/path, and restoration reproduces bytes |
| REC-002 | Truncate an allowed file | Pre-truncation content is backed up once and file mutation succeeds |
| REC-003 | Atomic replace or destructive rename | Correct original objects are recoverable and final allowed operation completes |
| REC-004 | Destructive operation is denied by policy | Operation remains denied; recovery does not create a policy side channel |
| REC-005 | Recovery is disabled | Allowed destructive operation proceeds with no artifact/event |
| REC-006 | File is zero bytes, at size quota, or one byte over | Boundary behavior is exact and reported |
| REC-007 | Item count, total bytes, or per-execution quota is exhausted | Enforcement decision is unchanged; bounded recovery status is observable |
| REC-008 | Retention expires | Only eligible inactive artifacts are removed; active sessions are untouched |
| REC-009 | Backup store is full, denied, locked, or unavailable before an otherwise allowed destructive operation | Operation proceeds under its original allow decision, no partial artifact remains, and a typed recovery-failure event is emitted |
| REC-010 | Secret-tagged file lacks equivalently protected encrypted storage | No backup is created and no secret leaks in metadata |
| REC-011 | Protected encrypted backup store with equivalent ACL is configured for a secret-tagged file | Backup is created before mutation, encrypted at rest, and readable only by the trusted recovery principal |
| REC-012 | Symlink, hard link, junction, sparse, locked, or changing file is destroyed | Recovery captures authorized object semantics without following into denied data |
| REC-013 | Concurrent destructive operations target same file | Artifacts/index remain consistent, bounded, and attributable |
| REC-014 | Child process performs destructive operation | Artifact is attributed to shared execution and actual normalized source path |
| REC-015 | Sandbox attempts to enumerate, read, create, modify, or delete the recovery namespace | Every attempt is denied and the trusted store snapshot remains unchanged |
| REC-016 | Recovery event/metadata contains secret-bearing path or content | Redaction/access rules prevent disclosure while retaining usable trusted index |
| REC-017 | Crash occurs during backup/index/operation | Recovery state is atomic/reconcilable and enforcement never becomes permissive |
| REC-018 | Hook sends a backup destination/path choice instead of a destructive-operation request | Trusted Rust layer rejects the untrusted destination and independently selects the configured recovery store |
| REC-019 | Hook attempts to write directly to recovery storage | Storage ACL/handle design denies direct DLL access; only trusted Rust coordinator writes artifacts |

## Component and dependency boundaries

| ID | Scenario | Expected observation |
| --- | --- | --- |
| BND-001 | Launcher binary imports/dependencies and source include graph are inspected | Launcher depends only on native launcher/common/protocol surfaces and contains no Agent prompt, settings, JSON policy, or application-configuration parser |
| BND-002 | Agent prompt/settings/config files contain canaries and launcher runs normally | Launcher never opens those files and no canary reaches its memory-safe diagnostics or IPC |
| BND-003 | Hook writes events and reads policy during a monitored run while test snapshots user/world-writable temp roots | No policy, event, secret, or audit artifact is created in a world-readable/writable temporary location |
| BND-004 | Native launcher/hook import graph is checked | Native components depend only on the versioned protocol contract, approved Windows libraries, and pinned native dependencies—not Rust implementation symbols/types |
| BND-005 | Public Rust crate metadata/API is inspected | IPC internals, native handles, Detours/BuildXL types, recovery locations, and mutable compiled-policy internals are not public |
| BND-006 | CLI source dependency graph and behavior are checked | CLI delegates request execution to the library and contains no duplicate policy compiler or lifecycle manager |
| BND-007 | Hook event requests contain recovery metadata/destination fields not authorized by protocol | Decoder rejects unknown authority-bearing fields; trusted Rust layer remains sole recovery coordinator |
| BND-008 | Production artifact strings/imports/filesystem traces are scanned | No test-only fault switch, fixture secret, prompt parser, policy temp-file path, or unpinned reference-project code is present |

## Fail-closed security and documented limitations

| ID | Scenario | Expected observation |
| --- | --- | --- |
| SEC-001 | Launcher executable is missing, replaced, unsigned, or hash-mismatched | Request fails before target start |
| SEC-002 | Required x64/x86 DLL is missing, replaced, unsigned, or hash-mismatched | Request fails before target/child user code |
| SEC-003 | Protocol versions among library, launcher, and DLL differ | Compatibility check fails closed |
| SEC-004 | Policy compile, serialization, mapping, pipe, injection, or hook init fails | No unsandboxed fallback path runs |
| SEC-005 | Sandbox is invoked from an elevated token | Request is rejected before target creation with a typed `ElevatedHostUnsupported` error |
| SEC-006 | Child environment, command line, policy, events, diagnostics, and recovery are scanned | All synthetic secret canaries are absent from prohibited locations |
| SEC-007 | Policy/event error contains attacker-controlled format/control characters | Logs remain structured, bounded, and non-forgeable |
| SEC-008 | Child attempts to open/modify policy mapping, hook DLL, launcher, or pipe ACL | Access is denied and confinement remains healthy |
| SEC-009 | Conventional application calls supported DLL-unload or memory-protection APIs against the hook | Covered tampering APIs are denied and confinement remains active |
| SEC-010 | Child issues direct filesystem/network system call fixture | Test continuously demonstrates and labels standard-backend limitation without exposing real secrets |
| SEC-011 | Child uses covered `OpenProcess`/`WriteProcessMemory`/remote-thread APIs against a process outside its session | Access is denied before modification; direct-syscall tampering remains separately classified by BYP-010 |
| SEC-012 | Privileged service, driver, or elevated broker is requested | Capability is unavailable directly and must remain behind a trusted broker |
| SEC-013 | Rust parent, launcher, target, hook thread, proxy, or IPC endpoint is killed independently | Each lifecycle transition is bounded, typed, and leaves no silently unconfined descendants |
| SEC-014 | Malformed policy/frame corpus runs under sanitizers and fuzzers | No memory-safety fault, panic across FFI, leak, or permissive parse |
| SEC-015 | Test suite runs as standard user | No normal operation requires administrator privileges or ACL recursion |
| SEC-016 | Installation/test compares protected tree ACLs before and after | No recursive ACL mutation occurs |
| SEC-017 | Host credentials exist in parent process | Child receives only explicit safe environment and cannot access mandatory credential paths |
| SEC-018 | Event/log/recovery volume is intentionally exhausted | Resource use stays bounded and policy decisions remain fail-closed |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| BYP-001 | Filesystem probe uses every hooked Win32 and NT entry point for the same denied write | No covered entry point reaches the target; coverage gaps name the exact missing API |
| BYP-002 | Process probe uses alternate creation APIs, shell activation, and native creation | Normally supported creation paths cannot start an uninstrumented child |
| BYP-003 | Network probe resolves with one stack and connects with another | Authorization remains destination/session-bound across stacks |
| BYP-004 | Registry probe opens with Win32 then mutates through NT handle APIs, and vice versa | Cross-family handle use cannot evade the final mutation check |
| BYP-005 | Granted directory is replaced by a junction/reparse point during repeated operations | Final-target checking prevents escape throughout the race |
| BYP-006 | Allowed file handle is reused after rename/link replacement | File identity and requested operation prevent stale-path authorization |
| BYP-007 | Child uses inherited file, registry, socket, process, and section handles | No inherited capability bypasses the compiled policy or trusted-handle allowlist |
| BYP-008 | Child opens a sibling/out-of-session process and calls `DuplicateHandle` | Process/handle access is denied and no external handle enters the sandbox process |
| BYP-009 | Event pipe is flooded while denied operations run | Audit degradation cannot change deny decisions or deadlock hooks |
| BYP-010 | Hook DLL unload, patch, and direct-syscall fixtures run in an isolated tree | Results are labeled `EXPECTED_LIMITATION` where outside the stated threat model, with no kernel-grade claim |
| BYP-011 | Child delegates through service, scheduled task, WMI, COM, or elevation broker | Direct arbitrary execution is blocked; a test broker executes only the exact operation pre-authorized by trusted Rust policy |
| BYP-012 | Test corpus from reference products is re-expressed as black-box behavior | Semantic regressions are detected without copying GPL or closed-source implementation code |

## Command attribution and transactional Agent workspaces

| ID | Scenario | Expected observation |
| --- | --- | --- |
| ATTR-001 | Trusted Rust starts two commands with different opaque command IDs | Every event is correlated to exactly one command without carrying command text |
| ATTR-002 | Command ID is zero, malformed, replayed, or mismatched with execution identity | Preparation or event decoding rejects it before the event is published |
| ATTR-003 | Policy generations are issued across repeated starts | Values are nonzero and strictly increase within one sandbox coordinator |
| ATTR-004 | Event carries a stale or future policy generation | Event channel fails closed; it is not aggregated under the active command |
| ATTR-005 | x86/x64 descendants emit concurrent violations | Parent and child events retain identical execution/command/generation attribution |
| ATTR-006 | Diagnostics and events are scanned with command/environment canaries | Only opaque identifiers appear; commands, arguments, environment, and secrets do not |
| EVT-013 | Attributed events are aggregated | Attribution participates in the key so events from separate commands never merge |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| WS-001 | Existing execution uses `DirectWorkspaceBackend` | Program, cwd, policy, recovery, events, and exit behavior remain unchanged |
| WS-002 | Unknown or unavailable backend is requested | Typed unsupported/configuration failure is returned before process creation |
| WS-003 | Direct backend is benchmarked before and after abstraction | Warm startup and steady-state overhead remain within existing budgets |
| WS-004 | ProjFS backend prepares a session | Unique protected projection root and bounded journal are created by trusted Rust |
| WS-005 | ProjFS is unavailable or disabled | Requested projected execution fails explicitly and never falls back to Direct |
| WS-006 | Target probes registry, network, process, and denied file resources through projection | Existing enforcement decisions and events remain unchanged |
| WS-007 | Target writes the projected workspace | Source workspace remains unchanged until trusted commit |
| WS-008 | Target opens source through drive, volume, junction, symlink, file ID, or handle alias | Write is denied and no source side effect occurs |
| WS-009 | Projection contains ADS, hard-link, reparse, case-sensitive, or non-ASCII paths | Ambiguous/escaping operations fail closed; supported paths preserve identity |
| WS-010 | Target attempts to mutate projection control or provider files | Mandatory deny blocks access and reports a redacted event |
| WS-011 | Provider callback crashes, times out, or returns malformed data | Job terminates and no source commit occurs |
| WS-012 | Provider IPC disconnects before or after readiness | Startup fails or running Job terminates exactly once |
| WS-013 | Host exits while projected target is active | Target tree terminates and session remains recoverable by bounded cleanup |
| WS-014 | Query changes after create/modify/delete/rename | Canonical ordered journal contains each effective change once |
| WS-015 | Discard is requested | Projection and journal are removed without changing the source workspace |
| WS-016 | Commit is requested | Trusted host applies only reviewed journal entries and records recovery metadata |
| WS-017 | Revert is requested for a committed session | Versioned recovery restores the prior state without target authority |
| WS-018 | Source changes externally after projection read | Commit detects identity/hash conflict and applies nothing |
| WS-019 | Commit fails after staging one of several operations | No partial source transaction becomes visible; projection remains inspectable |
| WS-020 | Large/concurrent changes exceed configured bounds | Further changes/commit fail with typed quota status and bounded resources |
| WS-021 | A staged source contains, equals, or is contained by a mandatory-deny path | Preparation fails closed before any protected content is copied or target process starts; case variants cannot bypass the check |
| WS-022 | A staged request explicitly grants a source ancestor that exposes sibling transaction namespaces | Preparation fails closed; source-scoped grants remain valid and generated transaction IDs are never treated as authorization |
| WS-023 | Staged workspace authorization metadata is copied and revalidated through the trusted helper | Owner, group, DACL protection/inheritance, and mandatory label remain equivalent; paths travel only in bounded integrity-protected IPC |
| WS-024 | Target creates an object and applies an explicit or protected ACL in Staged mode | Commit returns conflict, source remains unchanged, and the transaction remains discardable |
| WS-025 | Trusted host requests automatic transactional workspace selection | ProjFS capability selects Projected when available and Staged otherwise; actual backend is reported and Direct/unsandboxed fallback is impossible |
| REC-020 | Projected destructive commit targets an ordinary file | Complete pre-commit content is captured before trusted mutation |
| REC-021 | Projected session expires | Retention GC removes only inactive verified session state |
| REC-022 | Recovery creation fails during projected commit | Commit stops before source mutation and reports typed failure |
| SEC-019 | Projection root is treated as the sole sandbox boundary | Test fails by design; source mandatory deny and ordinary hooks must still enforce |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| PTY-001 | Interactive cmd/PowerShell/Node/Python starts with PTY enabled | Input, output, resize, and exit are functional with typed lifecycle events; the isolated-console capability reaches the injected target and not pipe-mode targets |
| PTY-002 | Noninteractive command starts without PTY | Existing pipe path is selected with no PTY process or handle overhead |
| PTY-003 | Unsupported PTY architecture/configuration is requested | Typed failure occurs before process resume |
| PTY-004 | PTY command creates descendants | Every descendant remains in the Job and receives matching policy/hook |
| PTY-005 | Ctrl-C, timeout, cancellation, or host loss occurs | Complete PTY process tree terminates deterministically |
| PTY-006 | Binary and split UTF-8 data crosses PTY | Bytes/order are preserved and bounded without implicit decoding in the API |
| PTY-007 | Target duplicates PTY handles to an unrelated process | Duplication is denied and no external process gains the capability |
| PTY-008 | Target opens arbitrary named pipes after PTY setup | Existing named-pipe deny remains effective |
| PTY-009 | PTY closes or is reused | Capability is revoked by object identity; handle reuse grants nothing |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| BRK-001 | Broker preloads components/Profile | Files are revalidated/leased and remain read-only; no execution authority exists yet |
| BRK-002 | Two commands use one broker | Each receives fresh identity, Job, IPC, policy payload, and recovery namespace |
| BRK-003 | Sessions use different policy generations | Broker cannot reuse or widen the earlier policy |
| BRK-004 | Concurrent sessions run | Events, streams, cleanup, and capabilities remain isolated |
| BRK-005 | Broker crashes or is killed | Every associated running Job terminates; no descendant survives |
| BRK-006 | Broker presents stale component/Profile identity | New execution is rejected before process creation |
| BRK-007 | Broker loses policy/provider IPC | Startup fails or running execution terminates without fallback |
| BRK-008 | Target attempts to connect to broker control IPC | ACL/authentication rejects it without disclosing broker inputs |
| BRK-009 | Prewarming benchmark improvement is below 10 ms | Broker is not included in the default product |
| BRK-010 | Broker is enabled and benchmarked | Warm dispatch, resource growth, and shutdown meet configured budgets |
| PERF-015 | Direct/projected/broker modes are compared | Each mode has separate reproducible startup and steady-state budgets |

## Packaging, compatibility, licensing, and performance

| ID | Scenario | Expected observation |
| --- | --- | --- |
| PKG-001 | Build release component set | CLI/library, x64/x86 launchers, x64 DLL, and x86 DLL carry one compatible release/protocol identity |
| PKG-002 | Verify signatures and hashes before first launch | Valid artifacts pass; any byte change fails before execution |
| PKG-003 | Extract embedded artifacts | Extraction is atomic into per-version access-controlled directory, never shared writable temp |
| PKG-004 | Two processes extract/use same version concurrently | No partial artifact, race, or deletion of in-use component occurs |
| PKG-005 | Upgrade/downgrade/interrupted extraction occurs | Only complete verified set becomes active; prior valid set remains recoverable |
| PKG-006 | Clean stale versions | In-use version is retained; only verified inactive target directories are removed |
| PKG-007 | Generated binaries/build directories are inspected in source package | None are committed or included unintentionally |
| PKG-008 | CLI behavior is compared with direct library call | CLI remains a thin adapter with no alternate policy/lifecycle semantics |
| PKG-009 | Verified launcher/DLL is replaced between hash/signature verification and process/image load | Load is bound to the verified file identity/handle; replacement cannot execute and launch fails closed |
| PKG-010 | Extraction or component directory contains attacker-created symlink, junction, mount point, reparse point, or hard link | Secure extraction rejects the path before writing/loading and does not follow it outside the version root |
| PKG-011 | Current directory, `PATH`, DLL search directories, side-by-side manifests, and adjacent writable directories contain lookalike DLLs | Process loads only absolute verified dependencies under the trusted component root |
| PKG-012 | Component file is modified after extraction while another process is using it | Existing verified image remains stable; new launch re-verifies and rejects modified bytes |
| PKG-013 | File has valid name/version metadata but wrong signer, revoked/untrusted signature, or wrong release manifest hash | Verification rejects it before execution; metadata alone grants no trust |
| PKG-014 | Verified component is copied to an untrusted writable directory and launched from there | Location/ACL policy rejects execution even when bytes and signature match |
| PKG-015 | Release manifest is truncated, duplicated, reordered, rolled back, or mixed across versions | Signed canonical manifest validation rejects every incomplete/mixed set; approved rollback policy is explicit |
| PKG-016 | Antivirus/indexer locks active old set during cleanup, then locks a file required for new extraction | Old complete set remains usable in the first subcase; new launch fails and old set remains active in the second; no partial set activates |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| COMPAT-001 | `cmd` performs file/process fixture workflow | Allowed work succeeds, denied work is contained, output/exit are correct |
| COMPAT-002 | Windows PowerShell and supported PowerShell edition perform workflow | Same policy results across editions |
| COMPAT-003 | Supported Node versions perform file/process/network workflow | Same externally visible decisions |
| COMPAT-004 | Supported Python versions perform workflow | Same externally visible decisions |
| COMPAT-005 | Supported Git performs status, checkout-like fixture mutation, and local fetch | Local and network policy behavior is correct |
| COMPAT-006 | Rust compiler/Cargo builds a fixture crate | Compiler/cache compatibility grants are explicit and mandatory denies remain effective |
| COMPAT-007 | Representative package-manager/compiler caches are enabled | Only named compatibility paths use `inherit_user`; no dynamic auto-grant occurs |
| COMPAT-008 | Supported Windows/architecture CI matrix runs full release suite | Every required cell passes and records versions/artifacts |
| COMPAT-009 | Unsupported Windows or architecture is used | Typed unsupported result is returned, never silent partial enforcement |
| COMPAT-010 | Paths/profile/tool output use non-ASCII locale | Policy, process, streams, and events preserve meaning without lossy conversion |
| COMPAT-011 | One Agent workspace runs shell, PowerShell, Python, Node, Git, Cargo/Rust, and a declared native compiler | All in-workspace file, child-process, cache, build, and executable workflows succeed on the first attempt; external toolchain roots are data-driven and read-only |
| COMPAT-012 | The Agent workspace path contains spaces and non-ASCII characters | Every supported tool preserves the path and keeps all generated state beneath the workspace |
| COMPAT-013 | Compatibility Profile declares the users-hive root | Only exact-read-only `HKU` is accepted; recursive or SID-subtree grants fail closed |
| COMPAT-014 | Agent tool scenarios are loaded from the checked-in matrix | Required tool families are complete; duplicate, malformed, privileged-by-default, absolute-machine-path, and silently skipped required scenarios fail validation |
| COMPAT-015 | Required tools available on the host execute from declarative scenarios | Each runs once in a non-ASCII workspace, receives only configured read/metadata roots and private state, produces configured evidence, and never silently retries or writes outside the workspace |
| COMPAT-016 | A command succeeds after denied optional probes | Resolver returns `NoPrompt(CommandSucceeded)` and no authority suggestion |
| COMPAT-017 | A failed command has duplicate canonical external read violations | Resolver returns one exact read-only candidate with stable proposal identity and duplicate count |
| COMPAT-018 | Violations overlap mandatory-sensitive content or request host writes | No ordinary grant is proposed; typed unavailable capabilities identify the boundary |
| COMPAT-019 | Distinct violation evidence was dropped or is incomplete | Resolver refuses to guess a grant and returns `IncompleteEvidence` |
| COMPAT-020 | Trusted host requests isolated named-pipe compatibility | Default remains deny; explicit isolated mode rewrites only local Win32 pipe names into an execution-private namespace while remote/arbitrary native namespace access remains denied |
| COMPAT-021 | Tool queries free-space metadata for the workspace volume | Capacity query succeeds without granting a root directory handle, file enumeration, content read, or another volume/share |
| COMPAT-022 | User rejects one aggregated compatibility proposal | Identical proposal is suppressed in its workspace scope without hiding final audit evidence |
| COMPAT-023 | User approves a proposal for one restart | Approval is consumable exactly once, then the same proposal requires a new decision |
| COMPAT-024 | User approves a proposal for the workspace | Identical tool identity and grants reuse approval; changed executable hash, workspace, or proposal content does not |
| COMPAT-025 | Trusted host applies an approved filesystem proposal | A cloned policy gains only the proposed exact read/metadata authority; original policy remains unchanged |
| COMPAT-026 | Proposal fields are forged or changed to mandatory-sensitive content | Application fails with `InvalidProposal` and produces no policy |
| COMPAT-027 | Approved registry query proposal is applied | New policy receives exact-key read-only authority, never a recursive registry subtree |
| COMPAT-028 | A completed failed transactional command has one approved proposal | Restart plan consumes approval and rejects a second plan for the same one-shot decision |
| COMPAT-029 | Approved restart has a retained staged/projected transaction | Old transaction is discarded before new target creation; discard failure prevents restart |
| COMPAT-030 | Approved restart starts with minimally extended policy | New execution/policy generation succeeds from the beginning; no live Job receives widened authority |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| LIC-001 | Detours and BuildXL revisions are inspected | Revisions are pinned and reproducible |
| LIC-002 | Imported source list and transitive native dependencies are compared with notices | Every imported file has origin, revision, license, and modification boundary |
| LIC-003 | GPL reference projects and closed-source findings are scanned against imported code | No copied incompatible/reference-only code is present |
| LIC-004 | Native build fetches dependencies | Inputs are pinned and hashes/verifiable provenance are recorded |
| LIC-005 | Release package is assembled | Required MIT notices and `THIRD_PARTY_NOTICES.md` are included |

| ID | Scenario | Expected observation |
| --- | --- | --- |
| PERF-001 | Warm minimal process launch against native control | Median overhead is under 100 ms on recorded representative workstation |
| PERF-002 | Hook initialization handshake | Distribution meets under-50-ms target and reports tail latency |
| PERF-003 | Common development filesystem workload against control | Steady-state overhead target is below 5%, with workload and confidence reported |
| PERF-004 | x86/x64 and each supported Windows version run launch benchmark | No matrix cell has unexplained regression beyond agreed tolerance |
| PERF-005 | Event-free and violation-heavy workloads run | Hook path remains bounded; event pressure does not deadlock target |
| PERF-006 | Deep process tree and rapid churn run | Injection/lifecycle overhead and failure rate stay within recorded budget |
| PERF-007 | Network unrestricted/denied/allow-list modes run local throughput tests | Enforcement overhead is measured per mode without public-network noise |
| PERF-008 | Long-running workload samples memory/handles/threads | No unbounded growth or per-operation disk logging appears |
| PERF-009 | Recovery quotas are stressed | Memory/disk/index growth remains bounded by configured limits |
| PERF-010 | Baseline is compared with current release | Statistically significant regressions block release unless explicitly approved |
| PERF-011 | Release configuration omits an agreed memory/handle/thread budget | Performance gate fails as `NOT_CONFIGURED`; absence of a threshold cannot count as pass |
| PERF-012 | Idle and sustained workloads run to steady state over the agreed duration | Peak and slope for private bytes, committed memory, handles, and threads remain within configured absolute and growth budgets |
| PERF-013 | Benchmark machine is thermally unstable, power-throttled, busy, or differs materially from baseline profile | Run result is `INVALID_ENVIRONMENT` and the release performance gate remains unsatisfied |
| PERF-014 | Warmup/sample count/confidence criteria are not met | Benchmark reports insufficient evidence and release gate fails rather than using a single favorable sample |

## Cross-cutting release-gate scenarios

These cases are aliases for required evidence bundles, not substitutes for the
individual cases above.

| ID | Evidence bundle | Pass condition |
| --- | --- | --- |
| GATE-001 | Initialization | `PROC-001..002`, `IPC-010..025`, `SEC-001..005` prove no unsandboxed fallback |
| GATE-002 | Filesystem coverage | All `FS`, `SEM-001..004`, and applicable `HOOK` cases pass on required API families and architectures |
| GATE-003 | Mandatory denies | `POL-007..009`, `FS-049..050`, `REG-008..009` cannot be weakened by child input |
| GATE-004 | Descendant confinement | `PROC-003..034` and `LIFE-003..016` leave no normally created unconfined child |
| GATE-005 | Secret handling | `REQ-006`, `EVT-009`, `REG-020`, `REC-010..016`, `SEC-006..007,017` pass canary scan |
| GATE-006 | Component compatibility | `PKG-001..016`, `BND-001..008`, `COMPAT-008..009` pass for all supported matrix cells |
| GATE-007 | Third-party compliance | All `LIC` cases pass and artifacts are attached |
| GATE-008 | Performance | All `PERF-001..014` cases have reproducible results within accepted budgets |
| GATE-009 | Cross-runtime semantics | All `SEM` cases show zero Rust/x86/x64 decision disagreement for fixed and generated vectors |
| GATE-010 | Hook robustness | All `HOOK` cases pass under fault injection, concurrency, and long-run stress |

## Deferred-but-retained cases

ARM64/ARM64EC enforcement, AppContainer/BaseContainer, kernel-driver behavior,
registry virtualization, and hostile-binary containment are not initial-release
claims. Their future cases must use separate prefixes and cannot be counted as
passing or skipped initial-release coverage. `PROC-015`, `COMPAT-009`, and the
`BYP`-class scenarios above verify that current limitations are explicit.
`REC-011` is retained only for a future encrypted secret-store mode; initial
release evidence is `REC-010`, which requires that no secret backup is created.
