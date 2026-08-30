# BuildXL DetoursServices Import Boundary

Bolt Sandbox uses Microsoft BuildXL commit
`24a3f64655741d9ab8619d35d12513e6a7baabc1` as the immutable upstream for
DetoursServices adaptation. Imported files and SHA-256 digests are recorded in
`native/third_party/buildxl/provenance.json` and verified by
`scripts/test-third-party.ps1`.

This revision is the last commit modifying DetoursServices before the audit.
The audit also compared the imported source blobs with main snapshot
`c73b56a4c3e6b3956ffa73d7f88866c9f772bf23`; they are identical.

## Rules

- Keep files under `native/third_party/buildxl/` byte-for-byte identical to the
  pinned upstream revision.
- Put compatibility headers, policy conversion, event conversion, and other
  Bolt-specific changes outside the vendored directory.
- Import coherent upstream dependency closures, then activate them incrementally
  behind tested Bolt-owned interfaces.
- Preserve upstream license and notice files.
- Do not import the scheduler, build graph, C# engine, or BuildXL manifest wire
  protocol.

## Vendored adaptation baseline

The repository vendors the 55-file DetoursServices Windows runtime closure
needed to adapt BuildXL's path handling, access classification, handle overlay,
metadata virtualization, detoured filesystem/process functions, manifest
iteration, process injection, substitution, and reporting seams.
This is a source and provenance baseline: vendored does not mean linked or
shipped. The exact file list and hashes are enforced by the import manifest.

The currently compiled upstream subset is `Assertions`, `StringOperations`,
`TreeNode`, `PathTree`, `ResolvedPathCache`, `CanonicalizedPath`,
`FilesCheckedForAccess`, and `DetouredScope`. The complete immutable `DetouredFunctions.cpp`
translation unit is also compiled as an object-only compatibility contract for
x86/x64 Debug and Release, but is not linked into Bolt. This subset
provides BuildXL's case-insensitive hashing and path comparison, Win32 path
normalization, case-insensitive path tree, reparse-resolution cache and
invalidation, canonical paths, and checked-path set. The former hand-written
string-operation subset has been removed.

CMake copies the immutable path-core files byte-for-byte into a generated
adaptation directory. In that directory only, Bolt's narrow
`FileAccessHelpers` and `UtilityHelpers` compatibility headers replace the
same-named BuildXL headers that otherwise pull in manifest, reporting, and
process-injector globals. `Assertions.cpp` and `StringOperations.cpp` compile
directly from the vendored paths. `DetouredFunctionTypes.h` is also copied
unchanged into this narrow include boundary so hook signatures reuse BuildXL's
audited Windows API declarations without exposing its wider header graph.
`DetouredScope.cpp/h` are copied unchanged and compiled with a minimal generated
precompiled-header adapter; the upstream thread-local scope ensures recursive
Windows calls made by hook implementation details bypass policy re-entry.

The Bolt filesystem hook layer canonicalizes mutation paths and invalidates the
upstream `ResolvedPathCache` before create, delete, directory mutation, move,
and hard-link calls. Directory and move invalidation conservatively removes
cached descendants, matching BuildXL's defense against stale reparse targets.
Directory creation also resolves the parent directory's final identity and
appends the new leaf before its second write-policy check, preventing an
allowed path containing an intermediate junction from creating beneath a
denied target. Directory removal uses the same parent-final/leaf-preserving
deletion rule as files and invalidates cached descendants before an allowed
native call. x86 and x64 integration probes also exercise `CreateDirectoryA`
and `RemoveDirectoryA`; on the supported Windows baseline those wrappers funnel
through the installed wide-character hooks, including final-target events and
denied-call output/side-effect preservation.

Create/open classification is a Bolt-owned compatibility seam derived from
BuildXL's `WantsWriteAccess`, `WantsReadAccess`, and probe-only split. It treats
attribute/EA/security/synchronization-only opens as metadata, execution/content
opens as reads, all mutation or unknown rights as writes, and classifies
`CREATE_NEW`, `CREATE_ALWAYS`, and `OPEN_ALWAYS` as creates. Unknown creation
dispositions fail closed as writes.

`CreateFileW/A` apply that classification first to the textual identity and
again to the fully resolved identity before returning a handle. Intermediate
junctions therefore cannot grant access to a denied target. Calls carrying
`FILE_FLAG_OPEN_REPARSE_POINT` resolve only the parent and preserve the leaf
reparse object, matching the caller's requested object identity.

Synchronous `ReadFile` and `WriteFile` resolve the final identity from the
supplied handle and reapply read or write policy before submitting I/O. This
closes inherited-handle bypasses and zeroes the byte count on policy denial.
The authenticated event-pipe handle is the sole current non-disk write bypass,
allowing `EventSink` to report violations without recursively blocking itself.

Direct `NtReadFile` and `NtWriteFile` calls share the same handle decision.
Denied native submissions return `STATUS_ACCESS_DENIED`, set result information
to zero, leave caller buffers untouched, and do not signal the optional event
or invoke an APC because no I/O request reaches the kernel.

On supported Windows versions, `ReadFileEx` and `WriteFileEx` converge on those
native submission seams. Dedicated overlapped-handle tests verify that denial
occurs before submission, buffers remain unchanged, and completion routines
are never queued; no duplicate high-level detour is installed.

The first adapted BuildXL operation-family hooks are `CopyFileW/A`,
`CopyFileExW/A`, `CopyFileTransactedW/A`, and the dynamically resolved
`CopyFile2`. Like upstream BuildXL, ANSI entry points convert once and
delegate to the wide-character operation path. All entries share one
source/destination authorization path that
evaluates the source as read and the destination as write before invoking Windows,
reports the denied side through `EventSink`, and invalidates the destination
path cache on an allowed call. Unlike BuildXL's build-observation-oriented
post-call source check, Bolt performs both checks before the call so a denied
copy cannot leave a destination side effect.

The move family follows the same upstream funnel: `MoveFileW/A`,
`MoveFileExW/A`, `MoveFileWithProgressW/A`, and `MoveFileTransactedW/A`
share one source/destination authorization path. Both sides require write
access, denied calls report `Rename`, and ANSI variants delegate to the
wide-character implementation after conversion.

Shell deletion through `SHFileOperationW/A` preflights every entry in the
double-NUL source list with the same delete decision before invoking Shell32.
This prevents partial multi-item deletion, returns `ERROR_ACCESS_DENIED`, and
marks the operation aborted when any source is denied. Shell copy, move, and
rename similarly preflight the complete source/destination lists, including
`FOF_MULTIDESTFILES`, through the existing two-sided BuildXL-derived policy
funnels before allowing any Shell side effect.

BuildXL's vendored `ReplaceFileW` hook currently contains a policy TODO and
only invalidates its cache. Bolt therefore keeps the upstream signature and
scope pattern but supplies the architecture-required fail-closed adapter:
`ReplaceFileW/A` validate the consumed replacement source, replaced target,
and optional backup as independent write identities before invoking Windows.

The first handle-mutation adapter covers
`SetFileInformationByHandle` rename and disposition classes. Following BuildXL's flow, it
obtains the source's final path from the handle, decodes the length-delimited
destination, and applies the same two-sided write authorization as path-based
moves. `FileDispositionInfo` and `FileDispositionInfoEx` requests carrying a
delete flag require write access to that final source identity; requests that
clear disposition pass through unchanged. Unsupported or malformed mutation
identities fail closed, while unrelated file information classes retain native
Windows behavior.

`DeleteFileW/A` preserve BuildXL's last-reparse-point deletion semantics while
closing intermediate junction escapes: Bolt resolves the parent directory's
final identity, appends the untouched leaf name, and requires write access to
that resulting object before calling Windows. ANSI deletion follows BuildXL's
conversion funnel into the same wide-character decision.

Bolt also detours Win32 `SetEndOfFile` directly so an inherited or duplicated
write handle cannot bypass path policy. The adapter resolves the handle's final
identity, requires write access, reports denied truncation as `Write`, and only
then invokes the real API. Bolt also attaches BuildXL's exact
`ZwSetInformationFile_t` seam and applies the same check to allocation and
end-of-file information classes. Its disposition and extended-disposition
branches mirror the Win32 delete-flag split and report `Delete`. Direct NT
rename and extended-rename classes decode the NT length-delimited target and
reuse two-sided move authorization. Direct NT callers receive native
`STATUS_ACCESS_DENIED` without modifying the file; unsupported root-handle
relative rename identities fail closed.

BuildXL's vendored headers still mark `CreateFileMapping*` as a TODO. Bolt's
adapter therefore reuses final handle identity rather than importing incomplete
logic: `CreateFileMappingW/A` require write access for `PAGE_READWRITE` and
`PAGE_EXECUTE_READWRITE`, and read access for read-only or copy-on-write file
mappings. The same classifier is attached directly to `NtCreateSection` for
native callers. Anonymous page-file mappings and sections retain native
behavior.

`CreateHardLinkW/A` use BuildXL's exact function types and the shared
source-read/destination-write authorization path. Both identities are resolved
before Windows is called, preventing an allowed junction from placing a new
hard-link directory entry in a denied target.

`CreateSymbolicLinkW/A` retain BuildXL's exact signatures and ANSI-to-Unicode
funnel. Bolt preserves BuildXL's write check for the link location and adds the
FS-028 target metadata decision required by its containment model. Both final
identities are resolved before Windows is called, so an allowed link location
cannot create a reparse object aimed at a denied target.

Bolt extends BuildXL's `DeviceIoControl_t` seam beyond upstream GET-path
translation for `FSCTL_SET_REPARSE_POINT`. Mount-point and symbolic-link
buffers are length-checked, unknown tags fail closed, and both the reparse
handle source and decoded target are authorized before Windows can create the
link. Successful changes invalidate the resolved-path cache subtree.

The same seam classifies `FSCTL_SET_COMPRESSION` as a handle-based write.
Bolt resolves the final file identity before the control reaches Windows,
reports denied calls as `Write`, and preserves the prior compression state.

Directory enumeration begins with BuildXL's `FindFirstFileW/A` and
`FindFirstFileExW/A` function families. All four entries share a metadata
authorization decision and report denied searches as `Enumerate` before any
search handle or directory entry can be returned. The adapter resolves the
wildcard's parent directory and rechecks the reconstructed final search path,
so an allowed junction cannot expose names from a denied directory while the
wildcard leaf retains its original meaning.

Direct `NtQueryDirectoryFile` reuses BuildXL's exact function type, while
`NtQueryDirectoryFileEx` supplies the newer native signature absent from the
vendored revision. Both resolve the directory handle's final identity and
return `STATUS_ACCESS_DENIED` with zero result information before synchronous
or asynchronous enumeration can expose an entry.

`ReadDirectoryChangesW` is a Bolt-owned narrow seam because the vendored
BuildXL layer has no dedicated wrapper. It authorizes the directory handle's
final identity as enumeration before submitting synchronous, overlapped, or
completion-routine notification work. A denied watch returns
`ERROR_ACCESS_DENIED`, zeros only the documented byte count, leaves the caller
buffer and overlapped state untouched, and cannot schedule a completion.
The native `NtNotifyChangeDirectoryFile` and
`NtNotifyChangeDirectoryFileEx` entry points share that final-handle decision.
They return `STATUS_ACCESS_DENIED` with zero completion information before an
event or APC can be registered; both native signatures are Bolt-owned because
the vendored BuildXL revision does not declare dedicated wrappers.

Direct native opens reuse BuildXL's exact `NtCreateFile_t` and `NtOpenFile_t`
signatures. Bolt maps the six NT create dispositions to the existing access
classifier, treats delete-on-close as deletion, preserves open-reparse-point
leaf semantics, and routes absolute object paths through the same final-target
policy decision as `CreateFileW/A`. Root-relative object names first resolve
the supplied directory handle's final DOS identity, then append and normalize
the length-delimited relative name before authorization. Embedded-null and
absolute names paired with a root handle fail closed. Denial returns
`STATUS_ACCESS_DENIED`, clears the output handle and completion information,
and never calls ntdll.

`OpenFileById` reuses BuildXL's exact function type; the vendored implementation
is an explicit policy TODO and is not linked. Bolt opens the identified object
without the destructive delete-on-close flag, authorizes the returned handle's
final identity using the requested access class, and closes denied handles
before returning `ERROR_ACCESS_DENIED`. For an allowed delete-on-close request,
the existing handle-disposition seam applies deletion only after final-identity
authorization, avoiding a side effect during the identity probe.

Metadata probing through `GetFileAttributesW/A` and
`GetFileAttributesExW/A` shares one metadata-policy decision. Denied targets
return the native failure sentinel, preserve `ERROR_ACCESS_DENIED`, and cannot
leak existence, type, size, or timestamps through the output structure.
Their identity resolver follows every parent junction while preserving the
leaf reparse object, so an allowed textual alias cannot reveal metadata from a
denied final parent target.

Handle metadata probing through BuildXL's exact
`GetFileInformationByHandle*` function types resolves the final file identity
before invoking Windows. Direct `NtQueryInformationFile` calls share that
decision and return native `STATUS_ACCESS_DENIED`, preventing a previously
obtained handle from leaking attributes, size, timestamps, names, or IDs.
x86 and x64 integration probes additionally call
`GetFinalPathNameByHandleW/A` on an inherited denied handle. On the supported
Windows baseline both wrappers converge on that installed native-query
decision, leaving path buffers untouched and emitting canonical metadata
events without a duplicate top-level detour.

Path-based `NtQueryAttributesFile` and `NtQueryFullAttributesFile` calls decode
the length-delimited absolute `OBJECT_ATTRIBUTES` name and pass the DOS/UNC
identity through the same metadata seam. Denials return
`STATUS_ACCESS_DENIED` before the native call. Root-directory-relative names
remain fail-closed until their dedicated FS-052 identity tests activate that
resolution path.

Attribute mutation through `SetFileAttributesW/A` is a Bolt-owned Win32 seam
because the vendored BuildXL layer has no dedicated wrapper. Both variants
require write access, report denied changes as `Write`, and invalidate the path
cache before an allowed native call. The shared mutation seam rechecks the
fully resolved target, so security descriptor and EFS operations using the
same seam also cannot cross an intermediate junction.

Security descriptor mutation through `SetFileSecurityW/A` uses the same
Bolt-owned write seam because the vendored BuildXL layer has no dedicated
wrapper. ANSI paths are converted only for policy evaluation; the original
native entry point receives the caller's descriptor after authorization.
Denied calls preserve the descriptor and return `ERROR_ACCESS_DENIED`.

BuildXL declares and funnels `EncryptFileW/A` and `DecryptFileW/A`, but leaves
their wide-character policy logic as TODOs. Bolt reuses those exact function
types and applies its write seam before the native EFS operation, so policy
denials and events remain deterministic even when the underlying volume does
not support EFS.

`SetFileTime` closes the handle-based timestamp gap: non-empty time updates
resolve the handle's final identity and require write access, while an all-null
call retains native behavior. Denied updates report `Write` and leave every
timestamp unchanged.

The direct `ZwSetInformationFile` classifier also covers
`FileBasicInformation`, closing native timestamp/attribute mutation bypasses
with the same final-handle write decision and native NT denial result.

For textually allowed copy, move, and replace operation paths, Bolt resolves the nearest existing ancestor
through the real `CreateFileW` trampoline and `GetFinalPathNameByHandleW`,
appends any absent suffix, then evaluates the fully resolved source and
destination again with the operation-specific access requirements. Results use BuildXL's `ResolvedPathCache`; the existing
mutation invalidation path prevents stale junction/symlink targets. A denied
final target is reported by its resolved canonical identity and Windows is not
called.

The remaining vendored files are not yet members of a Bolt runtime link target.
They
are activated only after a failing behavior or compile-contract test defines
the required boundary. In particular, `DataTypes`, `PolicySearch`,
`PolicyResult`, and `SendReport` preserve the dependency context of the
upstream detour implementation but their BuildXL manifest and report protocols
must never become Bolt runtime inputs or outputs.

Bolt-owned adapters replace these coupled seams:

- `PolicyView` maps the authenticated Bolt policy payload to one fail-closed
  decision plus the canonical, prefix-independent path identity produced by
  BuildXL. Hooks reuse that identity for events and cache invalidation; source
  and destination evaluations remain distinct for rename and hard-link calls.
- `EventSink` maps hook outcomes to Bolt events and backpressure behavior. Its
  current filesystem implementation uses 64 preallocated records, assigns
  monotonic sequences after the Ready frame, and performs pipe writes on a
  dedicated worker. Hook calls only attempt a bounded enqueue and never wait
  for the pipe consumer; an explicit bounded drain is available for orderly
  process shutdown.
- Process injection and lifecycle adapters map Bolt execution state without a
  BuildXL scheduler, build graph, or C# host.

The first process-policy slice reuses BuildXL's exact `CreateProcessW_t` and
`CreateProcessA_t` signatures. Child policy is read only after the complete
Bolt payload passes integrity and shape validation, and both process hooks join
the same Detours transaction as filesystem hooks. `Deny` clears the caller's
process-information output and returns `ERROR_ACCESS_DENIED` before Windows can
create a process. For same-architecture descendants, `Inherit` follows
BuildXL's suspended-injection ordering: runtime handles are duplicated into the
child, the authenticated payload and matching hook DLL are installed, and a
private ready/release handshake completes before user code can run. The private
handshake avoids emitting a second session `Ready` frame. A caller-requested
`CREATE_SUSPENDED` state is restored before release to the caller. Injection,
duplication, or readiness failure terminates the child and clears its process
information; an unconfined child is never used as a fallback. Cross-architecture
descendants select the hook DLL from the actual process machine and use
Microsoft Detours' public helper payload/ordinal-1 flow. The Bolt adapter keeps
the upstream helper protocol but resolves the system directory independently of
the untrusted target environment and gives the helper a minimal, non-secret
`SystemRoot`/`WINDIR` environment. This provides both x64-to-x86 and
x86-to-x64 injection without importing BuildXL's C# `ProcessTreeContext` host.

The initial token-boundary slice attaches Bolt-owned
`CreateProcessWithTokenW` and `CreateProcessWithLogonW` seams in the same
transaction. Both are denied before Windows validates token or credential
inputs, clear `PROCESS_INFORMATION`, and enqueue a fixed process-operation
violation. The event contains no token, username, credential, application, or
command-line data. Calls made inside a disabled `DetouredScope` retain their
real API path for trusted hook implementation details.

`CreateProcessAsUserW/A` now reuse BuildXL's exact function declarations and
suspended child-injection ordering. A caller-supplied non-elevated primary token
is preserved, while Bolt adds `CREATE_SUSPENDED`, installs the inherited runtime,
waits for descendant readiness, and then restores the caller's suspension
semantics. Under `Deny`, both entry points fail before token validation and
clear `PROCESS_INFORMATION`; ordinary Windows token or privilege failures under
`Inherit` are returned unchanged when no process was created.

Direct executable activation through `ShellExecuteExW` is verified to reach the
same detoured `CreateProcessW` inheritance path. Bolt adds only a narrow,
case-insensitive `runas` guard around that upstream-backed path: elevation is
denied before Shell resolves the target or contacts an elevation broker, the
returned process handle is cleared, and the event contains only process identity
plus the fixed elevation operation. The reentrancy scope ends before ordinary
Shell activation so its nested process creation remains detoured.

The next slices are:

1. Activate access classification and handle overlay behind `PolicyView`.
2. Activate filesystem detours by operation family and route reports through
   `EventSink`.

The rest of `Public/Src/Sandbox/Windows` is deliberately not copied. It
contains BuildXL build definitions and unit-test infrastructure, a separate
Detours fork, and unrelated platform components. Required source is admitted
from the pinned revision when a tested runtime dependency demonstrates the
need.
