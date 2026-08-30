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
`TreeNode`, `PathTree`, `ResolvedPathCache`, `CanonicalizedPath`, and
`FilesCheckedForAccess`. The complete immutable `DetouredFunctions.cpp`
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

The Bolt filesystem hook layer canonicalizes mutation paths and invalidates the
upstream `ResolvedPathCache` before create, delete, directory mutation, move,
and hard-link calls. Directory and move invalidation conservatively removes
cached descendants, matching BuildXL's defense against stale reparse targets.

Create/open classification is a Bolt-owned compatibility seam derived from
BuildXL's `WantsWriteAccess`, `WantsReadAccess`, and probe-only split. It treats
attribute/EA/security/synchronization-only opens as metadata, execution/content
opens as reads, all mutation or unknown rights as writes, and classifies
`CREATE_NEW`, `CREATE_ALWAYS`, and `OPEN_ALWAYS` as creates. Unknown creation
dispositions fail closed as writes.

The first adapted BuildXL operation-family hook is `CopyFileW`. It evaluates
the source as read and the destination as write before invoking Windows,
reports the denied side through `EventSink`, and invalidates the destination
path cache on an allowed call. Unlike BuildXL's build-observation-oriented
post-call source check, Bolt performs both checks before the call so a denied
copy cannot leave a destination side effect.

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

The next slices are:

1. Activate access classification and handle overlay behind `PolicyView`.
2. Activate filesystem detours by operation family and route reports through
   `EventSink`.

The rest of `Public/Src/Sandbox/Windows` is deliberately not copied. It
contains BuildXL build definitions and unit-test infrastructure, a separate
Detours fork, and unrelated platform components. Required source is admitted
from the pinned revision when a tested runtime dependency demonstrates the
need.
