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

The repository vendors the 49-file DetoursServices filesystem runtime closure
needed to adapt BuildXL's path handling, access classification, handle overlay,
metadata virtualization, detoured filesystem functions, and reporting seams.
This is a source and provenance baseline: vendored does not mean linked or
shipped. The exact file list and hashes are enforced by the import manifest.

The currently compiled upstream subset is `Assertions`, `StringOperations`,
`TreeNode`, `PathTree`, `CanonicalizedPath`, and `FilesCheckedForAccess`. It
provides BuildXL's case-insensitive hashing and path comparison, Win32 path
normalization, case-insensitive path tree, canonical paths, and checked-path
set. The former hand-written string-operation subset has been removed.

CMake copies the immutable path-core files byte-for-byte into a generated
adaptation directory. In that directory only, Bolt's narrow
`FileAccessHelpers` and `UtilityHelpers` compatibility headers replace the
same-named BuildXL headers that otherwise pull in manifest, reporting, and
process-injector globals. `Assertions.cpp` and `StringOperations.cpp` compile
directly from the vendored paths.

The remaining vendored files are not yet members of a Bolt build target. They
are activated only after a failing behavior or compile-contract test defines
the required boundary. In particular, `DataTypes`, `PolicySearch`,
`PolicyResult`, and `SendReport` preserve the dependency context of the
upstream detour implementation but their BuildXL manifest and report protocols
must never become Bolt runtime inputs or outputs.

Bolt-owned adapters replace these coupled seams:

- `PolicyView` maps the authenticated Bolt policy payload to access decisions.
- `EventSink` maps hook outcomes to Bolt events and backpressure behavior.
- Process injection and lifecycle adapters map Bolt execution state without a
  BuildXL scheduler, build graph, or C# host.

The next slices are:

1. Activate access classification and handle overlay behind `PolicyView`.
2. Activate filesystem detours by operation family and route reports through
   `EventSink`.

The rest of `Public/Src/Sandbox/Windows` is deliberately not copied. It
contains BuildXL build definitions and unit-test infrastructure, a separate
Detours fork, and components such as process substitution and manifest
iteration that are outside Bolt's architecture. Required source is admitted
from the pinned revision when a tested runtime dependency demonstrates the
need.
