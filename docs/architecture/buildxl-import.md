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
- Add only the smallest source and dependency set needed by a tested behavior.
- Preserve upstream license and notice files.
- Do not import the scheduler, build graph, C# engine, or BuildXL manifest wire
  protocol.

## Staged import

The first slice contains `TreeNode.h`, `TreeNode.cpp`, `PathTree.h`, and
`PathTree.cpp`, providing BuildXL's case-insensitive path tree. A narrow adapter
implements the Windows-only `TryDecomposePath` function from BuildXL
`StringOperations.cpp` without importing that file's unrelated cross-platform
and manifest dependencies.

The next slices are:

1. `CanonicalizedPath`, `PolicySearch`, and `PolicyResult`, behind Bolt-owned
   policy adapters.
2. The filesystem detours, handle overlay, process injector, and reporting
   components needed by the architecture's enforcement matrix.
