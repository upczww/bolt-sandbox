# BuildXL DetoursServices Import Boundary

Bolt Sandbox uses Microsoft BuildXL commit
`c73b56a4c3e6b3956ffa73d7f88866c9f772bf23` as the immutable upstream for
DetoursServices adaptation. Imported files and SHA-256 digests are recorded in
`native/third_party/buildxl/provenance.json` and verified by
`scripts/test-third-party.ps1`.

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

The first slice contains `TreeNode.h` and `TreeNode.cpp`, the case-insensitive
child collection used by BuildXL's path tree. This establishes a compiled
upstream component before importing path decomposition and policy search.

The next slices are:

1. `PathTree` and the minimum Windows path decomposition functions.
2. `CanonicalizedPath`, `PolicySearch`, and `PolicyResult`, behind Bolt-owned
   policy adapters.
3. The filesystem detours, handle overlay, process injector, and reporting
   components needed by the architecture's enforcement matrix.
