# ADR-0001: Use manifest-bound read-only compatibility profiles

**Date**: 2026-09-01  
**Status**: accepted  
**Deciders**: Bolt Sandbox maintainers and project owner

## Context

General-purpose Agent workloads run many runtimes and toolchains whose startup
probes differ by machine and release. Hardcoding every compatible file and
registry path in Rust or C++ makes routine Node, Python, Git, or build-tool
updates require a code release. A freely editable runtime allowlist would be
easier to change, but it would also let a compromised target or prompt broaden
its own authority.

## Decision

Bolt Sandbox stores compatibility allows in a strict, read-only profile shipped
beside the native components. The component manifest binds the profile length
and SHA-256 digest, package ACLs prevent target mutation, and production hosts
may pin the whole manifest digest. Code retains parsing limits, safe placeholder
semantics, fail-closed behavior, and deny precedence; it does not retain
tool-specific allow paths.

## Alternatives Considered

### Keep tool-specific paths in code

- **Pros**: Small initial implementation and compile-time visibility.
- **Cons**: Every runtime probe becomes a code change; compatibility knowledge
  remains scattered across policy and execution modules.
- **Why not**: It repeatedly broke ordinary Node and Python startup and does not
  scale to heterogeneous Agent workloads.

### Load an arbitrary user-selected profile at execution time

- **Pros**: Maximum flexibility and no repackaging step.
- **Cons**: A prompt-controlled command line, environment, or writable file
  could silently expand sandbox authority.
- **Why not**: The target must never choose or modify its enforcement policy.

### Default-read all of Program Files and the user profile

- **Pros**: High compatibility with installed tools.
- **Cons**: Exposes unrelated application configuration, package credentials,
  cloud profiles, source repositories, and browser data.
- **Why not**: Compatibility does not justify broad host-data disclosure.

## Consequences

### Positive

- Compatibility updates become auditable data changes.
- The shipped profile is versioned, hashed, signed with the package, and easy to
  review independently from hook code.
- Version 1 can grant only content-read or metadata-read access; write access
  remains task-specific.
- Explicit and mandatory denies continue to override compatibility grants.

### Negative

- Changing the production profile changes the manifest digest and requires the
  normal trusted packaging workflow.
- Some tools still require task-private writable HOME, TEMP, or cache
  redirection rather than a profile entry.

### Risks

- A broad or escaped profile path could disclose host data. The parser rejects
  roots, traversal, globs, unknown placeholders, duplicates, oversized input,
  and unsupported grant types.
- Optional machine-specific roots may be unavailable. Optional entries skip
  only when their trusted base is absent; malformed or escaped entries fail the
  complete profile.
- Profile tampering could broaden authority. The runtime holds a no-replacement
  read lease and verifies the profile against the component manifest before
  compiling policy.
