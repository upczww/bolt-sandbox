# ADR-0002: Separate enforcement from transactional workspaces

**Date**: 2026-09-01
**Status**: accepted
**Deciders**: project owner and Codex

## Context

WorkBuddy demonstrates useful Agent ergonomics through ProjFS projection,
change review, backup, PTY, session state, and prewarming. Its Windows runtime
also permits fail-open fallback, broad dynamic grants, and user-mode-only
coverage that conflict with Bolt Sandbox's security and portability goals.
Bolt already provides sub-100-ms startup and fail-closed file, process, network,
registry, IPC, and recovery enforcement.

## Decision

We keep the existing Bolt execution boundary authoritative and add
transactional workspace behavior through a replaceable `WorkspaceBackend`.
ProjFS may provide an optional workspace view but never grants authority or
replaces Hook, Job, immutable policy, or recovery enforcement. Closed-source
WorkBuddy binaries are black-box semantic references only.

## Alternatives Considered

### Replace Bolt enforcement with a WorkBuddy-style ProjFS sandbox

- **Pros**: mature change review and low-friction write behavior.
- **Cons**: ProjFS does not cover registry, process, network, or direct source
  access and introduces provider/reparse failure modes.
- **Why not**: it is a workspace virtualization mechanism, not a complete
  sandbox boundary.

### Adopt the current Anthropic SRT Windows backend

- **Pros**: dedicated account and WFP provide a stronger kernel-backed network
  boundary.
- **Cons**: requires elevated machine provisioning and changes host ACLs.
- **Why not**: it conflicts with the default no-administrator, portable,
  sub-second product requirement. It remains a possible optional backend.

### Keep only direct workspace execution

- **Pros**: least complexity and lowest startup cost.
- **Cons**: weaker review, discard, conflict, and multi-file transaction UX.
- **Why not**: it does not provide the low-interruption Agent workflow the
  project now targets.

## Consequences

### Positive

- Security decisions remain immutable and fail closed.
- Direct mode retains its current performance and compatibility.
- Projection, PTY, recovery, and prewarming can evolve independently.
- Closed-source implementation code is not imported.

### Negative

- A ProjFS provider and trusted commit coordinator add significant Windows
  complexity and testing cost.
- Projection mode has a higher cold-start budget than direct mode.
- Commit/discard introduces source conflict and retention state.

### Risks

- **Projection bypass**: mandatory-deny the source workspace and test all path
  aliases, reparse points, handles, and races.
- **Silent downgrade**: return typed unsupported/failure results; never switch
  to direct execution implicitly.
- **Stale authority**: bind each command to a nonzero immutable policy
  generation and reject replay or mismatch.
- **Broker compromise or crash**: keep authority in trusted Rust, bind state to
  verified components, and terminate associated Jobs on loss.
