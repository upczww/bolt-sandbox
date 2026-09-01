# Agent Sandbox Evolution Plan

## Objective

Evolve Bolt Sandbox into a low-friction general Agent runtime without weakening
its fail-closed Windows enforcement. The implementation may adopt WorkBuddy's
useful product patterns—transactional workspaces, change review, PTY support,
session cleanup, command attribution, and measured prewarming—but must not copy
its closed-source sandbox or inherit its fail-open behavior.

## Non-negotiable boundaries

- The existing Job, launcher, hook, immutable policy, event, network, registry,
  and recovery paths remain the security boundary.
- ProjFS is an optional transactional workspace adapter, not an authorization
  boundary. The target cannot write the source workspace while projection mode
  is active.
- A broker, projection provider, policy update, hook, or IPC failure terminates
  or rejects the execution. There is no unsandboxed fallback.
- Runtime compatibility remains Manifest-bound and data-driven. Tool and
  machine paths do not enter product code.
- Network remains explicit and restrictive modes remain default-deny.
- Browser, shell, package manager, and compiler processes receive no bypass or
  injection exemption.
- Dynamic approval creates a new immutable policy generation. The target cannot
  append authority to its current policy.
- Diagnostics contain identifiers and typed reasons, never commands,
  environment values, secrets, or protected paths.

## Target architecture

```text
Agent / CLI / SDK
        |
        | command_id + policy_generation
        v
Trusted session coordinator
        +-- immutable policy compiler
        +-- WorkspaceBackend
        |     +-- DirectWorkspaceBackend
        |     `-- ProjectedWorkspaceBackend (optional ProjFS)
        +-- change journal / conflict detector
        +-- commit / discard / recovery coordinator
        `-- optional prewarmed broker
                    |
                    v
Execution Job -> launcher -> injected hook -> complete descendant tree
```

## Delivery phases

### Phase 0: specification and executable RED cases

- Record the architecture decision and threat model.
- Add stable attribution, workspace, PTY, broker, and transactional case IDs.
- Add the first compile-time RED contract for command attribution.

### Phase 1: command attribution and immutable policy generations

- Add an opaque fixed-size `CommandId`; never serialize command text.
- Assign a monotonic nonzero policy generation inside trusted Rust.
- Envelope every event with execution, command, and generation identity.
- Reject zero, stale, mismatched, replayed, or cross-execution attribution.
- Keep the current event payload types and bounded aggregation semantics.

### Phase 2: `WorkspaceBackend` abstraction

- Introduce `prepare`, `execution_root`, `query_changes`, `commit`, `discard`,
  and `close` lifecycle operations.
- Move current behavior behind `DirectWorkspaceBackend` without changing public
  semantics or startup performance.
- Keep workspace selection and mutation in trusted Rust.

### Phase 3: optional ProjFS backend

- Create a unique access-controlled projection root per session.
- Serve source content read-only and record target mutations in the projection.
- Deny target access to the source workspace during the run.
- Fail closed on unavailable ProjFS, callback failure, reparse ambiguity, IPC
  loss, or provider shutdown.
- Support create, modify, delete, rename, non-ASCII, case, and large-file cases.

Implemented: the provider dynamically loads only the system ProjFS library,
uses bounded callback pools, validates final source handles, rejects links,
reparse ambiguity and alternate streams, and materializes the merged view into
an ordinary transaction root before Rust exposes it. Provider callbacks and
materialization are exercised through an injected fake ProjFS function table;
the current workstation additionally verifies the real unavailable-component
path before target creation because `Client-ProjFS` is not installed.
`AutoTransactional` performs this authoritative probe through the verified
launcher and selects only between Projected and Staged; explicit Projected
requests retain strict no-fallback semantics.

### Phase 4: transactional commit and recovery

- Query and classify changes before commit.
- Revalidate source identities and hashes to detect host conflicts.
- Back up destructive targets before trusted-host mutation.
- Apply an all-or-fail commit plan; preserve the projection on failure.
- Support discard, bounded retention, and explicit revert.

### Phase 5: controlled ConPTY

- Add an explicit PTY capability for interactive commands.
- Transfer only the required input, output, resize, and control handles.
- Preserve Job containment, descendant injection, policy, and network behavior.
- Keep noninteractive pipe execution as the lower-overhead default.

### Phase 6: evidence-gated prewarming

- Preload verified component and parsed Profile state only when benchmarks show
  material benefit.
- Generate fresh execution identity, Job, policy payload, IPC, and recovery
  namespace for every command.
- Reject stale broker state and terminate associated Jobs if the broker exits.
- Do not ship the broker if improvement is less than 10 ms.

Decision: no broker ships by default. Seven final release samples measured
38.968–42.780 ms warm Direct startup (40.138 ms mean), and no bounded broker
prototype has demonstrated the required repeatable 10 ms improvement. See
ADR-0003. The no-evidence case fails the feature gate closed.

### Phase 7: optional hardened deployment backend

- Evaluate a dedicated low-privilege account and WFP enforcement for managed
  installations.
- Keep this optional because administrator provisioning conflicts with the
  default no-install, sub-second workflow.

## Performance budgets

- Direct warm startup: maximum 100 ms; current baseline is approximately 38 ms.
- Projected session cold preparation: maximum 250 ms.
- Projected warm command dispatch: maximum 100 ms.
- Direct steady-state filesystem overhead: below 5% on the existing workload.
- No unbounded process, handle, thread, projection, event, or recovery growth.

## Release order

The first deliverable is attribution plus a behavior-preserving workspace
abstraction. ProjFS, transactional commit, PTY, and broker prewarming are
separate gated increments. A later phase cannot begin while the previous phase
has failing x64/x86, Agent-scenario, security, or performance evidence.

## Open-source reference boundary

The ProjFS lifecycle and callback shape are informed by Microsoft's MIT-licensed
`Windows-classic-samples/Samples/ProjectedFileSystem` at revision
`d59e5f1dc9c768615e4e1ab1f0f009e6a3ed747c`. Bolt does not import that sample's
registry provider. Its native adapter is a smaller dynamic system-library
boundary so machines without the optional ProjFS component still start and
return a typed unavailable result.
