# ADR-0004: Use failure-correlated risk-tiered compatibility grants

- Status: accepted
- Date: 2026-09-02

## Context

General Agent workloads invoke heterogeneous tools whose harmless runtime
probes vary by version and host. Prompting for every denied probe makes the
sandbox unusable, while silently granting discovered paths reproduces
WorkBuddy's broad `auto_grant` and `inherit_user` exposure. Bolt must preserve
mandatory denies, immutable per-execution policy, fast startup, and a low-noise
Agent experience.

## Decision

Use a trusted-host compatibility resolver that is risk-tiered and correlated
with command failure. Known safe compatibility remains manifest-bound and
automatic; successful commands never prompt merely because they emitted
violations. A failed command may produce one bounded, deduplicated proposal for
the smallest representable grant, but the target cannot approve or mutate it.

Approval is scoped to one execution restart, one workspace, one verified tool
version, or an administrator-managed profile. It terminates the original Job,
discards an initial transactional workspace when applicable, creates a new
immutable policy generation, and restarts from the beginning. Live authority
is never widened.

Ordinary proposals cannot include mandatory-sensitive roots, broad filesystem
or registry roots, arbitrary named pipes, mailslots, devices, host console,
process/token authority, executable writes outside task-private storage, or
unbounded network access. Those return a typed unavailable capability until a
separately isolated capability is implemented and tested.

The host returns deterministic structured observations with `status`,
`summary`, `next_actions`, proposal identity, verified tool identity, requested
scope, minimal grants, ineligible capabilities, and audit artifacts. Identical
proposals and user rejections are suppressed within their scope so one command
causes at most one authorization interaction.

## Alternatives Considered

### Prompt for every violation

- **Pros**: No silent authority expansion.
- **Cons**: Harmless probes generate many prompts and train users to approve
  without review.
- **Why not**: Prompt volume makes normal Agent workflows impractical.

### Automatically grant every discovered resource

- **Pros**: Maximum compatibility and almost no prompts.
- **Cons**: A target can probe its way into host caches, credentials, devices,
  and writable state; policy becomes target-directed.
- **Why not**: This violates Bolt's immutable-policy and least-authority model.

### Maintain only a large static global whitelist

- **Pros**: Deterministic and simple at runtime.
- **Cons**: Cannot cover versioned SDKs and tools without broad machine paths,
  and requires releases for routine compatibility changes.
- **Why not**: It does not scale to a general sandbox.

## Consequences

- Successful commands remain silent even when optional probes are denied.
- First use of a genuinely blocked unknown tool may require one restart and one
  user decision.
- Persistent approvals are invalidated by executable, signer, workspace,
  policy, or expiry changes.
- Hosts need proposal storage, UI, audit, restart orchestration, and negative
  caching; these remain outside the hook decision path.
- Unsupported kernel-object capabilities stay visibly `UNVERIFIED` rather than
  being approximated with unsafe path grants.

