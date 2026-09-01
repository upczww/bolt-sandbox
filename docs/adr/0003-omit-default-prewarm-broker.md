# ADR-0003: Omit a default prewarm broker

- Status: accepted
- Date: 2026-09-01

## Context

An Agent runtime benefits from low command startup latency, but a resident
broker would add a long-lived privileged process, authenticated control IPC,
cross-command state, crash fan-out, stale component/profile handling, and new
resource-growth failure modes. The evolution plan therefore requires measured
improvement of at least 10 ms before such a broker ships.

Final release evidence on the representative workstation records seven warm
Direct starts between 38.968 ms and 42.780 ms (40.138 ms mean), while the
existing 100 ms release gate passes. No broker prototype has demonstrated a
repeatable 10 ms improvement after charging its IPC, identity, validation, and
cleanup costs.

## Decision

Do not include or enable a prewarmed broker. Reusable in-process `Sandbox`
configuration may retain non-authoritative Rust state, but every command still
creates fresh execution identity, policy generation, Job, launcher, IPC,
recovery namespace, and optional workspace/PTY capabilities.

The broker gate is fail closed: absence of evidence meeting the 10 ms threshold
means no broker, rather than permission to assume a benefit. Reconsider only
with a bounded prototype and Direct-vs-broker evidence covering startup,
concurrency, crash cleanup, stale state, handles, threads, and private bytes.

## Consequences

- Default warm startup remains approximately 40 ms without a resident service.
- There is no broker control endpoint or cross-command authority to attack.
- A future broker must be introduced by a new ADR and pass BRK-001..010 and
  PERF-015; this decision does not weaken those requirements.
