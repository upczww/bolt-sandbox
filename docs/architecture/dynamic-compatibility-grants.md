# Dynamic Compatibility Grant Proposals

## Purpose

General Agent workloads encounter tools that are not present in the bundled
compatibility profile. Bolt Sandbox may help a trusted host ask for a narrow
grant, but a target process must never modify its own policy or turn a denied
operation into an in-place allow.

## Evidence and proposal flow

1. The running command emits bounded typed violations containing execution,
   process, operation, and canonical resource identity.
2. The trusted host aggregates duplicate violations and removes resources
   covered by mandatory denies or ineligible capability classes.
3. A host-side proposal engine may suggest the smallest representable grant:
   exact metadata, exact/recursive read-only, task-private read-write, exact
   registry read-only, or an explicit network rule.
4. The UI presents resource, authority, executable identity, scope, duration,
   and risk. It never displays command-line or environment secrets.
5. Approval creates a new immutable policy generation and restarts the command
   from the beginning. The original process and descendants are terminated;
   no live process receives additional authority.

## Approval scopes

- **Once**: one restart of one command in one workspace.
- **Workspace**: commands matching the approved executable identity in one
  canonical workspace root.
- **Tool version**: a verified executable hash/signature plus a bounded resource
  rule. A changed executable requires new approval.
- **Administrator-managed profile**: packaged, reviewed, manifest-bound policy
  data. Targets and prompts cannot select or edit it.

Persistent entries store generic roots and placeholders where possible. They
must not store a discovered user SID, package version, drive letter, or tool
installation path when the trusted host can resolve an equivalent token.

## Ineligible ordinary grants

The following never become a normal “add path to whitelist” prompt:

- mandatory credential, SSH, GPG, cloud, browser-profile, and recovery roots;
- arbitrary device objects, host console, process handles, services, or token
  operations;
- arbitrary named-pipe or mailslot namespaces;
- executable, DLL, script, or registry writes outside task-private storage;
- broad user-profile, Program Files, registry-hive, drive, or UNC-share roots;
- network wildcards that erase domain/address/port restrictions.

These require a separately implemented typed capability with its own isolation
and tests. If unavailable, the host reports `capability-unavailable` rather
than offering an unsafe approval.

## Prompt minimization

- Manifest-bound read-only compatibility data handles known stable probes.
- Tool caches, HOME, TEMP, XDG, package stores, and build outputs are redirected
  to task-private directories before launch.
- Identical proposal keys are shown once per policy generation; rejected grants
  remain rejected without repeated prompts during that command.
- Multiple safe read probes from one verified tool may be grouped, but approval
  remains itemized and atomic.
- Missing resources preserve not-found and do not prompt unless the operation
  would create host state.

## WorkBuddy comparison

The inspected WorkBuddy installation bundles Tencent `tsbx` 5.3.3 plus its own
Node, Python, and PortableGit distributions. Its checked-in rules use
`default_action: deny_write`, `auto_grant: true`, default-allow networking, no
registry/process rules, browser process exemptions, and broad `inherit_user`
cache/config paths. Those choices explain much of its compatibility but expose
more host state than Bolt's threat model permits.

Bolt adopts the useful parts—data-driven rules, controlled runtimes, automatic
discovery, and consolidated prompts—without adopting default network access,
broad host-writable caches, or process bypasses.

## Required tests

- A target cannot forge, replay, approve, persist, or widen a proposal.
- Mandatory deny and ineligible capability classes never produce approvable
  suggestions.
- Approval restarts under a new policy generation; the original Job is gone.
- Exact read proposals cannot become write/recursive grants through aliases.
- Executable replacement, workspace change, policy change, or expiry invalidates
  persisted approval.
- Diagnostics and approval records pass secret-canary scans.
- Denial aggregation and rejection suppress repeat prompts without suppressing
  final audit evidence.

## Public host API

The Rust boundary implements the flow as separate consumable objects:

- `CompatibilityGrantResolver::resolve` returns `NoPrompt`, one aggregated
  `NeedsAuthorization`, or `CapabilityUnavailable`.
- `CompatibilityDecisionCache` records bounded once/workspace approvals and
  rejections; it stores bindings and decisions, never command/environment data.
- `CompatibilityGrantResolver::apply_approved` revalidates proposal identity,
  tool hash, workspace, mandatory denies, and compiler limits before cloning a
  minimally extended policy.
- `CompatibilityGrantResolver::prepare_restart` accepts only a completed failed
  result and consumes an existing approval.
- `CompatibilityRestartPlan::start` consumes the plan, discards the retained
  prior transaction first, and starts one new execution. A discard or start
  error is returned without direct or unsandboxed fallback.

The new `ExecutionId` and monotonic policy generation come from the normal
`Sandbox::start_with_options` path; no alternate launcher semantics exist.
