# Private User Registry

Status: implemented for explicit Agent scenarios on 2026-09-02.

## Purpose

Some Windows tools require writable per-user registry state even when all of
their filesystem state is redirected into the task workspace. Granting writes
to the real `HKEY_CURRENT_USER` would persist host state and may expose existing
credentials or application configuration. The private-user-registry capability
therefore redirects HKCU operations into a workspace-owned application Hive.

## Activation and trust boundary

The capability is opt-in. Declarative Agent scenarios set
`privateRegistry: true`; the trusted harness creates `.registry` beneath the
workspace and supplies `BOLT_SANDBOX_PRIVATE_HKCU` to the target. The native
runtime accepts that value only when the sealed filesystem policy grants write
access to both the textual path and its final resolved parent. A changed value
outside the workspace fails before user code.

The runtime loads or creates the Hive with `RegLoadAppKey`, creates a normal
`HKCU` subkey, and records its native object-manager prefix. Registry hooks
rewrite initial opens and creates beneath the real current-user SID (including
the per-user Classes view) to that prefix. Handles opened below the private
root remain there naturally, and descendants repeat the same setup from the
inherited environment. The real HKCU is never granted write authority.

## Security invariants

- Activation never changes HKLM, HKEY_USERS, or the real user Hive.
- The Hive path must remain under an ordinary read-write filesystem grant.
- Private-Hive native names may read, create, set, delete, and rename only
  inside that Hive; all other registry names retain normal policy precedence.
- Missing, malformed, external, read-only, or unresolved Hive paths fail
  closed before target readiness.
- The capability is data-driven and is never selected by executable name.

Microsoft documents that application Hives are not mounted in HKLM/HKU and
must be accessed through their returned handle; multiple processes can load
the same Hive. See `RegLoadAppKey` and `RegOverridePredefKey` in Microsoft Learn.

