# Compatibility Profile Architecture

Status: accepted for implementation on 2026-09-01.

## 1. Purpose

The compatibility profile supplies the minimum host read access required for
common Agent runtimes without embedding Node-, Python-, Git-, Rust-, or
machine-specific paths in policy code. It is not a request policy, a prompt
input, or an escape hatch for missing write access.

The bundled file name is `bolt-sandbox-compatibility.profile`. It lives in the
same ACL-protected directory as the launcher, hook DLLs, DNS proxy, and
component manifest. Packaging includes it in the component manifest.

## 2. Version 1 Format

The file is UTF-8 without a byte-order mark, uses LF or CRLF, and is at most
64 KiB. Blank lines and lines beginning with `#` are ignored. The first
non-comment line is exactly `BSC1`. Every remaining line has four pipe-separated
fields:

```text
kind|requiredness|base|suffix
```

Supported kinds are `fs-ro` for recursive filesystem read-only, `fs-meta` for
filesystem metadata-only access, `device-ro` for one exact NT device opened
read-only, `reg-ro` for recursive registry read-only,
`reg-exact-ro` for one exact registry key, and `reg-hide` for a trusted probe
that must appear absent. Requiredness is `required`, which fails when the
trusted base is absent, or `optional`, which skips only that entry.

Filesystem bases are `system-root`, `program-dir`, `cwd-parent`, `cwd-anchor`, `program-files`,
`program-files-x86`, `program-data`, `local-app-data`, `user-profile`, and
`absolute`. Registry entries use base `registry` and a
canonical `HKLM` or `HKCU` suffix. Version 1 deliberately has no write, delete,
`inherit-user`, glob, arbitrary environment expansion, executable selector, or
include directive.

Example:

```text
BSC1
fs-ro|required|system-root|.
fs-ro|required|program-dir|.
fs-meta|required|cwd-anchor|.
fs-ro|optional|program-files|Common Files\SSL\openssl.cnf
fs-ro|optional|user-profile|.rustup\toolchains
fs-ro|optional|user-profile|.cargo\registry\src
fs-ro|optional|user-profile|.cargo\registry\cache
device-ro|required|device|\Device\DeviceApi\CMApi
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Cryptography
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\SystemCertificates
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\SystemCertificates
reg-exact-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
reg-hide|required|registry|HKCU\Environment
```

## 3. Resolution Rules

The host resolves bases from its own process environment and the validated
absolute target executable, never from the child environment carried in
`SandboxRequest`.

- A suffix must be relative, contain no empty or `..` component, and contain no
  wildcard, NUL, alternate separator, or NT object-manager prefix.
- The normalized output must remain beneath its trusted base, except suffix `.`
  which means the base itself.
- `program-dir` is skipped when the program is already beneath `cwd`, preserving
  the workspace read-write grant.
- `cwd-parent` permits metadata only and exists for runtimes such as MSYS that
  enumerate one parent while reconstructing the current directory.
- `cwd-anchor` resolves to the first directory beneath the volume/share root and
  permits metadata only. It supports MSYS traversal in a dedicated Agent
  workspace root; resolution fails if that anchor would contain a mandatory
  sensitive path.
- A program directly at a filesystem root cannot create a root-wide allow.
- An `absolute` entry cannot resolve to a volume, UNC share root, device path,
  user-profile root, or known mandatory-sensitive subtree.
- Duplicate normalized rules are rejected rather than silently accepted.
- A `device-ro` entry must use base `device`, start with `\Device\`, and name
  one exact object. Roots, descendants, globs, parent components, alternate
  separators, optional rules, and every write operation remain invalid or
  denied. Device rules are evaluated before ordinary filesystem
  canonicalization because NT device handles do not expose Win32 final paths.
- Registry roots remain invalid except `reg-exact-ro|...|HKU`, which authorizes
  only the users-hive root object and never a SID subtree or hive enumeration.
- An existing exact-read-only registry key may attenuate a create-or-open call
  to a read-only open. Missing keys preserve not-found, and every subsequent
  mutation remains denied; no compatibility operation creates host state.

Missing leaf files remain valid grants so harmless absent probes preserve the
operating system's not-found result.

## 4. Trust and Lifecycle

1. Launch preparation opens the profile with no write/delete sharing.
2. It opens and verifies the component manifest, including an optional pinned
   manifest digest.
3. It verifies the profile length and SHA-256 against its manifest record.
4. It parses and resolves the bounded profile without consulting child input.
5. It merges profile read grants before sealing the immutable native payload.
6. Open component and profile handles remain alive through launch preparation.

Missing, malformed, unmanifested, tampered, unsupported, or over-limit bundled
profiles fail before target creation. Diagnostics identify only the failing
stage and never echo profile content or resolved paths.

## 5. Precedence and Writable State

```text
mandatory deny > explicit request deny > explicit grants > compatibility read
```

Compatibility never creates writable host paths. Agent hosts create a
task-private tree for TEMP, TMP, HOME, package caches, and tool output, then
grant that tree through ordinary request policy. Global npm, Cargo, Git, cloud,
browser, SSH, GPG, and credential locations remain denied unless a trusted host
explicitly grants a narrow non-secret subtree.

Versioned system language-resource package paths are discovered by the trusted
host from Windows MUI/LanguageOverlay metadata and supplied as read-only request
data. The package version, locale, user profile, compiler SDK, and tool install
paths are never embedded in product code.

## 6. Initial Bundled Profile

The first profile migrates existing compatibility grants from Rust constants:

- Windows installation root;
- selected external program directory;
- conventional Node OpenSSL configuration probe;
- Windows cryptographic provider configuration;
- machine, user, enterprise, and policy public certificate stores.

Additional read-only toolchain paths are added only after a real scenario test
demonstrates need and security review confirms the subtree contains no
credentials or unrelated user data.

## 7. Migration and Delivery

1. Add parser and resolver tests while old constants remain active.
2. Add profile verification to component preparation and packaging.
3. Make the bundled profile mandatory and migrate each old allow entry.
4. Remove corresponding constants from `execution.rs` and `compiler.rs`.
5. Run the complete Agent scenario matrix under x64 and x86 targets.
6. Document profile updates as security-impacting package changes.
