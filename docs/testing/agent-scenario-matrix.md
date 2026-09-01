# Agent Scenario Test Matrix

This matrix defines real workflows Bolt Sandbox must support before a
compatibility-profile release is complete. Stable mandatory cases use local
fixtures; public internet cases are supplemental and cannot replace local
evidence.

## Profile and Trust

- Valid LF and CRLF profiles produce identical rules.
- Missing magic, unknown version, BOM, malformed fields, unknown kinds, unknown
  bases, and unknown requiredness fail closed.
- Empty, duplicate, oversized, non-UTF-8, NUL-containing, and over-count profiles
  fail with bounded diagnostics.
- Relative escape, `..`, roots, device paths, globs, and alternate data streams
  fail closed.
- Optional missing bases skip only their rules; required missing bases fail.
- Missing leaf probes remain valid read-only rules.
- Profile length, digest, manifest record, pinned manifest, and no-replacement
  lease failures stop before target creation.
- Explicit and mandatory denies override every profile grant.
- No profile syntax can express write, delete, recovery, network, process, or
  environment authority.

## Filesystem Workflows

- Create, read, edit, rename, replace, truncate, and delete inside `cwd`.
- Read external SDK/runtime files while write, rename, delete, and writable
  mapping remain denied.
- Load runtime modules and DLLs from the selected program directory.
- Keep programs beneath `cwd` writable; reject root-wide program grants.
- Preserve not-found for absent permitted probes and access-denied elsewhere.
- Preserve mandatory denies for SSH, GPG, cloud, container, browser, Git, npm,
  Cargo credential, and recovery-store paths.
- Cover hard links, symbolic links, junctions, reparse points, case aliases,
  short names, UNC, final-handle identity, and mutation races.

## Runtime and Shell Workflows

- `cmd.exe`, Windows PowerShell, and PowerShell 7 run non-interactive scripts.
- Node loads built-ins and local modules, uses streams, performs file I/O,
  spawns a child, and completes HTTP/TLS.
- Python loads encodings and standard library modules, imports local code, uses
  streams, performs file I/O, spawns a child, and completes HTTP/TLS.
- Git performs init/status/diff/add in a task repository without global
  credentials.
- Cargo performs metadata/check/test with toolchains read-only and output/cache
  redirected to task-private storage.
- npm/pnpm runs an offline local-package script without global tokens.
- Available .NET and Java fixtures run when their runtimes are declared required.
- One workspace containing spaces and non-ASCII characters runs cmd, PowerShell,
  Python, Node, Git, Cargo/Rust, and an available GCC-compatible or MSVC native
  compiler without retries or per-command policy prompts. Every generated file,
  private home, temporary directory, cache, and build output remains beneath the
  workspace. Compiler SDK roots are host-discovered or explicitly supplied and
  granted read-only; they are never embedded in product code.
- Windows language resource package roots are resolved through `GetFileMUIPath`
  from a System32 language-neutral DLL and granted read-only. Versioned package,
  locale, user, and installation paths are not embedded in product or test code.

## Network Workflows

- Node, Python, curl, Git, and package clients cover Unrestricted, Denied,
  allowed and denied domain/CIDR/port, IPv4, and IPv6.
- DNS bindings remain scoped to execution, process, domain, address, port, and
  TTL; service-agnostic DNS still requires an independently allowed TCP port.
- Nonblocking sockets, WinHTTP, WinInet, Winsock, descendants, redirects, HTTP
  CONNECT, and host proxy variables cannot bypass policy.
- UDP, QUIC, raw sockets, malformed proxy frames, helper death, timeout, replay,
  and authentication failure remain fail closed.

## Process, Registry, and Lifecycle

- Descendants inherit policy across x64/x86 boundaries; denied children never
  execute user code.
- TLS reads public cryptographic and certificate configuration but cannot mutate
  it or access private keys and credentials.
- Registry read-only, exact-read, hidden, deny, WOW64 views, links, rename,
  delete, and transaction paths preserve precedence.
- Cancellation, timeout, owner or launcher death, event loss, stream
  backpressure, and initialization failure terminate the complete Job.

## Performance and Release Gates

- Profile parsing and expansion are bounded and occur before target creation.
- Warm startup stays below 100 ms; hook initialization stays below 50 ms.
- The package contains the profile and matching manifest record.
- x64/x86 native suites, Rust tests, strict Clippy, formatting, traceability,
  package ACL, signing pipeline, and scenario harness all pass.

The scenario harness prints one concise result per case, applies a per-case
deadline, and never retries outside the sandbox. Optional runtimes use explicit
host-provided executable paths; a runtime declared required but unavailable is
a failure, not a silent skip.

Run the executable suite with:

```powershell
pwsh scripts/test-agent-scenarios.ps1 `
  -ComponentRoot target\native\x64\Release `
  -PythonPath C:\trusted-runtimes\python\python.exe
```

The harness discovers Node, Git, and Cargo when possible, resolves Git for
Windows and rustup shims to their real runtime executables, validates every
declared path, and enables all runtime-gated CLI integration cases.

Current executable coverage includes Cargo offline metadata and `cargo check
--offline` with a task-private home and target directory. Modern Rust's private
anonymous stdout/stderr pipes are exercised without granting access to named
pipe or mailslot namespaces, and every `rustc` descendant remains in the outer
execution Job with the inherited sandbox runtime. `cargo test` remains a
release-matrix expansion because it adds execution of the compiled fixture, not
because compiler startup requires a broader host grant.
