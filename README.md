# Bolt Sandbox

Bolt Sandbox is the Windows sandbox component for Bolt Agent. Its initial goal
is to provide Trae-style, low-latency process confinement without recursively
modifying ACLs, installing a kernel driver, or starting a virtual machine.

The implementation plan is documented in
[docs/architecture/windows-sandbox.md](docs/architecture/windows-sandbox.md).
It combines BuildXL's filesystem coverage, Trae's component boundaries, and
WorkBuddy's registry, network-stack, audit, and recovery behavior without
copying closed-source product code.

## Status

Architecture and implementation planning.

## Intended Deliverables

Bolt Agent should integrate through the Rust `bolt-sandbox` library when it
needs typed requests, events, and lifecycle control. A `bolt-sandbox.exe` CLI
will provide the same behavior for standalone testing and non-Rust callers.

The runtime is distributed as a component set rather than a single binary:

- `bolt-sandbox.exe`, the optional Agent-facing CLI.
- `bolt-sandbox-launcher.exe`, the private suspended-process launcher.
- `bolt-sandbox-x64.dll` and `bolt-sandbox-x86.dll`, the injected hook DLLs.

The selected Agent-facing interface and the three private runtime artifacts
must be versioned, integrity-checked, and shipped as one compatible release.
The private artifacts may later be embedded in the CLI for packaging
convenience, but remain separate runtime components after secure extraction.
