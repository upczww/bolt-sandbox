# Repository Guidelines

## Project Structure & Module Organization

This repository is under test-driven implementation. `README.md` gives the overview; `docs/architecture/windows-sandbox.md` is the authoritative design, security model, delivery plan, and test strategy.

The Rust crate lives under `src/`. The planned Windows-native components belong in `native/launcher/` and `native/hook/`. Integration tests belong in `tests/`, fixtures in `tests/fixtures/`, and Windows build helpers in `scripts/`. Keep architectural decisions under `docs/architecture/`. Do not commit generated binaries or build directories.

## Build, Test, and Development Commands

The Rust build manifest and initial tests are available. Keep these workflows working and document prerequisites in `README.md`:

- `cargo fmt --all -- --check` checks Rust formatting.
- `cargo clippy --all-targets --all-features -- -D warnings` rejects Rust lint warnings.
- `cargo test --all-targets` runs Rust unit and integration tests.
- `pwsh scripts/verify-test-traceability.ps1` validates requirement and case mappings.
- `pwsh scripts/build-windows.ps1` is planned to build the launcher and x86/x64 hook DLLs once native components are introduced.

## Coding Style & Naming Conventions

Use four-space indentation; let `rustfmt` decide Rust layout. Use `snake_case` for Rust modules, functions, and test files, and `UpperCamelCase` for types. Native code should follow its checked-in formatter configuration. Keep public policy and lifecycle APIs in Rust; do not expose Detours- or BuildXL-specific types publicly. Favor modules aligned with policy, process, IPC, and events.

## Testing Guidelines

Add unit tests beside Rust modules and integration suites under `tests/`, named by behavior such as `filesystem.rs`. Cover success paths and fail-closed behavior. Filesystem changes must test normalized paths, links, reparse points, and handle operations; process changes must test descendants and mixed architectures; network changes must cover DNS and IPv4/IPv6.

## Commit & Pull Request Guidelines

Use short, imperative commit subjects (for example, `Add policy payload validation`) and keep commits focused. Pull requests should explain the security impact, tests run, supported Windows/architecture combinations, and any performance change. Link relevant issues or architecture sections; include logs for behavioral changes and update `THIRD_PARTY_NOTICES.md` when importing upstream code.

## Security & Third-Party Code

Preserve fail-closed behavior and never place secrets in command lines, environments, policies, events, or diagnostics. Pin imported Detours or BuildXL revisions and retain their license notices. GPL reference implementations may inform tests and semantics but must not be copied into this project.
