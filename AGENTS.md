# Repository Guidelines

## Project Structure & Module Organization

This repository is in the planning phase. `README.md` gives the overview; `docs/architecture/windows-sandbox.md` is the authoritative design, security model, delivery plan, and test strategy.

The planned implementation separates Rust (`src/`) from Windows-native components (`native/launcher/` and `native/hook/`). Integration tests belong in `tests/`, fixtures in `tests/fixtures/`, and Windows build helpers in `scripts/`. Keep architectural decisions under `docs/architecture/`. Do not commit generated binaries or build directories.

## Build, Test, and Development Commands

No build manifest or executable code exists yet, so there are currently no project build or test commands. When the planned structure is introduced, keep these expected workflows working and document any prerequisites in `README.md`:

- `cargo fmt --all -- --check` checks Rust formatting.
- `cargo clippy --all-targets --all-features -- -D warnings` rejects Rust lint warnings.
- `cargo test --all-targets` runs Rust unit and integration tests.
- `pwsh scripts/build-windows.ps1` should build the launcher and x86/x64 hook DLLs on Windows.

## Coding Style & Naming Conventions

Use four-space indentation; let `rustfmt` decide Rust layout. Use `snake_case` for Rust modules, functions, and test files, and `UpperCamelCase` for types. Native code should follow its checked-in formatter configuration. Keep public policy and lifecycle APIs in Rust; do not expose Detours- or BuildXL-specific types publicly. Favor modules aligned with policy, process, IPC, and events.

## Testing Guidelines

Add unit tests beside Rust modules and integration suites under `tests/`, named by behavior such as `filesystem.rs`. Cover success paths and fail-closed behavior. Filesystem changes must test normalized paths, links, reparse points, and handle operations; process changes must test descendants and mixed architectures; network changes must cover DNS and IPv4/IPv6.

## Commit & Pull Request Guidelines

Git history is unavailable in this checkout. Use short, imperative commit subjects (for example, `Add policy payload validation`) and keep commits focused. Pull requests should explain the security impact, tests run, supported Windows/architecture combinations, and any performance change. Link relevant issues or architecture sections; include logs for behavioral changes and update `THIRD_PARTY_NOTICES.md` when importing upstream code.

## Security & Third-Party Code

Preserve fail-closed behavior and never place secrets in command lines, environments, policies, events, or diagnostics. Pin imported Detours or BuildXL revisions and retain their license notices. GPL reference implementations may inform tests and semantics but must not be copied into this project.
