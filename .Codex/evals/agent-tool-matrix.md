# Agent Tool Matrix Eval

## Capability evals

- The checked-in scenario file covers shell, scripting, JavaScript package,
  Python package, source control, Rust, native, Go, JVM, .NET, build, test,
  search/text, archive/copy, network, database, browser, container, and signing
  tool families.
- Scenario execution is declarative: executable candidates, arguments,
  environment, read-only/metadata roots, fixture files, terminal mode, timeout,
  accepted exit codes, stdout checks, and expected workspace artifacts are data.
- No executable or host installation path is embedded in Rust/C++ product code.
- Every required tool available on the executing host completes once inside a
  non-ASCII workspace with spaces and writes only beneath that workspace.
- Missing optional tools are listed as `UNVERIFIED`; they are never reported as
  passing. Missing required-on-host tools fail the run.
- Network remains denied except in scenarios that declare a local-only or
  explicit allow-list fixture.

## Regression evals

- Existing Agent scenario suite remains 12/12.
- Rust fmt, strict Clippy, all Rust tests, traceability, and x64/x86 native unit
  suites remain green.
- Exact-read-only registry attenuation never creates or modifies host state.
- Pipe targets cannot access the host console; pseudo-console targets receive
  only their isolated console capability.

## Success metrics

- Required available scenarios: pass@1 = 100%.
- Release-critical regressions: pass^3 = 100%.
- Unexpected files outside the generated workspace: zero.
- User prompts/retries during one matrix run: zero.

