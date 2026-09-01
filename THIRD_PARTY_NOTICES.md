# Third-Party Notices

## Microsoft Detours 4.0.1-compatible main revision

Bolt Sandbox vendors the minimum Microsoft Detours static-library source set
needed for x86/x64 process injection and API interception. Detours is licensed
under the MIT License.

- Source: https://github.com/microsoft/Detours
- Branch snapshot: `main`
- Revision: `adb07604aa56508448b95bf037c2a6d0d3b6831a`
- License: MIT
- Import manifest: `native/third_party/detours/provenance.json`
- Modification boundary: imported files are unmodified; project integration
  lives outside the vendored directory.

The vendored `LICENSE.md` retains the upstream license text. Samples, tools,
and non-library files are not imported.

## Microsoft BuildXL

Bolt Sandbox vendors an audited DetoursServices filesystem runtime adaptation
baseline for Windows policy enforcement and filesystem interception. BuildXL
is licensed under the MIT License.

- Source: https://github.com/microsoft/BuildXL
- Revision: `24a3f64655741d9ab8619d35d12513e6a7baabc1`
- License: MIT
- Upstream component: `Public/Src/Sandbox/Windows/DetoursServices`
- Import manifest: `native/third_party/buildxl/provenance.json`
- Modification boundary: vendored files remain byte-for-byte identical to
  upstream; Bolt compatibility headers, adapters, protocol translation, and
  tests live outside the vendored directory.

The manifest records the 55-file coherent upstream Windows runtime source
closure and every file hash.
Only assertions, string/path operations, path-tree, resolved-path cache,
canonical-path, and checked-path components are currently active; the rest
remains an immutable adaptation baseline. BuildXL-specific
policy and reporting files retain upstream dependency context but are excluded
from Bolt build targets and packaging. Bolt does not accept the BuildXL
manifest wire protocol. The scheduler, C# engine, build graph, separate
Detours fork, and unrelated Windows sandbox components are not imported.

The pinned revision is the last commit that modified DetoursServices before
the 2026-08-30 audit. The later audited main snapshot did not change any of the
imported source files. BuildXL's repository-wide third-party notices are not
redistributed because this slice does not import the unrelated components they
describe.

## phnt

Bolt Sandbox adapts the minimum native ABI declarations required to intercept
`RtlCreateUserProcess` and `NtCreateUserProcess` from the phnt headers
maintained by Winsider Seminars & Solutions. phnt is licensed under the MIT
License.

- Source: https://github.com/winsiderss/phnt
- Revision: `53fbbdc5b5d2b08761db1c7b26bfa8c820924356`
- License: MIT
- Upstream declarations: `ntrtl.h`, `ntmmapi.h`, and `ntpsapi.h`
- Provenance manifest: `native/third_party/phnt/provenance.json`
- Modification boundary: only the required function signature and output
  structure layouts are adapted into
  `native/hook/process/native_process_abi.h`; the complete phnt header graph is
  neither imported nor compiled.

The vendored `native/third_party/phnt/LICENSE` is byte-for-byte identical to
the upstream license at the pinned revision.

## getrandom 0.4.3

Bolt Sandbox depends on the `getrandom` Rust crate to obtain execution pipe
identifiers and handshake nonces from the operating system's cryptographically
secure random source. The crate is licensed under either the MIT License or the
Apache License, Version 2.0.

- Source: https://github.com/rust-random/getrandom/tree/v0.4.3
- Package: https://crates.io/crates/getrandom/0.4.3
- License: MIT OR Apache-2.0

The dependency revision is pinned in `Cargo.toml` and resolved checksums are
recorded in `Cargo.lock`.

## winapi-util 0.1.11

Bolt Sandbox uses the safe `winapi-util` file-information wrapper to reject
multi-link Windows files before copying or projecting workspace content. The
crate is licensed under the Unlicense or MIT License.

- Source: https://github.com/BurntSushi/winapi-util/tree/0.1.11
- Package: https://crates.io/crates/winapi-util/0.1.11
- License: Unlicense OR MIT

The dependency revision is pinned in `Cargo.toml`; it and its Windows bindings
are checksum-locked in `Cargo.lock`.

## idna 1.1.0

Bolt Sandbox depends on the `idna` Rust crate for UTS #46 and Punycode domain
normalization. The crate is maintained by the rust-url developers and is
licensed under either the MIT License or the Apache License, Version 2.0.

- Source: https://github.com/servo/rust-url/tree/idna-v1.x/idna
- Package: https://crates.io/crates/idna/1.1.0
- License: MIT OR Apache-2.0

The dependency revision is pinned in `Cargo.toml` and resolved checksums are
recorded in `Cargo.lock`.

## sha2 0.11.0

Bolt Sandbox depends on the RustCrypto `sha2` crate to integrity-protect the
immutable compiled policy payload shared with native runtime components. The
crate is licensed under either the MIT License or the Apache License, Version
2.0.

- Source: https://github.com/RustCrypto/hashes/tree/sha2-v0.11.0/sha2
- Package: https://crates.io/crates/sha2/0.11.0
- License: MIT OR Apache-2.0

The dependency revision is pinned in `Cargo.toml` and resolved checksums are
recorded in `Cargo.lock`.
