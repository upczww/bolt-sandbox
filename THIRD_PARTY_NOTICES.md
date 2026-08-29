# Third-Party Notices

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
