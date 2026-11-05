# Contributing

VDB is security-sensitive database software. Discuss format, protocol,
cryptographic, and replication-semantic changes before implementation. Never
include production databases, keys, plaintext, or credentials in issues or
tests; use the private process in `SECURITY.md` for vulnerabilities.

Install the stable Rust toolchain with rustfmt and Clippy, then run:

```text
cargo fmt --all -- --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo check --manifest-path fuzz/Cargo.toml --bins
cargo audit
```

Changes to persisted or exchanged bytes require a version decision, canonical
test vectors, malformed-input tests, compatibility documentation, and migration
analysis. Changes to public behavior require tests and changelog entries.
Benchmark changes must follow `docs/benchmarks.md` and may not publish invented
or incomparable results.

Contributions are accepted under Apache-2.0 OR MIT, matching `Cargo.toml`.

