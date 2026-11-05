# Installation

VDB has not reached a supported 1.0 release. Build artifacts produced from tags
are evaluation artifacts until the blockers in `docs/compatibility.md` close.

## Release archive

Download the archive for the operating system and architecture, plus
`SHA256SUMS`. Verify the archive before extracting:

```text
sha256sum --check SHA256SUMS
```

Place `vdb` (or `vdb.exe`) on `PATH`, then run `vdb --version`. Release CI
targets Linux x86_64 and ARM64, macOS x86_64 and ARM64, and Windows x86_64.
Availability depends on successful CI for that tag.

## Build from source

Install stable Rust and a platform C toolchain, then run:

```text
git clone <repository-url>
cd vdb
cargo build --locked --release
./target/release/vdb --version
```

The binary is self-contained apart from normal operating-system libraries.
Docker is not required. Rebuilds use the committed `Cargo.lock`; exact
bit-for-bit reproducibility is not currently guaranteed because toolchain and
runner images are not fully hermetic.

Release archives include the binary, README, changelog, security policy,
licenses, and a CycloneDX SBOM. Checksums provide download integrity, not signer
identity or provenance. Signed provenance remains a release blocker.

