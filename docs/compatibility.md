# Compatibility and versioning

VDB currently reports package version 0.1.0 and is not a 1.0-compatible release.
Three independent versions exist:

- Cargo/package version: user-facing CLI and Rust API release.
- Database format version: `5`, stored in the checksummed database header.
- REST protocol version: `1`, carried in routes and the required protocol header.

Encrypted envelopes and replication events also carry their own format
versions. Package-version changes do not implicitly migrate persisted data.

## Current policy

Format 5 is readable and writable only by implementations that explicitly
support format 5. Non-empty unversioned files and formats 1–4 are rejected.
There is no silent downgrade or best-effort decoding. Backups carry their
format version and are verified before restore promotion.

Protocol 1 rejects another protocol version with HTTP 426. Incompatible wire
changes require a new version; additive optional fields still require review
because request signatures cover the exact body.

## Migration mechanism and 1.0 gate

No released legacy format exists, so the repository does not fabricate a
migration from undocumented development layouts. Before format 5 can be called
stable, VDB needs an explicit offline migration command, transactional migration
steps, before/after verification, crash tests, and committed fixtures for every
supported source format. A migration must never overwrite its only input copy.

VDB 1.0 also requires a supported replication transport/client, durable identity
custody beyond raw key files, signed release provenance, and a
published support window. Until those gates pass, release artifacts are for
evaluation and no backward-compatibility window is promised.

