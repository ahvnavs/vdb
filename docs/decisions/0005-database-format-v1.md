# ADR 0005: Versioned canonical local database format

Status: superseded by ADR 0006 and database format 2

## Decision

Persist a checksummed database header with explicit format version and random database identity. Store document metadata separately from encrypted payloads. Encode namespaces and records with domain-separated, length-delimited canonical binary encodings and fixed-width big-endian integers. Retain deletes as versioned tombstones. Expose exact-version and existence preconditions plus atomic multi-document batches and held MVCC read snapshots.

The prior experimental unversioned layout is rejected rather than implicitly migrated.

## Consequences

Hashes and keys no longer depend on JSON formatting or delimiter assumptions. Corruption can be identified at VDB record boundaries, and replication can later consume tombstones and stable identities. Format changes now require an explicit new version and migration. Format 1 remains pre-stable until migration, compatibility, backup, and broader fault-injection suites exist.
