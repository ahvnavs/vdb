# Production roadmap

Stages are ordered by dependency and exit criteria. Later features must not be advertised before their stage exits.

## Stage 0 — audited prototype (current)

Restore compilation; authenticate envelope metadata; validate inputs; use unambiguous history hashes; verify sequence and head metadata; add unit/integration-level kernel tests, CI, dependency audit automation, benchmark harness, threat model, invariants, and ADRs. Exit: format/check/clippy/tests pass and limitations are explicit.

## Stage 1 — stable embedded kernel (in progress)

Implemented foundation: typed errors, internal storage traits, database identity and format header, separate document metadata, tombstones, optimistic concurrency, atomic multi-document transactions, MVCC read snapshots, canonical records, current-state verification, client-side authenticated encryption, a versioned key hierarchy, password-protected key export, consistent verified logical backup/restore, operational snapshots, inspection/status, and offline verified compaction. Remaining: migrations; savepoints where justified; incremental/streaming backup; point-in-time recovery; broader crash/fault injection and compatibility testing; stable API review and benchmark baseline.

## Stage 2 — identity and verifiable history (foundation implemented)

Implemented Ed25519 writer identities, key-version metadata, canonical signed mutations, database-bound IDs, replay indexing, signed hash-linked history, Merkle state roots, inclusion proofs, retained-checkpoint comparison, and adversarial tests. Remaining: old-key-authorized rotation, revocation, external checkpoint publication/signing, portable verifier vectors, and key-custody workflows.

## Stage 3 — query and indexing (metadata foundation implemented)

Implemented typed metadata predicates, bounded collection scans, projection, ordering, cursor pagination, durable secondary/compound indexes, atomic maintenance/rebuild, planner/explain, client-filter signaling, differential/property tests, fuzz targets, and scan/index benchmark harnesses. Remaining: trusted-client JSON evaluation API, planner statistics/costing, index-assisted ordering/ranges, authenticated snapshot-aware cursors, sustained fuzz campaigns, and measured baselines. Searchable tokens remain rejected pending a dedicated leakage ADR.

## Stage 4 — secured network service (foundation implemented)

Implemented a typed native service boundary, versioned REST adapter, TLS-only serving, Ed25519 device/service authentication, scoped authorization, replay/rate controls, request/body/concurrency limits, deadlines, backpressure, structured errors/request IDs, graceful shutdown, health/readiness, JSON tracing, redacted request logs, and authenticated Prometheus metrics with storage/verification/replication health. Remaining: durable audit events, dynamic revocation/config reload, per-document capabilities, mTLS option, certificate automation, distributed tracing export, streaming, and multi-process admission coordination.

## Stage 5 — local-first replication (embedded foundation implemented)

Implemented random replica IDs, signed database-bound causal event IDs, dotted version vectors with sparse receive state, incremental missing-event discovery, idempotent atomic application, equivocation rejection, pending causal dependencies, tombstone propagation, explicit deterministic conflicts/resolution, event-set Merkle checkpoints, peer challenge authentication, canonical checksummed batches, and multi-instance partition/fault/restart tests. Remaining: conflict-aware query/index projection, network streaming transport, durable membership/revocation, replica retirement and vector pruning, safe tombstone GC, resource quotas, replication observability, portable protocol vectors, and broader randomized/fuzz simulation. No CRDT is implemented.

## Stage 6 — distributed operations and release readiness

Implemented operational snapshot/backup/restore, offline compaction, storage/cryptographic statistics, replication health, structured logging, metrics foundations, hostile-input fuzz targets, dependency/secret-scan CI, and a security reporting policy. Remaining: safe garbage collection, streaming/incremental backups, long-running fault injection/fuzzing, broader configurable resource quotas, alert/SLO definitions, reproducible multi-platform releases, checksums, SBOM, signing/provenance, changelog, and support/versioning policy. Exit: published SLO assumptions, release runbook, compatibility matrix, and independent security review.

## Immediate next milestone

Implement an atomic migration framework, then add compatibility fixtures and streaming/incremental backup before declaring any database format stable.
