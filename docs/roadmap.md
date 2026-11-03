# Production roadmap

Stages are ordered by dependency and exit criteria. Later features must not be advertised before their stage exits.

## Stage 0 — audited prototype (current)

Restore compilation; authenticate envelope metadata; validate inputs; use unambiguous history hashes; verify sequence and head metadata; add unit/integration-level kernel tests, CI, dependency audit automation, benchmark harness, threat model, invariants, and ADRs. Exit: format/check/clippy/tests pass and limitations are explicit.

## Stage 1 — stable embedded kernel (in progress)

Implemented foundation: typed errors, internal storage traits, database identity and format header, separate document metadata, tombstones, optimistic concurrency, atomic multi-document transactions, MVCC read snapshots, canonical records, current-state verification, client-side authenticated encryption, a versioned key hierarchy, password-protected key export, and initial property/corruption/process-abort/concurrency tests. Remaining: offline backup/restore; migrations; savepoints where justified; broader crash/fault injection and compatibility testing; stable API review and benchmark baseline.

## Stage 2 — identity and verifiable history (foundation implemented)

Implemented Ed25519 writer identities, key-version metadata, canonical signed mutations, database-bound IDs, replay indexing, signed hash-linked history, Merkle state roots, inclusion proofs, retained-checkpoint comparison, and adversarial tests. Remaining: old-key-authorized rotation, revocation, external checkpoint publication/signing, portable verifier vectors, and key-custody workflows.

## Stage 3 — query and indexing

Implement scans, predicates, projection, ordering, pagination, secondary/compound indexes, planner and explain. Keep encrypted search client-side initially; introduce searchable tokens only after a leakage ADR and threat-model update. Exit: transactional index invariants, planner correctness/property tests, and measured benchmarks.

## Stage 4 — secured network service

Version the native protocol; add TLS, authentication, capability authorization, request/connection limits, timeouts, rate limiting, backpressure, structured errors, graceful shutdown, health/readiness, tracing and metrics with redaction. REST remains an adapter. Exit: malicious-input testing, authorization matrix, TLS-by-default deployment, and operational documentation.

## Stage 5 — local-first replication

Define replica/mutation IDs, version vectors or dotted version vectors, causal ordering, idempotent exchange, duplicate suppression, tombstone retention, conflict representation, and deterministic resolution. Prefer explicit document conflicts before field-level CRDTs; add CRDTs only for demonstrated data types. Exit: partition/rejoin, divergent history, duplicate/reordering, and multi-device simulation suites.

## Stage 6 — distributed operations and release readiness

Add snapshots/compaction coordination, safe garbage collection, replication observability, portable backup/restore, fuzzing, long-running fault injection, resource quotas, reproducible multi-platform releases, checksums, SBOM, signing/provenance, changelog, security policy, and support/versioning policy. Exit: published SLO assumptions, release runbook, compatibility matrix, and independent security review.

## Immediate next milestone

Complete Stage 1 with offline backup/restore and an atomic migration framework, then run a stable API/format review and build the compatibility matrix before declaring any database format stable.
