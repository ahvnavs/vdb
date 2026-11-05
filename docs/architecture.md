# Current architecture

Status: implemented state as of 2026-11-05. The local storage, metadata-query, secured-network, and embedded replication foundations are functional and tested, but VDB is not yet production-ready as a distributed database.

## Layering

`Store` is the public embedded-database facade. It exposes durable metadata, point/collection reads, held read snapshots, conditional puts, tombstone deletes, atomic write batches, query/index management, planning/explain, and history verification. It depends on the internal `StorageEngine` and `StorageSnapshot` traits. No redb type appears in the public API.

`RedbEngine` is the only storage-engine implementation. It translates VDB namespaces, records, transactions, snapshots, and errors to redb. redb supplies serializable single-writer transactions, concurrent MVCC readers, crash recovery, and durable pages; VDB owns all database semantics and record formats.

`crypto.rs` is the trusted-client boundary. It derives collection and document keys from a versioned database key with HKDF-SHA256, then uses XChaCha20-Poly1305. Associated data binds the envelope version, algorithm, database ID, key ID/version, collection, document ID, and logical version. Storage and server code accept, persist, hash, and reproduce opaque envelopes without document keys.

`DatabaseService` is the transport-independent native protocol boundary. The REST adapter maps versioned resources onto typed requests without exposing storage-engine concepts. `network.rs` supplies TLS-only serving, signed request authentication, scoped authorization, replay/rate controls, bounded middleware, and graceful shutdown. The server continues to operate without content keys.

`Replica` is the local-first synchronization facade. It creates and verifies immutable signed causal events, exchanges sparse synchronization state, discovers missing dots, applies duplicates idempotently, exposes deterministic document conflicts, and creates explicit resolution events. Replication records use the storage abstraction; peers never receive redb tables or transactions.

`operations.rs` owns metadata-only inspection/status reports, storage and cryptographic statistics, replication health, logical backup format 1, verified atomic restore, and offline verification-gated compaction. Backups export all logical tables from one MVCC read transaction and do not expose redb pages as the VDB backup contract. The current buffered reader has a 512 MiB archive ceiling, and promotion uses same-directory no-clobber links so an entry created during verification is not overwritten.

## Network service

Protocol version 1 uses `/v1` plus an explicit version header. Configured Ed25519 device/service principals sign canonical requests. Permissions separate read, write, query, verification, and index administration. Health and readiness are public; protected routes fail closed. Request IDs are authenticated and returned in structured errors and response headers.

## Durable format version 5

Every new database receives a checksummed header containing:

- database format version `5`;
- a random 128-bit database identity encoded as lowercase hexadecimal;
- creation time in Unix milliseconds.

Missing headers in non-empty databases are rejected as unversioned/unsupported. Unsupported versions are not guessed or migrated. The earlier experimental three-table layout is intentionally rejected.

The backend uses private tables for database metadata, document metadata, encrypted payloads, signed mutations, writer public keys, unique mutation IDs, index definitions, derived index entries, signed replication events, and causal-dot duplicate indexes. Collection/document, index, and replication namespaces use domain-separated, length-delimited binary keys. Metadata and payloads are separate rows.

Persisted VDB records use explicit canonical binary encodings: domain tag, fixed-width big-endian integers, length-prefixed byte strings, and strict trailing-byte rejection. Checksummed records use BLAKE3 over the canonical body. Mutation hashes cover canonical mutation material rather than JSON or delimiter-concatenated strings.

Format 5 is explicit but remains pre-stable. Formats 1 through 4 are rejected, and no migration is implemented. Format 5 adds signed causal replication records and dot indexes; encrypted-envelope format 2 is unchanged.

## Replication and conflicts

Every replica uses its Ed25519 writer/device ID as a globally random 128-bit replica ID. A replication event has a `(replica ID, counter)` dot and a sorted version-vector context. The event ID and signature bind the shared database ID, dot, context, replica key metadata, operation, document identity/version, and optional encrypted payload. Missing dependencies are retained but not exposed as document state until causal closure arrives.

Synchronization exchanges a contiguous counter plus sparse received counters per replica. Missing-event discovery therefore remains correct under loss and reordering. Event/dot insertion is atomic; exact duplicates are no-ops and different events claiming one dot are rejected as equivocation. Checkpoints are deterministic Merkle roots over the sorted event-ID set.

Concurrent document heads are returned in event-ID order as an explicit conflict. Put-versus-put and delete-versus-put are not resolved automatically. Resolution emits a new causal event selecting one current head; an unseen concurrent event can make the conflict reappear. No CRDT is implemented. See `replication.md` for the interoperable byte format and algorithm.

Replicated state is currently read through `Replica::document`; it is not projected into the single-head `Store` query/index state. Mixing direct `Store` writes with `Replica` writes for one logical collection is unsupported. This separation prevents conflicts from being hidden behind a stale materialized winner until a conflict-aware query projection exists.

## Query subsystem

`query.rs` defines the typed AST, values, ordering, projections, execution modes, plans, results, and bounded cursors. The planner chooses document-ID lookup, a longest compound equality prefix, or collection scan. Residual evaluation preserves logical equivalence. Secondary indexes cover only visible metadata and are maintained in the same transaction as document writes. Protected fields are returned for explicit trusted-client filtering; blind-token predicates are rejected. Storage iteration enforces a 100,000-row scan-work ceiling and 64 MiB materialization ceiling; exceeding either returns an error rather than partial results.

`protocol.rs` admits blocking database operations through a semaphore whose permit is moved into the blocking closure. HTTP timeout or cancellation can stop waiting for a response, but it cannot free database-work capacity until that closure actually exits.

## Document state

`DocumentMetadata` contains collection, ID, logical version, creation mutation sequence, latest modification sequence, tombstone state, and optional encrypted-payload hash. Encrypted application payloads remain independent.

A live document has exactly one payload and payload hash. A tombstone has neither. Delete commits a new, strictly greater logical version and retains metadata; no physical document deletion is exposed. Re-creation must advance beyond the tombstone version.

`get` hides tombstones for convenient application reads. `get_record` returns metadata and therefore exposes tombstones to database/replication tooling.

## Transactions and concurrency

Every write batch is one redb write transaction. All preconditions and versions are checked inside that transaction. A failure aborts the entire batch, including mutation-log and head updates. Duplicate targets within a batch are rejected to keep precondition semantics unambiguous.

Available preconditions are unconditional, must-not-exist, must-exist, and exact-version compare-and-swap. Independently of the precondition, a committed logical version must be strictly greater than the prior live or tombstone version. Concurrent CAS writers therefore have at most one winner.

A `ReadSnapshot` owns a redb read transaction and presents a stable point-in-time view while later writes commit. Ordinary `get` creates a short-lived snapshot. Multiple readers may execute concurrently.

## Integrity and errors

Open validates the database header and format. Reads validate record domains, lengths, UTF-8, checksums, flags, size limits, metadata invariants, payload presence, envelope structure, and payload hashes. Verification also checks Ed25519 signatures, writer/key-version bindings, database identity, replay indexes, contiguous hash-linked history, current state, and the complete derived secondary-index map. Deterministic Merkle checkpoints and proofs cover live metadata and tombstones, but not the operational index catalog. Without a content key, storage verification cannot authenticate an envelope's AEAD tag or determine whether ciphertext decrypts.

`StoreError` distinguishes caller-correctable invalid input and write conflicts from unsupported formats, detected corruption, and storage failures. A failed history verification returns a structured invalid report; malformed bytes encountered during decoding return a corruption error.

## Remaining limitations

There is no migration framework, persistent savepoint API, incremental/streaming/encrypted backup, point-in-time recovery, protected-field server execution, authenticated/snapshot-pinned cursor, conflict-aware replicated query/index projection, dynamic revocation/per-document authorization, external checkpoint publication service, replication network transport, durable replica membership/revocation, replica retirement/vector pruning, safe tombstone GC, streaming/native binary wire encoding, or stable format guarantee. External checkpoint retention is required to detect self-consistent rollback.
