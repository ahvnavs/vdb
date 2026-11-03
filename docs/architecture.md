# Current architecture

Status: implemented state as of 2026-11-04. The local storage foundation is functional and tested, but VDB is not yet production-ready as a complete networked database.

## Layering

`Store` is the public embedded-database facade. It exposes durable metadata, point reads, held read snapshots, conditional puts, tombstone deletes, atomic write batches, and history verification. It depends on the internal `StorageEngine` and `StorageSnapshot` traits. No redb type appears in the public API.

`RedbEngine` is the only storage-engine implementation. It translates VDB namespaces, records, transactions, snapshots, and errors to redb. redb supplies serializable single-writer transactions, concurrent MVCC readers, crash recovery, and durable pages; VDB owns all database semantics and record formats.

`crypto.rs` is the trusted-client boundary. It derives collection and document keys from a versioned database key with HKDF-SHA256, then uses XChaCha20-Poly1305. Associated data binds the envelope version, algorithm, database ID, key ID/version, collection, document ID, and logical version. Storage and server code accept, persist, hash, and reproduce opaque envelopes without document keys.

The CLI and HTTP adapter remain thin callers of `Store`. The HTTP service still lacks production network security and must not be exposed to an untrusted network.

## Durable format version 3

Every new database receives a checksummed header containing:

- database format version `3`;
- a random 128-bit database identity encoded as lowercase hexadecimal;
- creation time in Unix milliseconds.

Missing headers in non-empty databases are rejected as unversioned/unsupported. Unsupported versions are not guessed or migrated. The earlier experimental three-table layout is intentionally rejected.

The backend uses private tables for database metadata, document metadata, encrypted payloads, signed mutations, writer public keys, and unique mutation IDs. Collection/document namespaces use a domain-separated, length-delimited binary key. Metadata and payloads are separate rows.

Persisted VDB records use explicit canonical binary encodings: domain tag, fixed-width big-endian integers, length-prefixed byte strings, and strict trailing-byte rejection. Checksummed records use BLAKE3 over the canonical body. Mutation hashes cover canonical mutation material rather than JSON or delimiter-concatenated strings.

Format 3 is explicit but remains pre-stable. Formats 1 and 2 are rejected, and no migration is implemented. Format 3 introduces encrypted-envelope format 2 and deliberately removes the plaintext fingerprint that format 2 exposed.

## Document state

`DocumentMetadata` contains collection, ID, logical version, creation mutation sequence, latest modification sequence, tombstone state, and optional encrypted-payload hash. Encrypted application payloads remain independent.

A live document has exactly one payload and payload hash. A tombstone has neither. Delete commits a new, strictly greater logical version and retains metadata; no physical document deletion is exposed. Re-creation must advance beyond the tombstone version.

`get` hides tombstones for convenient application reads. `get_record` returns metadata and therefore exposes tombstones to database/replication tooling.

## Transactions and concurrency

Every write batch is one redb write transaction. All preconditions and versions are checked inside that transaction. A failure aborts the entire batch, including mutation-log and head updates. Duplicate targets within a batch are rejected to keep precondition semantics unambiguous.

Available preconditions are unconditional, must-not-exist, must-exist, and exact-version compare-and-swap. Independently of the precondition, a committed logical version must be strictly greater than the prior live or tombstone version. Concurrent CAS writers therefore have at most one winner.

A `ReadSnapshot` owns a redb read transaction and presents a stable point-in-time view while later writes commit. Ordinary `get` creates a short-lived snapshot. Multiple readers may execute concurrently.

## Integrity and errors

Open validates the database header and format. Reads validate record domains, lengths, UTF-8, checksums, flags, size limits, metadata invariants, payload presence, envelope structure, and payload hashes. Verification also checks Ed25519 signatures, writer/key-version bindings, database identity, replay indexes, contiguous hash-linked history, and current state. Deterministic Merkle checkpoints and proofs cover live metadata and tombstones. Without a content key, storage verification cannot authenticate an envelope's AEAD tag or determine whether ciphertext decrypts.

`StoreError` distinguishes caller-correctable invalid input and write conflicts from unsupported formats, detected corruption, and storage failures. A failed history verification returns a structured invalid report; malformed bytes encountered during decoding return a corruption error.

## Remaining limitations

There is no migration framework, backup/restore API, savepoint API, collection scan, authorization/revocation policy, external checkpoint publication service, or stable format guarantee. External checkpoint retention is required to detect self-consistent rollback. Replication and networking were not expanded.
