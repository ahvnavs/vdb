# Threat model

Status: actual guarantees and limitations of database format 5, replication event format 1, and encrypted-envelope format 2.

## Assets and trust boundaries

Assets are document plaintext, database encryption keys, password-wrapped key exports, writer signing keys, authenticated namespace/version bindings, signed history, current state, retained checkpoints, database identity, and availability.

The trusted client boundary includes plaintext parsing, encryption/decryption, key generation/import, and AEAD authentication. The storage/server boundary receives encrypted envelopes and visible metadata and does not receive a content key. redb, database files, transport outside a protected channel, and the storage administrator are untrusted for confidentiality and integrity. The current CLI combines client and storage roles in one process; its local plaintext input file is supplied by the user and predates VDB.

## Attackers and assumptions

Considered attackers can inspect, modify, substitute, reorder, duplicate, truncate, or roll back database files and envelopes; submit malformed or oversized network data; replay requests or signed mutations; observe and interfere with networks; or inspect local arguments, terminal output, files, and process memory to the extent allowed by the OS. A compromised authorized device, writer, or content-key holder can act within that key's power.

The running binary, uncompromised client process, OS isolation, OS CSPRNG, and implementations of XChaCha20-Poly1305, HKDF-SHA256, Argon2id, BLAKE3, and Ed25519 are trusted. Users must protect high-entropy keys or strong wrapping passwords and retain any rollback checkpoint outside the database being checked.

## Confidentiality and authenticity guarantees

- A storage-only server can persist and return protected documents without the database key and does not need plaintext application fields.
- XChaCha20-Poly1305 hides plaintext and rejects ciphertext, tag, or bound-metadata modification for a client holding the correct key.
- Associated data binds envelope format/algorithm, database ID, key ID/version, collection, document ID, and logical version, preventing substitution across those contexts.
- Per-document keys are derived with domain-separated HKDF stages. Nonces are generated internally from the OS CSPRNG; callers cannot inject one.
- Exact key-version selection permits old and new versions to coexist during rotation without silent key fallback.
- Password exports use fixed-policy Argon2id plus authenticated encryption and reject malformed, downgraded, modified, or incorrectly passworded imports.
- Canonical BLAKE3/Ed25519 history verification detects altered mutations, wrong registered identities, invalid signatures, predecessor breaks, gaps, reordering, duplicate mutation IDs, and inconsistent state/index metadata.

The server validates envelope structure but cannot authenticate an AEAD tag without the content key. It can accept structurally valid random ciphertext; failure is discovered when a trusted client decrypts it. Mutation signatures establish writer provenance, not permission to write.

## Metadata leakage

The server and anyone reading the database can see database identity and creation time; collection and document IDs; logical versions and tombstone state; envelope/key format, key IDs and key versions; ciphertext and approximate plaintext length; random nonces; mutation sequence/count/type; writer and replica IDs, public keys, signatures, key versions, causal counters/version vectors, concurrent-head relationships, replication event counts/roots and synchronization patterns; payload hashes over ciphertext envelopes; checkpoint roots/counts; index definitions, indexed visible values, equality groups, cardinality and update patterns; query plans, cursors, requested metadata fields, opaque client-filter markers; request timing, access patterns, and network endpoints.

VDB format 5 does not store plaintext fingerprints. Repeated plaintext encrypted with fresh nonces is not directly equality-correlated, but stable document IDs, sizes, update timing, key IDs, indexed visible metadata, causal relationships, and access patterns remain correlatable. Collection, document, and index names are not hidden.

No blind/search token is implemented. `blind_token` queries fail closed. A future exact-match token would reveal equality/frequency, document-token association, query repetition, result size, update timing, and cross-query intersections as detailed in `query-language.md`; it requires a separate accepted ADR before implementation.

## Transport, authentication, and local handling

The network server requires rustls TLS and has no plaintext fallback. Protected requests require an allowlisted Ed25519 device/service identity, timestamp, nonce, request ID, body-bound signature, and scoped permission. Replay and rate state is process-local and is lost on restart; clocks must remain within configured skew. TLS certificates and authorization configuration are operator-managed. There is no mTLS, automated certificate renewal, dynamic revocation, or distributed admission state.

Transport encryption protects requests in flight but not metadata from the authenticated server. A compromised authorized principal can submit any operation allowed by its scopes. Network identity is admission evidence only and is not yet committed into durable mutation provenance. Timeouts cancel response processing, but an already executing atomic write can still commit.

The database service retains a separate operation permit inside each blocking database task. A timed-out response therefore does not release database-work admission until the underlying operation ends. Read-only query scans also enforce row and aggregate ciphertext budgets. These are availability bounds, not guarantees against denial of service by an authorized principal or storage operator.

The embedded replication handshake authenticates a fresh challenge, shared database ID, replica/key identity, and advertised state root against a caller-supplied authorization list. Every causal event is independently signed and database-bound. Altered, forged, cross-database, duplicate-dot, malformed, and checksummed-stream-corrupt events are rejected. A causally incomplete event remains pending and cannot hide a conflict until its dependencies exist.

An authorized malicious replica can still create arbitrary encrypted application values, delete documents, withhold events, flood unique valid events, or lie about causality using signed contexts whose dependencies it later supplies. The current implementation has no durable group membership, replicated revocation, Byzantine quorum, vector pruning, replica retirement, transport endpoint, or safe tombstone garbage collection. Authentication and signatures provide identity/integrity, not availability or honest application behavior.

The CLI does not log plaintext or keys and holds plaintext/key buffers in zeroizing memory where practical; Rust copies, allocator behavior, crash dumps, swap, terminal output, and user-created plaintext source files remain outside that guarantee. VDB creates no plaintext temporary document or key file.

Operational JSON logs contain only explicitly selected request/operation metadata. Metrics, inspection, and status expose counts, sizes, database/checkpoint roots, request routes/status, and replication health but never protected plaintext, ciphertext, keys, signatures, nonces, authentication headers, or bodies. Operators must still treat database IDs, paths, access timing, counts, roots, conflicts, and replica health as sensitive metadata.

Logical backups contain ciphertext plus all visible metadata, signed history, indexes, and replication events. They contain no content keys or plaintext generated by VDB, but confidentiality still depends on filesystem controls or an external reviewed encryption layer. Restore verifies integrity but cannot detect a self-consistent old backup without an externally retained checkpoint.

The current non-streaming backup reader rejects archives larger than 512 MiB before allocation. Backup and restore promotion use an atomic no-clobber link in the destination directory, so a destination created during verification is preserved and the operation fails. Cross-filesystem promotion is not used.

Raw key CLI arguments and `keygen` stdout can leak through process listings, shell history, logs around the process, or terminal capture. The wrapped-key library format is the supported safe-at-rest export mechanism, but CLI file/descriptor integration and an external key manager are not yet implemented.

## Rollback, availability, and non-goals

A complete older database can pass local verification. Rollback/truncation is detectable only against a checkpoint retained outside the attacked database; checkpoints are not externally published, timestamped, or separately signed. An administrator can delete or deny service, and cryptography cannot provide availability.

VDB provides no blockchain consensus, mining, token, proof-of-work, Byzantine quorum, global clock, automatic last-write-wins, field-level CRDTs, searchable encryption, blind indexes, arbitrary server-side protected-field query execution, traffic-analysis resistance, dynamic revocation/per-document policy, hardware-backed custody, secure deletion, endpoint compromise protection, or recovery from lost keys. Rotation does not automatically re-encrypt existing documents.
