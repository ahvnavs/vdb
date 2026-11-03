# Threat model

Status: actual guarantees and limitations of database format 3 and encrypted-envelope format 2.

## Assets and trust boundaries

Assets are document plaintext, database encryption keys, password-wrapped key exports, writer signing keys, authenticated namespace/version bindings, signed history, current state, retained checkpoints, database identity, and availability.

The trusted client boundary includes plaintext parsing, encryption/decryption, key generation/import, and AEAD authentication. The storage/server boundary receives encrypted envelopes and visible metadata and does not receive a content key. redb, database files, transport outside a protected channel, and the storage administrator are untrusted for confidentiality and integrity. The current CLI combines client and storage roles in one process; its local plaintext input file is supplied by the user and predates VDB.

## Attackers and assumptions

Considered attackers can inspect, modify, substitute, reorder, duplicate, truncate, or roll back database files and envelopes; submit malformed data; replay signed mutations; observe an unprotected network; or inspect local arguments, terminal output, files, and process memory to the extent allowed by the OS. A compromised writer or content-key holder can create apparently legitimate data within that key's power.

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

The server and anyone reading the database can see database identity and creation time; collection and document IDs; logical versions and tombstone state; envelope/key format, key IDs and key versions; ciphertext and approximate plaintext length; random nonces; mutation sequence/count/type; writer IDs, public keys, signatures, and key versions; payload hashes over ciphertext envelopes; checkpoint roots/counts; request timing, access patterns, and network endpoints.

VDB format 3 does not store plaintext fingerprints. Repeated plaintext encrypted with fresh nonces is not directly equality-correlated, but stable document IDs, sizes, update timing, key IDs, and access patterns remain correlatable. Collection and document names are not hidden.

## Transport, local handling, and logging

The current HTTP server has no TLS, authentication, authorization, rate limiting, or production hardening and must not be exposed to an untrusted network. Encryption protects document content but not visible metadata, requests, or availability. The CLI does not log plaintext or keys and holds plaintext/key buffers in zeroizing memory where practical; Rust copies, allocator behavior, crash dumps, swap, terminal output, and user-created plaintext source files remain outside that guarantee. VDB creates no plaintext temporary document or key file.

Raw key CLI arguments and `keygen` stdout can leak through process listings, shell history, logs around the process, or terminal capture. The wrapped-key library format is the supported safe-at-rest export mechanism, but CLI file/descriptor integration and an external key manager are not yet implemented.

## Rollback, availability, and non-goals

A complete older database can pass local verification. Rollback/truncation is detectable only against a checkpoint retained outside the attacked database; checkpoints are not externally published, timestamped, or separately signed. An administrator can delete or deny service, and cryptography cannot provide availability.

VDB provides no blockchain consensus, mining, token, proof-of-work, Byzantine quorum, global clock, searchable encryption, blind indexes, traffic-analysis resistance, authorization/revocation policy, hardware-backed custody, secure deletion, endpoint compromise protection, or recovery from lost keys. Rotation does not automatically re-encrypt existing documents.
