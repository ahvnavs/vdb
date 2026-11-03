# Threat model

## Assets and boundaries

Assets include document plaintext and encryption keys, writer signing keys, writer provenance, mutation ordering, current state, retained checkpoints, database identity, and availability. Plaintext/document keys and writer secrets belong to clients. Storage receives ciphertext, public identity material, signatures, and visible metadata. redb and the filesystem are untrusted for integrity.

## Attackers

- A storage attacker who can inspect, modify, reorder, duplicate, truncate, or roll back database files.
- A caller submitting malformed envelopes or replaying signed mutation material.
- A network attacker observing or modifying traffic while the server lacks TLS.
- A local attacker able to inspect command lines, terminal output, shell history, files, or process memory under OS permissions.
- A compromised writer key holder producing valid malicious mutations.

The OS, running binary, OS CSPRNG, BLAKE3, XChaCha20-Poly1305, Ed25519 implementation, and uncompromised client process are trusted.

## Current guarantees

- XChaCha20-Poly1305 authenticates ciphertext and identity/version metadata and protects plaintext under a high-entropy key.
- Each mutation has a database-bound canonical BLAKE3 ID and Ed25519 signature proving possession of its recorded writer key.
- History verification detects altered fields, invalid signatures, wrong registered keys, broken/reordered predecessors, gaps, duplicate/replayed IDs, and inconsistent head/index metadata.
- Current-state verification detects altered metadata/payloads, missing payloads, unsafe tombstone payloads, and mismatch with the latest mutation.
- Deterministic Merkle checkpoints commit to every live document and tombstone. Proofs bind collection/document identity and complete metadata to a root.
- Secret seed temporaries and in-memory signing keys are zeroized where supported.

## Rollback and truncation

A complete older database can be internally consistent and pass local verification. Truncation is detected only against a checkpoint retained outside the attacked database. Checkpoints are not yet externally published, timestamped, or separately signed. `history::verify_history` and `Store::verify_against` accept retained checkpoints.

## Identity versus authorization

Signatures identify a key; they do not establish authorization. The local database registers a key on its first local write. Key versions support rotation metadata, but old-key authorization, revocation, capabilities, and policy enforcement are absent. A compromised signing key can produce apparently authentic malicious mutations.

## Metadata leakage

Visible data includes database identity/time; collection/document IDs; versions and tombstones; writer IDs, public keys, key versions and signatures; mutation IDs/order/count; checkpoint root/count; plaintext BLAKE3 fingerprints; ciphertext sizes; nonces; access patterns; and network metadata. Plaintext fingerprints permit equality correlation and guessing of predictable documents.

## Non-goals

VDB is not a blockchain or cryptocurrency and provides no consensus, mining, token, proof-of-work, global clock, or Byzantine quorum. There is no TLS, network authorization, key revocation, hardware custody, external transparency log, traffic-analysis resistance, or availability against an administrator.
