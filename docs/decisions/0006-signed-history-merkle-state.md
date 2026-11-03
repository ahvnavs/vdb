# ADR 0006: Ed25519-signed history and deterministic Merkle state

Status: accepted, database format 2

## Decision

Sign canonical mutation bytes with Ed25519. Derive database-bound mutation IDs with BLAKE3, hash-link complete signed records, and maintain a unique mutation-ID index. Commit live records and tombstones to a deterministic binary Merkle tree with inclusion proofs.

## Consequences

VDB verifies writer-key possession, mutation integrity, ordered history, current state, and inclusion. External checkpoint retention is required for rollback detection. Identity is not authorization. Incompatible unsigned format 1 is rejected rather than guessed or silently migrated.
