# Cryptography

Status: implemented cryptographic integrity architecture for database format 2.

## Primitives

- XChaCha20-Poly1305 from RustCrypto protects document plaintext using OS-generated 192-bit nonces.
- BLAKE3 provides content hashes, mutation IDs, record hashes/checksums, and Merkle hashes. Uses have distinct domain strings.
- Ed25519 from `ed25519-dalek` signs canonical mutation bytes.
- Secret seeds and CLI key buffers use `zeroize`; Ed25519 secret zeroization is enabled.

VDB defines encodings and domain separation, not custom cryptographic primitives.

## Writer identities

A `WriterIdentity` contains a random 128-bit writer ID, non-zero key version, Ed25519 signing key, and public key. Generation uses the OS CSPRNG. `vdb writer-keygen` emits provisioning material; its terminal output remains sensitive.

The database binds `(writer ID, key version)` to one public key. Reusing that tuple with another key is corruption. A writer may advance key versions under the same writer ID. Format 2 does not yet require an old key to authorize a new key, revoke keys, or confer write permission. Identity proves possession and provenance, not authorization.

## Canonical mutations

The signed representation uses domain `vdb.mutation.signing.v2` and canonical fields: database ID; sequence and kind; collection, document ID, version; metadata and optional payload hashes; predecessor record hash; writer ID, key version, public key, and algorithm. Integers are fixed-width big-endian and variable fields are unsigned 64-bit length-prefixed bytes.

The mutation ID is BLAKE3 over those bytes. Ed25519 signs the same bytes. A separate mutation-record hash commits to the signed bytes, mutation ID, and signature; the successor references that hash. A unique mutation-ID index rejects replay. Verification rejects malformed encoding, wrong database identity, gaps, reordering, predecessor changes, duplicate IDs, unregistered keys, invalid signatures, and record-hash mismatch.

## State checkpoints and proofs

A checkpoint contains format version, database ID, latest sequence, history head, state root, and leaf count. Leaves cover live records and tombstones, sorted by canonical namespace key. A leaf commits to document identity, version, creation/modification sequence, deletion flag, and optional payload hash. Ordered Merkle nodes use a separate domain; an odd final child is duplicated; the empty root has its own domain.

Inclusion proofs contain complete document metadata, position, leaf hash, sibling path, and checkpoint. Verification recomputes the identity-bound leaf and root. Checkpoints are not separately signed; detecting a self-consistent rollback requires a checkpoint retained outside the database.

## Verification

- `vdb verify` checks the stored signature chain, writer registry, replay index, current metadata, ciphertext hashes, and tombstones.
- `Store::mutation` and `history::verify_mutation` verify individual mutations.
- `history::verify_history` verifies exported ordered histories and detects truncation when given a retained checkpoint.
- `Store::checkpoint`, `Store::inclusion_proof`, and `merkle::verify_inclusion_proof` provide state commitments and membership verification.

## Limits

This is not blockchain consensus: there is no mining, token, proof-of-work, quorum, or global ordering. Signatures do not implement authorization or revocation. A complete older database verifies locally unless compared with an external checkpoint.
