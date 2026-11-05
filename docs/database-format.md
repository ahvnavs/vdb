# Database format

Current format: `5`, pre-stable. Format 5 adds signed causal replication events and a duplicate/equivocation index. Unsupported or unversioned non-empty databases are rejected; no migration is inferred.

## Header and tables

The checksummed header stores format version, random 128-bit database ID, and creation time. The database ID is signed into every mutation to prevent cross-database replay.

Private logical tables contain database metadata, current document metadata, encrypted payloads, signed mutations by sequence, writer keys by writer ID/key version, mutation IDs by sequence, checksummed index definitions, derived index entries, signed replication events by event ID, and replication event IDs by causal dot. redb remains an implementation detail. Tombstones retain metadata and omit payload rows.

## Canonical records

Records use an ASCII domain plus NUL, fixed-width big-endian integers, and unsigned 64-bit length-prefixed byte strings. Persisted checksummed records append a raw 32-byte BLAKE3 checksum. Decoders require complete consumption.

Mutation storage nests three domains: immutable signing material; signed record material containing mutation ID and Ed25519 signature; and persisted material containing the mutation-record hash and storage checksum. The mutation ID hashes signing material. The successor references the complete signed-record hash.

Encrypted-envelope format 2 stores algorithm, database ID, key ID, key version, collection, document ID, logical version, 24-byte nonce, and ciphertext/tag. Its canonical associated-data encoding is domain-separated and length-delimited. No plaintext hash is persisted. Storage hashes the complete opaque envelope for state/history integrity, while AEAD authenticity remains verifiable only by a key-holding client.

Index definitions canonically encode name, collection, and one to four visible metadata fields. Index entry keys encode the index namespace, typed equality values, and document namespace key; the value repeats the document namespace key. Entries with a missing indexed field are omitted. Index maintenance is atomic with document writes, and verification recomputes the full derived entry map.

Replication event format 1 canonically encodes database/replica identity, replica key version/public key, causal dot, sorted version-vector context, document identity/version, mutation kind, and optional opaque encrypted envelope. The BLAKE3 event ID and Ed25519 signature cover that material. Persisted events and exchange batches are checksummed. The dot index makes duplicate delivery idempotent and rejects two different signed events claiming one replica counter.

## State commitments

Checkpoint leaves cover every current metadata row, including tombstones, in canonical namespace-key order. Leaf, node, odd-node, and empty-tree rules are documented in `cryptography.md` and implemented in `merkle.rs`.

## Compatibility

No migration from formats 1 through 4 exists. Format 5 remains pre-stable pending backup/restore, migrations, cross-version fixtures, and portable verifier/replication vectors. Any incompatible change must increment the header version.
