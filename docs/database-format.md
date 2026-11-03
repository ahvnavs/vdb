# Database format

Current format: `3`, pre-stable. Format 3 introduces encrypted-envelope format 2 and removes the prior plaintext fingerprint. Unsupported or unversioned non-empty databases are rejected; no migration is inferred.

## Header and tables

The checksummed header stores format version, random 128-bit database ID, and creation time. The database ID is signed into every mutation to prevent cross-database replay.

Private logical tables contain database metadata, current document metadata, encrypted payloads, signed mutations by sequence, writer keys by writer ID/key version, and mutation IDs by sequence. redb remains an implementation detail. Tombstones retain metadata and omit payload rows.

## Canonical records

Records use an ASCII domain plus NUL, fixed-width big-endian integers, and unsigned 64-bit length-prefixed byte strings. Persisted checksummed records append a raw 32-byte BLAKE3 checksum. Decoders require complete consumption.

Mutation storage nests three domains: immutable signing material; signed record material containing mutation ID and Ed25519 signature; and persisted material containing the mutation-record hash and storage checksum. The mutation ID hashes signing material. The successor references the complete signed-record hash.

Encrypted-envelope format 2 stores algorithm, database ID, key ID, key version, collection, document ID, logical version, 24-byte nonce, and ciphertext/tag. Its canonical associated-data encoding is domain-separated and length-delimited. No plaintext hash is persisted. Storage hashes the complete opaque envelope for state/history integrity, while AEAD authenticity remains verifiable only by a key-holding client.

## State commitments

Checkpoint leaves cover every current metadata row, including tombstones, in canonical namespace-key order. Leaf, node, odd-node, and empty-tree rules are documented in `cryptography.md` and implemented in `merkle.rs`.

## Compatibility

No format-1 or format-2 migration exists. Format 3 remains pre-stable pending backup/restore, migrations, cross-version fixtures, and portable verifier test vectors. Any incompatible change must increment the header version.
