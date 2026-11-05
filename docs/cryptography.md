# Cryptography

Status: implemented client-side confidentiality, verifiable history, and signed causal replication for database format 5. VDB composes established primitives; it does not define a cipher, KDF, signature scheme, or hash function.

## Document encryption

Trusted clients encrypt with XChaCha20-Poly1305 from RustCrypto. The API generates a fresh 192-bit nonce with the OS CSPRNG and does not accept caller-provided nonces. This makes accidental reuse unavailable through the supported API; uniqueness remains probabilistic rather than mathematically guaranteed.

Envelope format 2 contains the algorithm, database ID, key ID and version, collection, document ID, logical version, nonce, and ciphertext/tag. A canonical, domain-separated binary representation of every field except nonce and ciphertext is authenticated as associated data. Moving ciphertext to another database, namespace, identity, version, or key reference therefore fails decryption. There is no persisted plaintext hash.

The storage and HTTP layers treat the envelope as opaque. They can validate its schema and sizes, hash it into signed mutations, and store/reproduce it without any content key. They cannot verify the AEAD tag, distinguish valid ciphertext from structurally valid garbage, or decrypt it.

## Key hierarchy and rotation

`DatabaseKey` holds a random 256-bit root secret, random 128-bit key ID, and non-zero version. HKDF-SHA256 derives a collection key from the root, database ID, collection, and key version, then derives a document key from that collection key and document ID. Derived keys and root secrets use zeroizing containers where practical.

Rotation preserves the key ID, generates a new independent root secret, and increments the version. Envelopes select an exact `(key ID, version)`; no fallback to a newer key occurs. A `Keyring` may retain old versions for old envelopes while new writes use the newest version. Rotation does not re-encrypt existing records automatically, and deletion of an old key makes its records unavailable.

The current CLI reads a raw high-entropy 32-byte hexadecimal database secret from a key file and derives a database-scoped key ID. `keygen` creates a new file without overwrite and uses mode 0600 on Unix. The file remains a raw secret and is not a substitute for OS keychain, hardware-backed, or external key-manager custody.

## Password-protected key export

`DatabaseKey::wrap_with_password` exports an authenticated, versioned JSON-compatible structure. Argon2id derives the wrapping key with a random 128-bit salt, 19 MiB memory, three iterations, and one lane; XChaCha20-Poly1305 wraps the key ID, version, and root secret with a random nonce. Import requires the exact supported policy and rejects downgrade, malformed input, wrong passwords, and modified ciphertext. Applications should choose strong passwords and protect the wrapped file like a credential. No plaintext key temporary file is created by VDB.

## Verifiable history

BLAKE3 supplies domain-separated payload hashes, mutation IDs, record checksums, and Merkle hashes. Ed25519 signs canonical mutations. Signing material includes the database ID, sequence, operation, namespace, logical version, state hashes, predecessor, writer ID, writer-key version, public key, and algorithm. A unique mutation-ID index rejects replay, and successors reference the complete signed-record hash.

State checkpoints commit to live records and tombstones in canonical namespace order. Inclusion proofs bind complete document metadata and identity to the root. `vdb verify` validates stored structure, signatures, history linkage, current-state hashes, and Merkle state, but does not possess document keys and therefore does not authenticate AEAD tags.

## Limits

This is not blockchain consensus. Signatures prove key possession and provenance, not authorization. A self-consistent old database requires an externally retained checkpoint to detect rollback. Metadata indexes do not inspect plaintext. There is no searchable encryption, blind index, deterministic encryption, order leakage mechanism, key revocation protocol, hardware-backed custody, or automatic re-encryption during rotation.
