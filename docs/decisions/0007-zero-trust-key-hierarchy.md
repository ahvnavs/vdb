# ADR 0007: Zero-trust envelope and key hierarchy

Status: accepted, database format 3 and encrypted-envelope format 2

## Decision

Encrypt application payloads at the trusted client with XChaCha20-Poly1305. Generate nonces internally with the OS CSPRNG. Bind the database, namespace, logical version, and exact key ID/version through canonical associated data. Derive collection and document keys from a versioned database root with HKDF-SHA256. Remove plaintext fingerprints from durable state.

Represent rotation as a new independent root secret under the same key ID and a strictly increasing version. Decryption requires an exact version, while a client keyring may retain older versions. Wrap exported database keys with fixed-policy Argon2id and XChaCha20-Poly1305.

## Consequences

Storage and transport can handle opaque envelopes without keys, but cannot authenticate their AEAD tags. Collection/document identities, versions, key references, sizes, nonces, timing, and access patterns remain visible. Rotation does not re-encrypt existing data. The existing raw-key CLI is transitional; the wrapped-key library format provides protected at-rest export, but no key-manager integration exists.
