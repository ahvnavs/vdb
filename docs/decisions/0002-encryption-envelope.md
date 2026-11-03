# ADR 0002: XChaCha20-Poly1305 client envelope

Status: superseded by ADR 0007 and encrypted-envelope format 2

## Decision

Encrypt content on the client using XChaCha20-Poly1305 with a fresh OS-generated 192-bit nonce. Authenticate the envelope format, collection, ID, and logical version as domain-separated, length-delimited associated data. The server does not receive the key.

## Consequences

Moving ciphertext between identities or versions is detected by clients. Visible identifiers, sizes, access patterns, and the current plaintext digest still leak. Command-line key input is transitional. Key storage, rotation, dedicated zeroizing types, and removal/keying of the plaintext digest remain required.
