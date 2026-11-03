# Database invariants

Items marked **enforced** are implemented and tested. Remaining items constrain later milestones.

1. Every database has one checksummed header with a supported format version, immutable random database ID, and creation timestamp. **Enforced.**
2. A non-empty database without a recognized VDB header is rejected; formats are never guessed. **Enforced.**
3. Collection/document keys are domain-separated and length-delimited, so distinct valid identities cannot alias. **Enforced.**
4. Collection and document IDs are non-empty, bounded, and cannot contain NUL. **Enforced.**
5. Document metadata is stored independently from encrypted application payloads. **Enforced.**
6. A live document has exactly one payload and matching payload hash; a tombstone has neither. **Enforced on writes and checked on reads/verification.**
7. Delete creates a durable tombstone at a strictly greater version; it does not erase identity/history. **Enforced.**
8. Re-creation after deletion must advance beyond the tombstone version. **Enforced.**
9. Every put/delete, current-state update, mutation append, sequence advance, and head advance is committed atomically. **Enforced by one redb transaction.**
10. A multi-document transaction either commits every operation in order or commits none. **Enforced.**
11. CAS preconditions are evaluated against state inside the serialized write transaction. **Enforced.**
12. A document logical version always strictly increases across live and tombstone states. **Enforced.**
13. Mutation sequences begin at one, are unique, contiguous, and ordered exactly as operations commit. **Enforced and verified.**
14. Every mutation after genesis names the exact preceding mutation hash. **Enforced and verified.**
15. Anything entering a VDB cryptographic hash or signature uses raw content bytes or an explicit domain-separated canonical binary encoding, never map iteration, platform-native integers, JSON formatting, or ambiguous delimiters. **Enforced for format 3.**
16. Persisted canonical records reject wrong domains, truncation, overflow, excessive fields, invalid flags, checksum mismatch, and trailing bytes. **Enforced.**
17. A held read snapshot never observes commits made after the snapshot began. **Enforced by redb MVCC and tested.**
18. Concurrent readers do not block one another; concurrent exact-version writers have at most one successful commit. **Enforced and tested.**
19. Caller-correctable invalid input/conflicts are distinguishable from corruption, unsupported format, and storage failure. **Enforced by typed errors.**
20. Envelope format/algorithm, database ID, key ID/version, collection, document ID, and logical version are authenticated with ciphertext. **Enforced for envelope format 2.**
21. Failed encryption authentication never returns plaintext. **Enforced.**
22. Storage and network layers never require a document encryption key. **Enforced by the current API boundary.**
23. No committed mutation may disappear without detectable evidence anchored outside the database. **Not yet enforced; external checkpoints are absent.**
24. Tombstones remain until every relevant replica has observed them or a specified safe-GC rule applies. **Physical tombstones are enforced; replica-aware GC is not implemented.**
25. Backup/restore preserves database identity, format, history, tombstones, and verification state. **Not implemented.**
26. A migration is atomic or restartable, version-gated, and tested forward and under interruption. **Not implemented.**
27. Every mutation ID commits to database, operation, state, predecessor, writer ID, key version, and public key. **Enforced.**
28. Every committed mutation has a valid Ed25519 signature and registered writer/key-version binding. **Enforced and verified.**
29. Mutation IDs are unique; replay or index inconsistency is rejected. **Enforced and verified.**
30. Deterministic state roots include all current live records and tombstones in canonical order. **Enforced.**
31. Inclusion proofs bind complete document metadata and identity to a checkpoint root. **Enforced and negatively tested.**
32. Local verification cannot detect self-consistent rollback without an externally retained checkpoint. **Explicit limitation.**
33. Encryption nonces are generated internally from the OS CSPRNG and callers cannot supply them. **Enforced; uniqueness is probabilistic over a 192-bit space.**
34. Each encrypted document key is domain-separated by database key, database ID, collection, document ID, and key version. **Enforced with HKDF-SHA256.**
35. Decryption selects an exact key ID and version; rotation never silently substitutes the newest key. **Enforced and tested.**
36. Password-wrapped key imports accept only the implemented Argon2id policy and authenticated wrap format; parameter downgrade is rejected. **Enforced.**
37. Storage may validate envelope structure without keys but must not claim ciphertext authenticity until a key-holding client verifies the AEAD tag. **Enforced by the API boundary and documented limitation.**
