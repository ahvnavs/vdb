# Replication protocol

Status: implemented embedded replication foundation, event format version 1, database format 5.

## Model and scope

Each provisioned database replica has a random 128-bit replica ID and one or more versioned Ed25519 keys. Replicas participating in one synchronization group share the immutable VDB database ID. Provisioning/cloning that identity is an operator action; two unrelated databases cannot synchronize merely because their contents happen to match.

Replication is an immutable signed causal-event set. It is separate from each node's linear local mutation audit chain: independently committed linear sequences cannot be spliced without invalidating their predecessor hashes. redb remains private and peers exchange only canonical replication events and synchronization state.

The current implementation is an embedded/in-process protocol API. A streaming network transport and durable membership/revocation registry are not yet implemented.

`Replica` event state is currently authoritative for replicated collections and is read through `Replica::document`. It is not projected into the single-head `Store::get`/query/index tables because doing so would either discard conflicts or expose a stale winner. Applications must not mix direct `Store` writes and `Replica` writes for the same logical collection. A future conflict-aware query projection must preserve every head explicitly.

## Causal clock

An event's dot is `(replica_id, counter)`. Counters start at one. A local event uses one plus the greatest locally stored counter for its replica. Its context is a sorted version vector mapping every observed replica ID to the greatest observed counter. The event's own context entry must equal `counter - 1` (an absent entry means zero).

An event `A` observes event `B` when `A.context[B.replica_id] >= B.counter`. Two document events are concurrent when neither observes the other. A received event whose causal dependencies are missing is durably retained but is not exposed as a document head until every dot from one through each context counter exists locally.

Synchronization state represents each replica's stored dots as:

- `contiguous`: the greatest counter for which all counters from one are present;
- `sparse`: sorted counters above that frontier already present.

This representation permits reordered and partial delivery without falsely acknowledging holes. A sender offers each event whose dot is absent from the receiver state. Repeating the exchange is incremental and repairs packet loss.

## Canonical event

All integers are unsigned big-endian. Strings and byte strings have an unsigned 64-bit length prefix. Maps are encoded in ascending replica-ID order. Decoders reject truncation, duplicates, excessive fields, invalid UTF-8, trailing bytes, and checksum mismatch.

Signing material begins with `vdb.replication.signing.v1\0` and contains, in order:

1. event format version (`u32`, currently 1);
2. database ID;
3. replica ID, key version, and Ed25519 public key;
4. dot counter;
5. context entry count followed by sorted `(replica ID, counter)` entries;
6. kind byte (`1` put, `2` delete);
7. collection, document ID, and logical document version;
8. payload-present byte and, for a put, the complete encrypted-envelope fields;
9. signature algorithm (`Ed25519`).

`event_id = BLAKE3(signing_material)` as lowercase hexadecimal. `signature` is Ed25519 over the exact signing material. Persisted event encoding begins with `vdb.replication.event.v1\0`, contains length-prefixed signing material, event ID, and signature, then appends the raw 32-byte BLAKE3 checksum of all preceding event bytes.

A batch begins with `vdb.replication.batch.v1\0`, contains an event count and length-prefixed persisted events, then appends a raw BLAKE3 checksum. Current limits are 100,000 events per batch and 8 MiB per event. Implementations must validate the batch before applying any event.

## Application and duplicate suppression

Events are indexed both by event ID and by causal dot. Applying a batch is one redb transaction:

- an existing dot with the same event ID is an idempotent duplicate;
- an existing dot with a different event ID is replica equivocation and rejects the batch;
- an event ID without its dot index is corruption;
- otherwise both rows are inserted atomically.

Before storage, VDB verifies database binding, identifier lengths, causal-dot rules, event ID, Ed25519 signature, mutation kind/payload agreement, encrypted-envelope structure, and envelope database/collection/document/version binding. Storage verification rechecks every persisted event and dot index.

## Document state and conflicts

For a document, discard any event causally observed by another causally ready event for that document. Sort the remaining heads by event ID.

- zero heads: absent;
- one put head: live;
- one delete head: deleted;
- two or more heads: explicit conflict containing every sorted head.

Deletion is an ordinary signed causal event with no payload. Consequently delete-versus-modify is a conflict when concurrent; deletion never silently wins. Tombstones replicate indefinitely because safe replica-aware garbage collection is not implemented.

Resolution is explicit. A caller selects one current conflict head. The resolving replica emits a new event containing the selected put payload or deletion and its complete current version-vector context. That event observes all known heads. If another unseen concurrent event later arrives, conflict state reappears rather than losing it. No automatic last-write-wins rule or field CRDT exists.

## Checkpoints

Sort all stored event IDs lexicographically, decode each as one 32-byte Merkle leaf, and apply the binary Merkle rules in `cryptography.md`. A replication checkpoint contains database ID, event count, and root. Equal checkpoints prove equal event-ID sets under the hash assumptions; unequal checkpoints trigger state exchange. They do not prove freshness without an externally retained checkpoint and do not replace signature validation.

## Peer authentication

The transport supplies a fresh random 32-byte hexadecimal challenge. A peer responds with database ID, replica ID, key version, public key, challenge, current event root, and an Ed25519 signature over canonical `vdb.replication.hello.v1\0` material containing those fields in that order. The receiver verifies the exact challenge, shared database ID, configured `(replica ID, key version, public key)` authorization, and signature before accepting events.

Challenges must never repeat. TLS remains required for network confidentiality and endpoint protection. The current authorization list is supplied by the caller and is not a durable replicated membership system; an authenticated peer may relay events from other replicas, so production transport integration must validate event-writer membership against a durable group policy.

## Security and limitations

Signatures reject forged or altered events but do not make an authorized malicious replica honest. Causally incomplete events remain pending, preventing an invented context from immediately suppressing a conflict, but replica retirement, key revocation, Byzantine membership, bounded vector pruning, tombstone garbage collection, and denial-of-service resistance for very large histories remain future work.

Replication exposes database, replica, collection and document IDs; counters and version vectors; conflict relationships; deletion state; encrypted-envelope metadata and size; event counts, roots, signatures, and synchronization access patterns. It never requires a document content key and does not authenticate AEAD ciphertext tags.
