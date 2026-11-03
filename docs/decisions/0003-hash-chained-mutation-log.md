# ADR 0003: Domain-separated hash-chained mutation log

Status: superseded by ADR 0006

## Decision

Commit each mutation into a BLAKE3 chain over domain-separated, length-delimited fields. Store the current envelope, mutation, sequence, and head in one redb transaction.

## Consequences

Local modification, gaps, and broken links are detectable. This is not authenticity or rollback protection: unkeyed hashes can be recomputed and a self-consistent older database can be restored. Signed mutations, canonical portable encoding, Merkle commitments, and external checkpoints are deferred to Stage 2.
