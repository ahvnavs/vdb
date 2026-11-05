# ADR 0010: Verified logical backups and offline compaction

Status: accepted, backup format 1

## Decision

Export every private logical table from one redb MVCC read transaction into a domain-separated checksummed backup container. Write through a same-directory temporary file, fsync, atomic rename, and parent-directory sync. Verify every completed backup through a full temporary restore. Restore only to absent destinations, verify before atomic promotion, and compact only with an exclusive offline database handle after pre-verification and before post-verification.

## Consequences

Backups preserve database identity, signed history, tombstones, indexes, and replication state without exposing redb pages as the public format. They remain coupled to the current VDB format and are memory-buffered rather than streaming. Operators must secure ciphertext/metadata archives and retain external checkpoints for rollback detection. Compaction cannot silently discard history or replication tombstones.
