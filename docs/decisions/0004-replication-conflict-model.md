# ADR 0004: Preserve conflicts before adopting CRDTs

Status: accepted, database format 5 and replication event format 1

## Decision

Use immutable signed replication event IDs, Ed25519 replica identities, dotted version-vector causality, sparse receive frontiers, and explicit preservation of concurrent document versions. Keep the causal event set separate from each replica's linear local audit chain. Do not silently apply last-write-wins. Resolution is a new causal event selecting a current head. Add CRDTs only per documented data type after workloads justify their complexity.

## Consequences

Users can observe and resolve genuine concurrency without hidden data loss. Reordering, duplicates, and partial delivery are idempotent. Metadata, version vectors, event retention, and tombstone costs increase. Replica retirement, vector pruning, safe tombstone garbage collection, durable membership/revocation, and transport streaming remain required before large or dynamic replica groups are practical.
