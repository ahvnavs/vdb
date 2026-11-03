# ADR 0004: Preserve conflicts before adopting CRDTs

Status: proposed

## Decision

For the first replication design, use immutable mutation IDs, replica identities, causal metadata based on version vectors (likely dotted version vectors), and explicit preservation of concurrent document versions. Do not silently apply last-write-wins. Add deterministic merge policies only per documented data type; evaluate field-level CRDTs after workloads justify their complexity.

## Consequences

Users can observe and resolve genuine concurrency without hidden data loss. Metadata and tombstone costs increase. The exact clock encoding, pruning, replica retirement, and deterministic tie-breaking require specification and simulation before implementation.
