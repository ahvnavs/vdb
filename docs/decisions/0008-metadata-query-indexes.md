# ADR 0008: Metadata-only server queries and derived indexes

Status: accepted, database format 4

## Decision

Represent queries as a typed AST. Permit server execution and durable secondary/compound indexes only over metadata already visible in the encrypted envelope or document record. Plan exact document-ID lookups, then longest compound equality prefixes, then collection scans. Apply residual predicates after every access path.

Represent protected-field work as an explicit client-filtering mode that returns encrypted candidates. Reserve blind-token syntax but reject it until a separate leakage-reviewed format is accepted. Do not implement deterministic or order-revealing encryption.

## Consequences

Server-side equality, comparison, Boolean predicates, projection, ordering, limits, and pagination work for visible metadata without content keys. Protected-field queries require bandwidth and client computation. Indexes expose no new plaintext values, but make indexed field combinations, equality groups, cardinality, update patterns, and access paths easier to observe. Index catalog and entries are verified derived state but are not signed mutations or Merkle leaves.
