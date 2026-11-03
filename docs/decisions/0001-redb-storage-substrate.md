# ADR 0001: Use redb behind a VDB storage boundary

Status: accepted for the prototype

## Decision

Use redb for local ACID persistence while VDB owns document, transaction, history, and format semantics. Public APIs must not expose redb types.

## Consequences

VDB gains a memory-safe embedded transactional substrate and crash recovery. The current `Store` is only a preliminary boundary; Stage 1 must introduce a trait and format header before compatibility is promised. A future engine replacement requires conformance and migration tests.
