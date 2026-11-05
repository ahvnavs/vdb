# Query language and execution

Status: implemented metadata query subsystem for database format 5.

## Scope

The server can evaluate only information already visible outside document ciphertext. Queryable fields are `document_id`, `version`, `created_sequence`, `modified_sequence`, `deleted`, `key_id`, and `key_version`. Collection is the query namespace. Protected JSON fields are never decrypted or parsed by storage/query code.

The typed AST supports equality, inequality, numeric/string comparison, existence, `AND`, `OR`, projection, ordering, limits, and opaque cursor pagination. Comparisons require matching value types. Missing values fail comparisons and equality; `exists` tests presence explicitly. Queries exclude tombstones by default unless `include_deleted` is set.

No string expression parser is implemented. Callers construct or serialize the `Query` AST, avoiding an ad-hoc query syntax and parser ambiguity.

## Execution modes

1. `server_visible_metadata`: all predicates use visible metadata and are evaluated exactly by the server.
2. `blind_token`: reserved but currently rejected. VDB has no searchable-encryption token format or token index.
3. `client_side_filtering`: a `client_protected` marker causes the server to return the metadata-filtered encrypted candidate set with `requires_client_filter = true`. The trusted client must decrypt, parse, and apply the protected predicate. The marker is opaque but still visible to the server.

The server never claims a protected predicate was evaluated. Projection must be omitted when encrypted records are required for client filtering.

## Planning and indexes

The planner chooses, in order, an exact document-ID lookup, the longest available compound-index equality prefix, or a collection scan. Every candidate is passed through the residual AST, so indexed and scan execution have identical logical semantics. `explain` returns the mode, access path, equality prefix, residual-filter status, client-filter requirement, and whether ordering is performed in memory.

Secondary indexes are durable derived data over visible metadata. Definitions contain collection, name, and one to four non-repeated fields. Compound indexes are justified for common conjunctions and use leftmost equality prefixes. Comparisons and `OR` currently fall back to scans. Index creation, drop, and rebuild are atomic redb transactions. Put/delete transactions remove old entries and add new entries atomically with document state. Verification recomputes the complete index entry set.

Index definitions and entries are checksummed/validated but are operational derived state, not signed history or Merkle-state leaves. An attacker who can rewrite the whole database may remove a definition and its entries without history evidence; externally controlled schema declarations are needed if index-catalog rollback must be detected.

## Ordering and cursors

Results default to document-ID ascending order. Explicit order clauses support ascending or descending visible fields; document ID is the deterministic tie-breaker. Ordering is currently in memory. Cursors contain the last result's ordering values and document ID using URL-safe base64 JSON. They are bounded and strictly validated but not authenticated or snapshot-pinned. A modified cursor can alter pagination position, and writes between pages can cause ordinary seek-pagination insertions or omissions. Hold a `ReadSnapshot` across pages for a stable database view.

## Search-token leakage analysis

Before VDB implements a client-generated exact-match token, its format must have a separate ADR and tests. At minimum, such a token would reveal:

- equality and frequency of indexed values within its derivation scope;
- which documents carry a token and when tokens are added, changed, queried, or removed;
- query repetition, result cardinality, access patterns, and intersections across token indexes;
- token/index names and key-version metadata;
- low-entropy values to a malicious authorized client or an attacker with a token-generation oracle.

The design would need database/collection/index domain separation, keyed token derivation using a reviewed primitive, key-version and rotation semantics, deletion/rebuild behavior, authorization, rate limits, and an explicit decision about cross-version correlation. Deterministic encryption, order-revealing encryption, and server-visible plaintext values are not acceptable substitutes.
