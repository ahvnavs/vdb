# Operations

Status: implemented operational CLI, structured diagnostics, metrics, tracing, verified backup/restore, and offline compaction foundation.

## Inspection and status

```text
vdb inspect --db app.vdb
vdb status --db app.vdb
vdb verify --db app.vdb
```

`inspect` returns database metadata, state checkpoint, storage allocation/count statistics, and replication health. `status` additionally performs full cryptographic verification and reports signed mutations verified, replication events verified, state leaves, history/state/replication roots, conflicts, pending causal events, and sparse receive gaps. `verify` remains the minimal integrity command.

Query execution has explicit work guards: collection scans inspect at most 100,000 stored document metadata rows and materialize at most 64 MiB of selected metadata/ciphertext per operation. An operation exceeding either budget fails instead of returning a partial logical result. Use indexed/document-ID plans or partition collections when these limits are reached.

Diagnostics never deserialize protected payloads, decrypt documents, display ciphertext, print keys, signatures, nonces, authorization headers, request bodies, or plaintext. Database IDs, counts, roots, replica counts, conflict counts, paths supplied to the CLI, and storage sizes are operational metadata and may still be sensitive.

## Structured logging and tracing

The CLI installs a JSON tracing subscriber writing to stderr. `RUST_LOG` controls filtering and defaults to `info`. Network completion events contain request ID, method, route path, status, and elapsed milliseconds. Backup, restore, and compaction events contain operation outcomes and non-secret counts/identifiers. Query strings, bodies, ciphertext, keys, signatures, and authentication headers are not logged.

Example:

```text
RUST_LOG=vdb=debug vdb serve ...
```

## Metrics

Authenticated principals with `admin` permission may request `GET /v1/metrics`. The Prometheus text response includes HTTP totals/errors/in-flight requests, authentication failures, rate limiting, timeouts, storage bytes/fragmentation, document/tombstone counts, verified mutations, replication events/pending events/conflicts, and verification validity. Metrics collection performs database status verification and is intentionally protected and rate-limited; scrape conservatively.

Health `/healthz` means the process is running. Readiness `/readyz` means database metadata can be read. Neither substitutes for `/v1/metrics`, `status`, or full verification.

## Compaction

```text
vdb compact --db app.vdb
```

Compaction is offline. Stop VDB and every process using the file. The command refuses a database that fails full verification, opens an exclusive redb handle, runs compaction passes until no further progress is possible, closes the handle, reopens through VDB, and verifies again. It reports before/after file sizes and pass count. Compaction never garbage-collects tombstones, signed history, or replication events.

Do not kill compaction intentionally. redb provides transactional file recovery, but operators should retain a verified backup before maintenance. A read/write transaction or another process can cause compaction to fail safely rather than proceeding without exclusivity.

## Routine procedure

1. Monitor readiness, verification validity, request errors/timeouts, fragmentation, pending replication events, and conflicts.
2. Create and independently verify backups on a tested schedule; retain checkpoints outside the database and backup.
3. Exercise restore into a new path regularly.
4. Investigate increasing pending events/gaps before considering any tombstone retention change.
5. Compact only during a maintenance window after a verified backup.
6. Preserve corrupted files for diagnosis; restore or resynchronize instead of editing bytes.
