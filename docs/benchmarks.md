# Performance benchmarks

VDB performance claims must be backed by a dated result file containing the
machine, toolchain, workload, and confidence interval. Results from different
machines are not directly comparable. The checked-in baseline is
[`benchmarks/results/2026-11-05-baseline.md`](../benchmarks/results/2026-11-05-baseline.md).

## Reproduction

Run benchmarks from an otherwise idle checkout with the release benchmark
profile:

```text
cargo bench --bench database -- --noplot
cargo bench --bench comparison -- --noplot
cargo bench --bench resource_probe -- vdb
cargo bench --bench resource_probe -- sqlite
cargo bench --bench resource_probe -- redb
```

Criterion uses 20 samples, a one-second warm-up, and a two-second target
measurement. Its HTML and machine-readable output is written below
`target/criterion/`; that generated data is not committed. Keep the complete
confidence interval, not only the point estimate, when publishing results.

## Workload definitions

- `create_new_database` measures creation and initialization of a fresh file.
  It is a logical cold start; it does not evict the operating-system page cache.
- `reopen_existing_database` repeatedly opens an initialized database and is a
  warm-start measurement.
- Point reads return and validate the stored opaque encrypted envelope. Point
  writes are durable, signed, hash-linked commits.
- Sequential writes use one durable transaction per document. Batch writes use
  one atomic transaction for the complete batch. Transaction construction and
  temporary-database setup occur outside timed sections.
- Query workloads contain 1,000 protected records and exercise collection scan
  and secondary-index execution. The index workload intentionally returns all
  matching rows, so it measures index traversal rather than claiming selective
  lookup speed.
- Concurrent workloads use four operating-system threads: either four readers,
  or three readers and one writer. Thread creation is included.
- Cryptographic workloads cover 1 KiB XChaCha20-Poly1305 envelopes, Ed25519
  signing/verification, complete history verification, and Merkle proof
  construction/verification.
- Sync applies signed replication events to an independent replica. Fixture
  construction is excluded from timing.
- The resource probe inserts 10,000 opaque 1 KiB values in batches of 100 in a
  fresh process. It reports Linux `VmHWM`, total files in the temporary database
  directory, and file amplification relative to application payload bytes.

## Comparison policy

The comparison uses SQLite in WAL mode with `synchronous=FULL`, and direct redb
as the second embedded baseline. All engines store the same opaque 1 KiB value,
use primary-key reads, and use equivalent single-record or 100-record atomic
transactions. Setup and value construction are excluded from the timed region.

The systems do not provide equivalent semantics. VDB additionally maintains
document metadata, checksums, writer signatures, mutation IDs, a replay index,
and hash-linked history. Direct redb has none of those semantics. SQLite has
durability and transaction semantics but the comparison schema does not add
VDB's cryptographic history. Results therefore quantify overhead for these
specific workloads; they are not product rankings.

The VDB comparison pre-encrypts envelopes outside timed writes, so encryption
cost is reported separately. The resource probe includes VDB encryption and
history maintenance because its primary outputs are peak memory and final file
size. SQLite is checkpointed before sizing. No cache dropping, CPU pinning, or
frequency control is performed; record those controls if future release
measurements add them.

## Profiling and optimization rules

Use Criterion to locate workload-level cost centers, then use an available
sampling profiler before changing a hot path. Always rerun the affected
benchmark and correctness gates. Do not optimize away authenticated metadata,
signature checks, atomicity, conflict detection, or durable commits.

The baseline host did not have `perf`, Valgrind/Callgrind, or heaptrack
installed. Its process-level profile uses elapsed time, peak RSS, and file size.
No kernel implementation was changed from that evidence alone: signature
verification explains most full-history verification time, and VDB's richer
on-disk semantics explain much of its comparison overhead. Both require a more
granular profile before a safe implementation change.

