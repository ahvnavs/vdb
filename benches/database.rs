use std::{
    fs,
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Instant,
};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::{TempDir, tempdir};
use vdb::{
    crypto::{DatabaseKey, decrypt_document, encrypt_document},
    identity::{WriterIdentity, verify_detached},
    merkle::verify_inclusion_proof,
    model::{EncryptedDocument, VersionPrecondition, WriteOperation},
    query::{IndexDefinition, MetadataField, Predicate, Query, QueryValue},
    replication::{Replica, ReplicationEvent},
    store::Store,
};

const SMALL_PAYLOAD: &[u8] = br#"{"value":42,"protected":true}"#;

struct Fixture {
    _directory: TempDir,
    store: Store,
    key: DatabaseKey,
    database_id: String,
}

fn fixture(name: &str) -> Fixture {
    let directory = tempdir().expect("benchmark temporary directory");
    let store = Store::open(directory.path().join(format!("{name}.vdb"))).expect("open database");
    let database_id = store.metadata().expect("database metadata").database_id;
    let key = DatabaseKey::from_database_secret(&database_id, [7_u8; 32]).expect("database key");
    Fixture {
        _directory: directory,
        store,
        key,
        database_id,
    }
}

fn document(fixture: &Fixture, collection: &str, id: &str, version: u64) -> EncryptedDocument {
    encrypt_document(
        &fixture.key,
        &fixture.database_id,
        collection,
        id,
        version,
        SMALL_PAYLOAD,
    )
    .expect("encrypt benchmark document")
}

fn startup_benchmarks(c: &mut Criterion) {
    c.bench_function("startup/create_new_database", |b| {
        b.iter_batched(
            || tempdir().expect("cold-start directory"),
            |directory| Store::open(directory.path().join("cold.vdb")).expect("create database"),
            BatchSize::SmallInput,
        )
    });

    let directory = tempdir().expect("warm-start directory");
    let path = directory.path().join("warm.vdb");
    drop(Store::open(&path).expect("create warm database"));
    c.bench_function("startup/reopen_existing_database", |b| {
        b.iter(|| Store::open(black_box(&path)).expect("reopen database"))
    });
}

fn storage_benchmarks(c: &mut Criterion) {
    let point = fixture("point");
    point
        .store
        .put(&document(&point, "bench", "seed", 1))
        .expect("seed point read");
    c.bench_function("storage/point_read", |b| {
        b.iter(|| point.store.get("bench", black_box("seed")).expect("read"))
    });

    let write = fixture("write");
    let mut next = 0_u64;
    c.bench_function("storage/point_write_durable", |b| {
        b.iter(|| {
            next += 1;
            let id = format!("point-{next}");
            write.store.put(&document(&write, "bench", &id, 1))
        })
    });

    let mut group = c.benchmark_group("storage/write_shapes");
    for count in [10_usize, 100] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("sequential_commits", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || fixture("sequential"),
                    |fixture| {
                        for index in 0..count {
                            fixture
                                .store
                                .put(&document(&fixture, "bench", &format!("doc-{index}"), 1))
                                .expect("sequential write");
                        }
                    },
                    BatchSize::LargeInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("atomic_batch", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let fixture = fixture("batch");
                        let operations = (0..count)
                            .map(|index| WriteOperation::Put {
                                document: document(&fixture, "bench", &format!("doc-{index}"), 1),
                                precondition: VersionPrecondition::MustNotExist,
                            })
                            .collect::<Vec<_>>();
                        (fixture, operations)
                    },
                    |(fixture, operations)| fixture.store.write_transaction(operations),
                    BatchSize::LargeInput,
                )
            },
        );
    }
    group.finish();
}

fn query_benchmarks(c: &mut Criterion) {
    let fixture = fixture("query");
    for number in 0_u64..1_000 {
        fixture
            .store
            .put(&document(
                &fixture,
                "query_bench",
                &format!("document-{number:04}"),
                number + 1,
            ))
            .expect("seed query document");
    }
    let mut scan = Query::collection("query_bench");
    scan.limit = 1_000;
    scan.predicate = Some(Predicate::Ge {
        field: MetadataField::Version,
        value: QueryValue::Number(500),
    });
    c.bench_function("query/collection_scan_1000", |b| {
        b.iter(|| fixture.store.query(black_box(&scan)).expect("scan query"))
    });

    fixture
        .store
        .create_index(&IndexDefinition {
            name: "key_version".into(),
            collection: "query_bench".into(),
            fields: vec![MetadataField::KeyVersion],
        })
        .expect("create index");
    let mut indexed = Query::collection("query_bench");
    indexed.limit = 1_000;
    indexed.predicate = Some(Predicate::Eq {
        field: MetadataField::KeyVersion,
        value: QueryValue::Number(1),
    });
    c.bench_function("query/secondary_index_1000", |b| {
        b.iter(|| {
            fixture
                .store
                .query(black_box(&indexed))
                .expect("indexed query")
        })
    });
}

fn concurrency_benchmarks(c: &mut Criterion) {
    let concurrent_fixture = fixture("concurrency");
    concurrent_fixture
        .store
        .put(&document(&concurrent_fixture, "bench", "seed", 1))
        .expect("seed concurrency database");
    let store = Arc::new(concurrent_fixture.store.clone());
    c.bench_function("concurrency/4_readers_x250", |b| {
        b.iter_custom(|iterations| {
            let started = Instant::now();
            for _ in 0..iterations {
                let handles = (0..4)
                    .map(|_| {
                        let store = Arc::clone(&store);
                        thread::spawn(move || {
                            for _ in 0..250 {
                                black_box(store.get("bench", "seed").expect("concurrent read"));
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                for handle in handles {
                    handle.join().expect("reader thread");
                }
            }
            started.elapsed()
        })
    });

    let mixed = fixture("mixed");
    mixed
        .store
        .put(&document(&mixed, "bench", "seed", 1))
        .expect("seed mixed database");
    let store = Arc::new(mixed.store.clone());
    let database_id = mixed.database_id.clone();
    let next_round = AtomicU64::new(0);
    c.bench_function("concurrency/3_readers_1_writer_x100", |b| {
        b.iter(|| {
            let round = next_round.fetch_add(1, Ordering::Relaxed);
            let mut handles = (0..3)
                .map(|_| {
                    let store = Arc::clone(&store);
                    thread::spawn(move || {
                        for _ in 0..100 {
                            black_box(store.get("bench", "seed").expect("mixed read"));
                        }
                    })
                })
                .collect::<Vec<_>>();
            let writer_store = Arc::clone(&store);
            let writer_database_id = database_id.clone();
            handles.push(thread::spawn(move || {
                let key = DatabaseKey::from_database_secret(&writer_database_id, [7_u8; 32])
                    .expect("mixed key");
                for index in 0..100 {
                    let id = format!("mixed-{round}-{index}");
                    let value =
                        encrypt_document(&key, &writer_database_id, "bench", &id, 1, SMALL_PAYLOAD)
                            .expect("mixed encryption");
                    writer_store.put(&value).expect("mixed write");
                }
            }));
            for handle in handles {
                handle.join().expect("mixed thread");
            }
        })
    });
}

fn cryptography_benchmarks(c: &mut Criterion) {
    let fixture = fixture("crypto");
    c.bench_function("crypto/encrypt_1_kib", |b| {
        let payload = vec![42_u8; 1024];
        let mut version = 0_u64;
        b.iter(|| {
            version += 1;
            encrypt_document(
                &fixture.key,
                &fixture.database_id,
                "bench",
                "document",
                version,
                black_box(&payload),
            )
            .expect("encrypt")
        })
    });
    c.bench_function("crypto/decrypt_1_kib", |b| {
        let encrypted = encrypt_document(
            &fixture.key,
            &fixture.database_id,
            "bench",
            "large",
            1,
            &vec![42_u8; 1024],
        )
        .expect("encrypt fixture");
        b.iter(|| decrypt_document(&fixture.key, black_box(&encrypted)).expect("decrypt"))
    });

    let identity = WriterIdentity::generate().expect("identity");
    let message = b"vdb signing benchmark";
    let signature = identity.sign_bytes(message);
    let public = identity.public_key();
    c.bench_function("crypto/ed25519_sign", |b| {
        b.iter(|| identity.sign_bytes(black_box(message)))
    });
    c.bench_function("crypto/ed25519_verify", |b| {
        b.iter(|| verify_detached(&public, &signature, black_box(message)))
    });
}

fn integrity_benchmarks(c: &mut Criterion) {
    let fixture = fixture("integrity");
    for index in 0..1_000_u64 {
        fixture
            .store
            .put(&document(
                &fixture,
                "integrity",
                &format!("document-{index:04}"),
                1,
            ))
            .expect("seed integrity database");
    }
    c.bench_function("integrity/verify_1000_mutations", |b| {
        b.iter(|| fixture.store.verify().expect("verify history"))
    });
    c.bench_function("integrity/build_merkle_proof_1000", |b| {
        b.iter(|| {
            fixture
                .store
                .inclusion_proof("integrity", black_box("document-0500"))
                .expect("build proof")
        })
    });
    let proof = fixture
        .store
        .inclusion_proof("integrity", "document-0500")
        .expect("proof")
        .expect("existing document proof");
    c.bench_function("integrity/verify_merkle_proof_1000", |b| {
        b.iter(|| verify_inclusion_proof(black_box(&proof)).expect("verify proof"))
    });
}

fn sync_fixture(events: usize) -> (TempDir, Replica, Vec<ReplicationEvent>) {
    let directory = tempdir().expect("sync directory");
    let first_path = directory.path().join("first.vdb");
    let second_path = directory.path().join("second.vdb");
    let first = Store::open_with_identity(
        &first_path,
        WriterIdentity::generate().expect("first identity"),
    )
    .expect("first store");
    fs::copy(&first_path, &second_path).expect("copy initial database");
    let second = Store::open_with_identity(
        &second_path,
        WriterIdentity::generate().expect("second identity"),
    )
    .expect("second store");
    let first = Replica::new(first);
    let second = Replica::new(second);
    let database_id = first.store().metadata().expect("metadata").database_id;
    let key = DatabaseKey::from_database_secret(&database_id, [9_u8; 32]).expect("sync key");
    for index in 0..events {
        first
            .put(
                encrypt_document(
                    &key,
                    &database_id,
                    "sync",
                    &format!("document-{index:04}"),
                    1,
                    SMALL_PAYLOAD,
                )
                .expect("sync encryption"),
            )
            .expect("create sync event");
    }
    let missing = first
        .missing_for(&second.state().expect("second state"))
        .expect("missing events");
    (directory, second, missing)
}

fn sync_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("replication");
    for events in [10_usize, 100] {
        group.throughput(Throughput::Elements(events as u64));
        group.bench_with_input(
            BenchmarkId::new("apply_events", events),
            &events,
            |b, &events| {
                b.iter_batched(
                    || sync_fixture(events),
                    |(_directory, replica, missing)| replica.apply(&missing),
                    BatchSize::LargeInput,
                )
            },
        );
    }
    group.finish();
}

fn configure() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(2))
}

criterion_group! {
    name = benches;
    config = configure();
    targets = startup_benchmarks,
        storage_benchmarks,
        query_benchmarks,
        concurrency_benchmarks,
        cryptography_benchmarks,
        integrity_benchmarks,
        sync_benchmarks
}
criterion_main!(benches);
