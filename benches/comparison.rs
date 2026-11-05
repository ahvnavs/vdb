use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use redb::{Database, ReadableDatabase, TableDefinition};
use rusqlite::{Connection, params};
use tempfile::{TempDir, tempdir};
use vdb::{
    crypto::{DatabaseKey, encrypt_document},
    model::{VersionPrecondition, WriteOperation},
    store::Store,
};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("documents");
const PAYLOAD_BYTES: usize = 1024;
const BATCH: usize = 100;

struct VdbFixture {
    _directory: TempDir,
    store: Store,
    documents: Vec<vdb::model::EncryptedDocument>,
}

fn vdb_fixture(count: usize) -> VdbFixture {
    let directory = tempdir().expect("VDB comparison directory");
    let store = Store::open(directory.path().join("comparison.vdb")).expect("open VDB");
    let database_id = store.metadata().expect("VDB metadata").database_id;
    let key = DatabaseKey::from_database_secret(&database_id, [5_u8; 32]).expect("VDB key");
    let payload = vec![42_u8; PAYLOAD_BYTES];
    let documents = (0..count)
        .map(|index| {
            encrypt_document(
                &key,
                &database_id,
                "documents",
                &format!("document-{index:06}"),
                1,
                &payload,
            )
            .expect("encrypt VDB document")
        })
        .collect();
    VdbFixture {
        _directory: directory,
        store,
        documents,
    }
}

fn sqlite_fixture() -> (TempDir, Connection) {
    let directory = tempdir().expect("SQLite comparison directory");
    let connection = Connection::open(directory.path().join("comparison.sqlite")).expect("SQLite");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE documents (id TEXT PRIMARY KEY, payload BLOB NOT NULL);",
        )
        .expect("configure SQLite");
    (directory, connection)
}

fn redb_fixture() -> (TempDir, Database) {
    let directory = tempdir().expect("redb comparison directory");
    let database = Database::create(directory.path().join("comparison.redb")).expect("redb");
    let tx = database.begin_write().expect("redb setup transaction");
    tx.open_table(TABLE).expect("redb table");
    tx.commit().expect("redb setup commit");
    (directory, database)
}

fn point_read_comparison(c: &mut Criterion) {
    let vdb = vdb_fixture(1);
    vdb.store.put(&vdb.documents[0]).expect("seed VDB");
    let (sqlite_directory, sqlite) = sqlite_fixture();
    sqlite
        .execute(
            "INSERT INTO documents(id, payload) VALUES (?1, ?2)",
            params!["document-000000", vec![42_u8; PAYLOAD_BYTES]],
        )
        .expect("seed SQLite");
    let (redb_directory, redb) = redb_fixture();
    let tx = redb.begin_write().expect("redb seed transaction");
    tx.open_table(TABLE)
        .expect("redb table")
        .insert("document-000000", vec![42_u8; PAYLOAD_BYTES].as_slice())
        .expect("redb insert");
    tx.commit().expect("redb commit");

    let mut group = c.benchmark_group("comparison/point_read_1kib");
    group.bench_function("vdb", |b| {
        b.iter(|| {
            vdb.store
                .get("documents", black_box("document-000000"))
                .expect("VDB read")
        })
    });
    group.bench_function("sqlite_wal_full", |b| {
        b.iter(|| {
            sqlite
                .query_row(
                    "SELECT payload FROM documents WHERE id = ?1",
                    [black_box("document-000000")],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("SQLite read")
        })
    });
    group.bench_function("redb_direct", |b| {
        b.iter(|| {
            let tx = redb.begin_read().expect("redb read transaction");
            let table = tx.open_table(TABLE).expect("redb table");
            table
                .get(black_box("document-000000"))
                .expect("redb read")
                .map(|value| black_box(value.value().len()))
        })
    });
    group.finish();
    black_box((sqlite_directory, redb_directory));
}

fn point_write_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/point_write_durable_1kib");
    group.bench_function("vdb_signed_envelope", |b| {
        b.iter_batched(
            || vdb_fixture(1),
            |fixture| fixture.store.put(&fixture.documents[0]),
            BatchSize::LargeInput,
        )
    });
    group.bench_function("sqlite_wal_full", |b| {
        b.iter_batched(
            sqlite_fixture,
            |(_directory, connection)| {
                connection.execute(
                    "INSERT INTO documents(id, payload) VALUES (?1, ?2)",
                    params!["document-000000", vec![42_u8; PAYLOAD_BYTES]],
                )
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("redb_direct", |b| {
        b.iter_batched(
            redb_fixture,
            |(_directory, database)| {
                let tx = database.begin_write().expect("redb transaction");
                tx.open_table(TABLE)
                    .expect("redb table")
                    .insert("document-000000", vec![42_u8; PAYLOAD_BYTES].as_slice())
                    .expect("redb insert");
                tx.commit()
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn batch_write_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/atomic_batch_100x1kib");
    group.throughput(Throughput::Elements(BATCH as u64));
    group.bench_with_input(BenchmarkId::new("vdb", BATCH), &BATCH, |b, &count| {
        b.iter_batched(
            || vdb_fixture(count),
            |fixture| {
                fixture.store.write_transaction(
                    fixture
                        .documents
                        .into_iter()
                        .map(|document| WriteOperation::Put {
                            document,
                            precondition: VersionPrecondition::MustNotExist,
                        })
                        .collect(),
                )
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_with_input(
        BenchmarkId::new("sqlite_wal_full", BATCH),
        &BATCH,
        |b, &count| {
            b.iter_batched(
                sqlite_fixture,
                |(_directory, mut connection)| {
                    let transaction = connection.transaction().expect("SQLite transaction");
                    for index in 0..count {
                        transaction
                            .execute(
                                "INSERT INTO documents(id, payload) VALUES (?1, ?2)",
                                params![format!("document-{index:06}"), vec![42_u8; PAYLOAD_BYTES]],
                            )
                            .expect("SQLite insert");
                    }
                    transaction.commit()
                },
                BatchSize::LargeInput,
            )
        },
    );
    group.bench_with_input(
        BenchmarkId::new("redb_direct", BATCH),
        &BATCH,
        |b, &count| {
            b.iter_batched(
                redb_fixture,
                |(_directory, database)| {
                    let tx = database.begin_write().expect("redb transaction");
                    {
                        let mut table = tx.open_table(TABLE).expect("redb table");
                        for index in 0..count {
                            table
                                .insert(
                                    format!("document-{index:06}").as_str(),
                                    vec![42_u8; PAYLOAD_BYTES].as_slice(),
                                )
                                .expect("redb insert");
                        }
                    }
                    tx.commit()
                },
                BatchSize::LargeInput,
            )
        },
    );
    group.finish();
}

fn configure() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(2))
}

criterion_group! {
    name = comparisons;
    config = configure();
    targets = point_read_comparison, point_write_comparison, batch_write_comparison
}
criterion_main!(comparisons);
