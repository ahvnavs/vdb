use std::{env, fs, path::Path, time::Instant};

use redb::{Database, TableDefinition};
use rusqlite::{Connection, params};
use serde::Serialize;
use tempfile::tempdir;
use vdb::{
    crypto::{DatabaseKey, encrypt_document},
    model::{VersionPrecondition, WriteOperation},
    store::Store,
};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("documents");
const DOCUMENTS: usize = 10_000;
const PAYLOAD_BYTES: usize = 1024;
const TRANSACTION_DOCUMENTS: usize = 100;

#[derive(Serialize)]
struct ResourceResult {
    engine: String,
    documents: usize,
    payload_bytes_each: usize,
    logical_payload_bytes: u64,
    database_file_bytes: u64,
    file_amplification: f64,
    peak_rss_kib: Option<u64>,
    elapsed_ms: u128,
    transaction_documents: usize,
}

fn main() {
    let engine = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("usage: resource_probe <vdb|sqlite|redb>"));
    let directory = tempdir().expect("resource probe directory");
    let started = Instant::now();
    match engine.as_str() {
        "vdb" => populate_vdb(directory.path()),
        "sqlite" => populate_sqlite(directory.path()),
        "redb" => populate_redb(directory.path()),
        _ => panic!("unknown engine {engine}"),
    }
    let elapsed_ms = started.elapsed().as_millis();
    let logical_payload_bytes = (DOCUMENTS * PAYLOAD_BYTES) as u64;
    let database_file_bytes = directory_bytes(directory.path());
    let result = ResourceResult {
        engine,
        documents: DOCUMENTS,
        payload_bytes_each: PAYLOAD_BYTES,
        logical_payload_bytes,
        database_file_bytes,
        file_amplification: database_file_bytes as f64 / logical_payload_bytes as f64,
        peak_rss_kib: peak_rss_kib(),
        elapsed_ms,
        transaction_documents: TRANSACTION_DOCUMENTS,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).expect("serialize resource result")
    );
}

fn populate_vdb(path: &Path) {
    let store = Store::open(path.join("probe.vdb")).expect("open VDB");
    let database_id = store.metadata().expect("VDB metadata").database_id;
    let key = DatabaseKey::from_database_secret(&database_id, [4_u8; 32]).expect("VDB key");
    let payload = vec![42_u8; PAYLOAD_BYTES];
    for start in (0..DOCUMENTS).step_by(TRANSACTION_DOCUMENTS) {
        let operations = (start..(start + TRANSACTION_DOCUMENTS).min(DOCUMENTS))
            .map(|index| WriteOperation::Put {
                document: encrypt_document(
                    &key,
                    &database_id,
                    "documents",
                    &format!("document-{index:06}"),
                    1,
                    &payload,
                )
                .expect("encrypt VDB document"),
                precondition: VersionPrecondition::MustNotExist,
            })
            .collect();
        store
            .write_transaction(operations)
            .expect("VDB transaction");
    }
}

fn populate_sqlite(path: &Path) {
    let mut connection = Connection::open(path.join("probe.sqlite")).expect("open SQLite");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE documents (id TEXT PRIMARY KEY, payload BLOB NOT NULL);",
        )
        .expect("configure SQLite");
    let payload = vec![42_u8; PAYLOAD_BYTES];
    for start in (0..DOCUMENTS).step_by(TRANSACTION_DOCUMENTS) {
        let transaction = connection.transaction().expect("SQLite transaction");
        for index in start..(start + TRANSACTION_DOCUMENTS).min(DOCUMENTS) {
            transaction
                .execute(
                    "INSERT INTO documents(id, payload) VALUES (?1, ?2)",
                    params![format!("document-{index:06}"), &payload],
                )
                .expect("SQLite insert");
        }
        transaction.commit().expect("SQLite commit");
    }
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("SQLite checkpoint");
    drop(connection);
}

fn populate_redb(path: &Path) {
    let database = Database::create(path.join("probe.redb")).expect("open redb");
    let payload = vec![42_u8; PAYLOAD_BYTES];
    for start in (0..DOCUMENTS).step_by(TRANSACTION_DOCUMENTS) {
        let tx = database.begin_write().expect("redb transaction");
        {
            let mut table = tx.open_table(TABLE).expect("redb table");
            for index in start..(start + TRANSACTION_DOCUMENTS).min(DOCUMENTS) {
                table
                    .insert(format!("document-{index:06}").as_str(), payload.as_slice())
                    .expect("redb insert");
            }
        }
        tx.commit().expect("redb commit");
    }
    drop(database);
}

fn directory_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .expect("read probe directory")
        .map(|entry| {
            let entry = entry.expect("probe directory entry");
            let metadata = entry.metadata().expect("probe file metadata");
            if metadata.is_file() {
                metadata.len()
            } else {
                0
            }
        })
        .sum()
}

fn peak_rss_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}
