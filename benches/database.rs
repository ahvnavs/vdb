use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::tempdir;
use vdb::{
    crypto::{DatabaseKey, decrypt_document, encrypt_document},
    query::{IndexDefinition, MetadataField, Predicate, Query, QueryValue},
    store::Store,
};

fn database_benchmarks(c: &mut Criterion) {
    let directory = tempdir().expect("benchmark temporary directory");
    let path = directory.path().join("benchmark.vdb");
    let store = Store::open(path.to_str().expect("UTF-8 benchmark path")).expect("open database");
    let database_id = store.metadata().expect("database metadata").database_id;
    let key = DatabaseKey::from_database_secret(&database_id, [7_u8; 32]).expect("database key");
    let document = encrypt_document(
        &key,
        &database_id,
        "bench",
        "document",
        1,
        br#"{"value":42}"#,
    )
    .expect("encrypt benchmark document");
    store.put(&document).expect("seed benchmark database");

    c.bench_function("get_document", |b| {
        b.iter(|| store.get("bench", "document").expect("read document"))
    });
    c.bench_function("decrypt_document", |b| {
        b.iter(|| decrypt_document(&key, &document).expect("decrypt document"))
    });
    c.bench_function("verify_one_mutation_history", |b| {
        b.iter(|| store.verify().expect("verify history"))
    });

    for number in 0_u64..1_000 {
        let id = format!("document-{number:04}");
        let document = encrypt_document(
            &key,
            &database_id,
            "query_bench",
            &id,
            number + 1,
            br#"{"protected":true}"#,
        )
        .expect("encrypt query benchmark document");
        store.put(&document).expect("seed query benchmark document");
    }
    let mut scan = Query::collection("query_bench");
    scan.limit = 1_000;
    scan.predicate = Some(Predicate::Ge {
        field: MetadataField::Version,
        value: QueryValue::Number(500),
    });
    c.bench_function("query_collection_scan_1000", |b| {
        b.iter(|| store.query(&scan).expect("scan query"))
    });

    store
        .create_index(&IndexDefinition {
            name: "key_version".into(),
            collection: "query_bench".into(),
            fields: vec![MetadataField::KeyVersion],
        })
        .expect("create benchmark index");
    let mut indexed = Query::collection("query_bench");
    indexed.limit = 1_000;
    indexed.predicate = Some(Predicate::Eq {
        field: MetadataField::KeyVersion,
        value: QueryValue::Number(1),
    });
    c.bench_function("query_secondary_index_1000", |b| {
        b.iter(|| store.query(&indexed).expect("indexed query"))
    });
}

criterion_group!(benches, database_benchmarks);
criterion_main!(benches);
