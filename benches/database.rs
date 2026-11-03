use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::tempdir;
use vdb::{
    crypto::{decrypt_json, encrypt_json},
    store::Store,
};

fn database_benchmarks(c: &mut Criterion) {
    let directory = tempdir().expect("benchmark temporary directory");
    let path = directory.path().join("benchmark.vdb");
    let store = Store::open(path.to_str().expect("UTF-8 benchmark path")).expect("open database");
    let key = [7_u8; 32];
    let document = encrypt_json(&key, "bench", "document", 1, br#"{"value":42}"#)
        .expect("encrypt benchmark document");
    store.put(&document).expect("seed benchmark database");

    c.bench_function("get_document", |b| {
        b.iter(|| store.get("bench", "document").expect("read document"))
    });
    c.bench_function("decrypt_document", |b| {
        b.iter(|| decrypt_json(&key, &document).expect("decrypt document"))
    });
    c.bench_function("verify_one_mutation_history", |b| {
        b.iter(|| store.verify().expect("verify history"))
    });
}

criterion_group!(benches, database_benchmarks);
criterion_main!(benches);
