#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vdb::replication::decode_batch(data);
    if let Ok(proof) = serde_json::from_slice::<vdb::model::InclusionProof>(data) {
        let _ = vdb::merkle::verify_inclusion_proof(&proof);
    }
});
