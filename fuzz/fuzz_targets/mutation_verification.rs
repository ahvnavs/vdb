#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mutation) = serde_json::from_slice::<vdb::model::MutationRecord>(data) {
        let _ = vdb::history::verify_mutation(&mutation);
    }
});
