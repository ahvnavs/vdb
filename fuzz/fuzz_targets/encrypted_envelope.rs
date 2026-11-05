#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = serde_json::from_slice::<vdb::model::EncryptedDocument>(data) {
        let _ = vdb::crypto::validate_envelope(&envelope);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = vdb::crypto::WrappedDatabaseKey::from_json(text);
    }
});
