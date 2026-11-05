#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<vdb::network::AuthorizationConfig>(data);
    let _ = serde_json::from_slice::<vdb::protocol::PutDocumentRequest>(data);
    let _ = serde_json::from_slice::<vdb::query::Query>(data);
    let _ = vdb::network::canonical_request(1, "POST", "/v1/query", "00", 0, "00", data);
});
