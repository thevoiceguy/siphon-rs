#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sip_parse::{parse_request, serialize_request};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 || data.len() > 2048 {
        return;
    }

    let bytes = Bytes::copy_from_slice(data);

    // If we can successfully parse a request, we should be able to serialize it
    // and re-parse it without panic
    if let Ok(request) = parse_request(&bytes) {
        let serialized = serialize_request(&request);

        // Re-parsing should not panic
        let _ = parse_request(&serialized);

        // If re-parsing succeeds, key fields should match
        if let Ok(reparsed) = parse_request(&serialized) {
            // Method should be preserved
            assert_eq!(request.start.method, reparsed.start.method);

            // URI should be preserved
            assert_eq!(request.start.uri.as_str(), reparsed.start.uri.as_str());

            // Body length should match
            assert_eq!(request.body.len(), reparsed.body.len());
        }
    }
});
