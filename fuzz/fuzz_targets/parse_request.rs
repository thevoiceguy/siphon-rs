#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sip_parse::parse_request;

fuzz_target!(|data: &[u8]| {
    // Ignore non-UTF8 or obviously tiny payloads.
    if data.len() < 4 {
        return;
    }
    let bytes = Bytes::copy_from_slice(data);
    let _ = parse_request(&bytes);
});
