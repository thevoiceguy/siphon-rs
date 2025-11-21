#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sip_parse::{parse_request, parse_response};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let bytes = Bytes::copy_from_slice(data);
    let _ = parse_request(&bytes);
    let _ = parse_response(&bytes);
});
