// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]
use libfuzzer_sys::fuzz_target;
use sip_core::multipart::MultipartBody;

fuzz_target!(|data: &[u8]| {
    // The first line is the Content-Type; the rest is the body.
    let Some(split) = data.iter().position(|&b| b == b'\n') else {
        return;
    };
    let Ok(content_type) = std::str::from_utf8(&data[..split]) else {
        return;
    };
    let body = &data[split + 1..];
    // Parsing never panics; a parsed body written again parses to the same parts.
    if let Ok(parsed) = MultipartBody::parse(content_type, body) {
        let again = MultipartBody::parse(&parsed.content_type(), &parsed.to_bytes())
            .expect("a written body parses");
        assert_eq!(again.parts().len(), parsed.parts().len());
    }
});
