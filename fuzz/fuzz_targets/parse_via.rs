// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]
use libfuzzer_sys::fuzz_target;
use sip_parse::parse_via_header;
use smol_str::SmolStr;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 || data.len() > 512 {
        return;
    }

    // Try to convert to UTF-8 string
    if let Ok(s) = std::str::from_utf8(data) {
        let header = SmolStr::new(s);
        // Via parsing should never panic
        let _ = parse_via_header(&header);
    }
});
