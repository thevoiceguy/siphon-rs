// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]
use libfuzzer_sys::fuzz_target;
use sip_core::SipUri;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 || data.len() > 1024 {
        return;
    }

    // Try to convert to UTF-8 string
    if let Ok(s) = std::str::from_utf8(data) {
        // URI parsing should never panic, only return errors
        let _ = SipUri::parse(s);
    }
});
