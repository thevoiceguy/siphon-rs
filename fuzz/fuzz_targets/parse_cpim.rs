// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]
use libfuzzer_sys::fuzz_target;
use sip_core::cpim::parse_cpim;

fuzz_target!(|data: &[u8]| {
    // Ignore non-UTF8 or obviously tiny payloads.
    if data.len() < 10 {
        return;
    }

    // Try to parse as UTF-8 string
    if let Ok(s) = std::str::from_utf8(data) {
        // Parse should either succeed or return a CpimError, never panic
        let _ = parse_cpim(s);
    }
});
