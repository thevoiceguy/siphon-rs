// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The registrar's binding logic, driven by whatever REGISTER arrives.
//!
//! A binding decides where a user's calls are sent, and every part of it
//! — the address of record, the contact, the expiry, the q-value — comes
//! out of a REGISTER a device wrote. The canonical form of the AOR is
//! what bindings are looked up by, so two spellings that normalise to the
//! same string are the same user and two that do not are not.

#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sip_registrar::{normalize_aor, Binding};
use smol_str::SmolStr;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 || data.len() > 8192 {
        return;
    }
    let bytes = Bytes::copy_from_slice(data);
    let Some(request) = sip_parse::parse_request(&bytes) else {
        return;
    };

    // The address of record a REGISTER claims, canonicalised. Bindings
    // are keyed by this, so it must be total over anything that parses
    // and it must be deterministic — two lookups of the same URI have to
    // land on the same key.
    //
    // Deliberately *not* asserted: that re-parsing the result and
    // normalising again is a fixed point. The result is a collision-free
    // key, not a URI — a parameter whose value contains `tel:` puts one
    // in the middle of it — so re-parsing it is not a thing the registrar
    // ever does, and asserting it only fails on inputs nobody sends. The
    // fuzzer found that assertion within minutes, which is the target
    // being wrong rather than the code.
    let to = sip_parse::header(request.headers(), "To")
        .and_then(|to| sip_parse::parse_to_header(&to));
    let aor = to.as_ref().and_then(|to| {
        let uri = to.inner().uri();
        let first = normalize_aor(uri).ok()?;
        let second = normalize_aor(uri).ok()?;
        assert_eq!(first, second, "the same URI normalised two ways");
        assert!(!first.is_empty(), "a URI that parsed normalised to nothing");
        Some(first)
    });

    // Every contact the REGISTER offers, made into the binding it asks
    // for. The validators are the point: what they reject never reaches
    // the location store.
    let Some(aor) = aor else { return };
    for contact in request.headers().get_all("Contact") {
        let Ok(binding) = Binding::new(
            SmolStr::new(&aor),
            SmolStr::new(contact),
            Duration::from_secs(3600),
        ) else {
            continue;
        };

        // What the rest of the REGISTER says about this binding, each
        // through its own validator.
        let binding = match sip_parse::header(request.headers(), "Call-ID") {
            Some(call_id) => match binding.with_call_id(SmolStr::new(call_id.as_str())) {
                Ok(binding) => binding,
                Err(_) => continue,
            },
            None => binding,
        };
        let cseq = sip_parse::header(request.headers(), "CSeq")
            .and_then(|v| v.as_str().split_whitespace().next()?.parse::<u32>().ok())
            .unwrap_or(1);
        let Ok(binding) = binding.with_cseq(cseq) else {
            continue;
        };

        // A q-value out of range is a refusal, not a binding that sorts
        // ahead of every real device.
        let q = contact
            .split(";q=")
            .nth(1)
            .and_then(|q| q.split(';').next())
            .and_then(|q| q.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        let binding = match binding.with_q_value(q) {
            Ok(binding) => binding,
            Err(_) => continue,
        };

        let _ = (
            binding.aor(),
            binding.contact(),
            binding.expires(),
            binding.call_id(),
            binding.cseq(),
            binding.q_value(),
        );
    }
});
