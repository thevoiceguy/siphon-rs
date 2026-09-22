// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The dialog layer, driven by whatever arrives.
//!
//! A dialog is identified by Call-ID and two tags, and its route set is
//! built from the `Record-Route` headers of a message the far end sent.
//! Both are read out of text a peer chose, and a dialog that matches the
//! wrong messages — or a route set built from a header that is not what
//! it looks like — sends requests somewhere they should not go.

#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sip_core::SipUri;
use sip_dialog::{Dialog, DialogId};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 || data.len() > 8192 {
        return;
    }
    let bytes = Bytes::copy_from_slice(data);

    // A request: the identity a UAS would give the dialog it creates.
    if let Some(request) = sip_parse::parse_request(&bytes) {
        if let Some(id) = DialogId::from_request(&request) {
            // The three parts are text from the wire; reading them back
            // must not panic however they were spelled.
            let _ = (id.call_id(), id.local_tag(), id.remote_tag());
            // A dialog id is a map key, so it must hash and compare.
            let _ = id == id.clone();
            use std::collections::HashSet;
            let mut seen = HashSet::new();
            seen.insert(id);
        }
    }

    // A response: both the UAC's and the UAS's view of the same dialog,
    // and the dialog each would build from it.
    if let Some(response) = sip_parse::parse_response(&bytes) {
        let _ = DialogId::from_response_uac(&response);
        let _ = DialogId::from_response_uas(&response);

        let local: SipUri = match SipUri::parse("sip:local@fuzz.invalid") {
            Ok(uri) => uri,
            Err(_) => return,
        };
        let remote: SipUri = match SipUri::parse("sip:remote@fuzz.invalid") {
            Ok(uri) => uri,
            Err(_) => return,
        };
        // The request half is fixed, so what varies is the response the
        // dialog is built from — the half a peer controls.
        let invite = Bytes::from_static(
            b"INVITE sip:remote@fuzz.invalid SIP/2.0\r\n\
              Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfuzz\r\n\
              From: <sip:local@fuzz.invalid>;tag=localtag\r\n\
              To: <sip:remote@fuzz.invalid>\r\n\
              Call-ID: fuzz-call-id\r\n\
              CSeq: 1 INVITE\r\n\
              Contact: <sip:local@10.0.0.1>\r\n\
              Content-Length: 0\r\n\r\n",
        );
        if let Some(request) = sip_parse::parse_request(&invite) {
            for dialog in [
                Dialog::new_uac(&request, &response, local.clone(), remote.clone()),
                Dialog::new_uas(&request, &response, local.clone(), remote.clone()),
            ]
            .into_iter()
            .flatten()
            {
                // The route set comes from the peer's Record-Route; walking
                // it is what every in-dialog request does.
                for hop in dialog.route_set() {
                    let _ = hop.as_str();
                }
                let _ = dialog.remote_target().as_str();
                let _ = (dialog.local_cseq(), dialog.remote_cseq(), dialog.state());
            }
        }
    }
});
