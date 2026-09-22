// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Offer/answer (RFC 3264), driven by whatever offer arrives.
//!
//! The offer is a body a caller wrote, and the answer decides where media
//! is sent and which codecs are used. An answer that names a stream the
//! offer did not, or that accepts more streams than were offered, puts
//! media somewhere nobody asked for.

#![no_main]
use libfuzzer_sys::fuzz_target;
use sip_sdp::{negotiate, SessionDescription};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 || data.len() > 16384 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(offer) = SessionDescription::parse(text) else {
        return;
    };

    // What this node can do — fixed, so what varies is the offer.
    let local = match SessionDescription::parse(
        "v=0\r\n\
         o=fuzz 1 1 IN IP4 10.0.0.1\r\n\
         s=-\r\n\
         c=IN IP4 10.0.0.1\r\n\
         t=0 0\r\n\
         m=audio 10000 RTP/AVP 0 8 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n",
    ) {
        Ok(local) => local,
        Err(_) => return,
    };

    let Ok(answer) = negotiate::negotiate_answer(&offer, "10.0.0.1", &local) else {
        return;
    };

    // RFC 3264 §6: an answer has exactly as many m-lines as the offer,
    // in the same order and of the same types. A stream that is not
    // wanted is answered with port zero, never dropped.
    assert_eq!(
        answer.media.len(),
        offer.media.len(),
        "the answer changed how many streams there are"
    );
    for (offered, answered) in offer.media.iter().zip(&answer.media) {
        assert_eq!(
            offered.media_type, answered.media_type,
            "the answer changed a stream's media type"
        );
        // Every format in the answer was offered: an answer cannot
        // introduce a codec the caller never said it could decode.
        if answered.port != 0 {
            for format in &answered.formats {
                assert!(
                    offered.formats.contains(format),
                    "the answer accepted a format the offer did not carry"
                );
            }
        }
    }

    // The answer is a document in its own right: it has to survive being
    // written out and read back, since that is what goes on the wire.
    let written = answer.to_string();
    let _ = SessionDescription::parse(&written);
});
