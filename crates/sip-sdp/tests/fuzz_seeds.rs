// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The seed corpus the offer/answer fuzz target starts from.
//!
//! See `sip-parse/tests/fuzz_seeds.rs` for why these are generated rather
//! than committed. These are offers worth mutating: more than one stream,
//! a rejected stream, a codec this node does not have, a direction that
//! has to be reversed, and the alternative m-lines a real gateway sends.

use std::path::PathBuf;

const TARGET: &str = "offer_answer";

fn offers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "audio_pcmu",
            "v=0\r\n\
             o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0 8 101\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\n\
             a=fmtp:101 0-16\r\n\
             a=sendrecv\r\n",
        ),
        (
            "audio_video",
            "v=0\r\n\
             o=alice 1 1 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             m=video 49172 RTP/AVP 96\r\n\
             a=rtpmap:96 H264/90000\r\n\
             a=fmtp:96 profile-level-id=42e01f\r\n",
        ),
        (
            "held_stream",
            "v=0\r\n\
             o=alice 1 2 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=sendonly\r\n",
        ),
        (
            "rejected_stream",
            "v=0\r\n\
             o=alice 1 1 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             m=video 0 RTP/AVP 96\r\n\
             a=rtpmap:96 H264/90000\r\n",
        ),
        (
            "no_common_codec",
            "v=0\r\n\
             o=alice 1 1 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 99\r\n\
             a=rtpmap:99 SomeCodec/16000\r\n",
        ),
        (
            "alternative_audio_lines",
            // What a gateway sends when it offers SRTP and plain RTP for
            // the same stream and expects one to be zeroed (RFC 3264 §6).
            "v=0\r\n\
             o=gw 1 1 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/SAVP 0\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abcdefghijklmnopqrstuvwxyz0123456789ABCD\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             m=audio 49172 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
        ),
        (
            "ipv6_and_ptime",
            "v=0\r\n\
             o=alice 1 1 IN IP6 2001:db8::1\r\n\
             s=-\r\n\
             c=IN IP6 2001:db8::1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 8\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=ptime:20\r\n\
             a=maxptime:150\r\n",
        ),
    ]
}

#[test]
fn the_offer_seeds_are_valid_and_written_when_asked() {
    let offers = offers();
    assert!(!offers.is_empty());

    for (name, sdp) in &offers {
        assert!(
            sip_sdp::SessionDescription::parse(sdp).is_ok(),
            "seed {name} is not valid SDP"
        );
    }

    let Some(dir) = std::env::var_os("SIPHON_FUZZ_SEED_DIR").map(PathBuf::from) else {
        return;
    };
    let target_dir = dir.join(TARGET);
    std::fs::create_dir_all(&target_dir).expect("create the target's corpus directory");
    for (name, sdp) in &offers {
        std::fs::write(target_dir.join(name), sdp.as_bytes()).expect("write the seed");
    }
}
