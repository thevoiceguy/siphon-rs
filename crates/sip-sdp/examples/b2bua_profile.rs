// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Demonstrates a B2BUA bridging two legs while negotiating SDP with MediaProfileBuilder.
use sip_sdp::profiles::MediaProfileBuilder;

fn main() {
    // Leg A offer (caller -> B2BUA)
    let offer_a = MediaProfileBuilder::audio_video()
        .add_audio_codec(111, "opus", 48000)
        .build("caller", "192.0.2.10", 4000, Some(4002));

    // Leg B capabilities (callee) - audio only + opus
    let profile_b = MediaProfileBuilder::audio_only().add_audio_codec(111, "opus", 48000);

    // B2BUA negotiates answer to caller based on callee profile
    let answer_to_a = sip_sdp::profiles::negotiate_answer(
        &offer_a,
        &profile_b,
        "b2bua",
        "198.51.100.1",
        6000,
        None,
    );

    // B2BUA constructs offer toward callee using the same profile (audio/opus)
    let offer_b = profile_b.build("b2bua", "198.51.100.1", 6000, None);

    println!("Caller offer (A):\n{}", offer_a.to_string());
    println!("Answer to caller (A):\n{}", answer_to_a.to_string());
    println!("Offer to callee (B):\n{}", offer_b.to_string());
}
