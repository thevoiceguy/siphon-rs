//! Demonstrates building SDP offers/answers using MediaProfileBuilder.
use sip_sdp::profiles::{negotiate_answer, MediaProfileBuilder};

fn main() {
    // Build an audio/video offer with default codecs.
    let offer = MediaProfileBuilder::audio_video().build("alice", "192.0.2.1", 5004, Some(5006));

    // Build a local profile that only supports audio + opus.
    let local_profile = MediaProfileBuilder::audio_only().add_audio_codec(111, "opus", 48000);

    // Negotiate an answer that intersects codecs.
    let answer = negotiate_answer(&offer, &local_profile, "bob", "198.51.100.10", 7000, None);

    println!("Offer:\n{}", offer.to_string());
    println!("Answer:\n{}", answer.to_string());
}
