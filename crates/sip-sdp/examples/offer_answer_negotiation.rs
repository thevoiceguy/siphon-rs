//! Example demonstrating RFC 3264 offer/answer SDP negotiation.
//!
//! This example shows:
//! - Creating SDP offers using configuration profiles
//! - Parsing SDP from text format
//! - Negotiating SDP answers from offers
//! - Serializing SDP back to text format
//! - Complete round-trip offer/answer flow
//!
//! Usage:
//! ```bash
//! cargo run --example offer_answer_negotiation
//! ```

use sip_sdp::{profiles, negotiate, SessionDescription};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SDP Offer/Answer Negotiation Example ===\n");

    // ================================================
    // Scenario 1: Audio-Only Call with Early Offer
    // ================================================
    println!("╔══════════════════════════════════════╗");
    println!("║  SCENARIO 1: AUDIO-ONLY EARLY OFFER ║");
    println!("╚══════════════════════════════════════╝\n");

    // Alice creates an audio-only offer
    println!("Step 1: Alice creates SDP offer (AudioOnly profile)");
    let alice_offer = profiles::create_from_profile(
        profiles::SdpProfile::AudioOnly,
        "alice",
        "192.168.1.100",
        8000,
        None,
    );

    println!("  Origin: o={} {} {} {} {} {}",
             alice_offer.origin.username,
             alice_offer.origin.session_id,
             alice_offer.origin.session_version,
             alice_offer.origin.net_type,
             alice_offer.origin.addr_type,
             alice_offer.origin.unicast_address);
    println!("  Session: s={}", alice_offer.session_name);
    println!("  Connection: c={} {} {}",
             alice_offer.connection.as_ref().unwrap().net_type,
             alice_offer.connection.as_ref().unwrap().addr_type,
             alice_offer.connection.as_ref().unwrap().connection_address);
    println!("  Media: {} streams", alice_offer.media.len());
    for (i, media) in alice_offer.media.iter().enumerate() {
        println!("    [{}] {} port {} proto {} formats {:?}",
                 i, media.media_type, media.port, media.protocol, media.formats);
        println!("         Codecs: {} rtpmaps", media.rtpmaps.len());
        for (pt, rtpmap) in &media.rtpmaps {
            println!("           PT {} = {}/{}", pt, rtpmap.encoding_name, rtpmap.clock_rate);
        }
    }

    // Serialize offer to text (as would be sent in SIP INVITE body)
    println!("\nStep 2: Serialize offer to SDP text format");
    let alice_offer_text = alice_offer.to_string();
    println!("  SDP size: {} bytes", alice_offer_text.len());
    println!("  SDP text:\n{}", alice_offer_text.lines()
        .take(5)
        .collect::<Vec<_>>()
        .join("\n"));
    println!("  ... ({} more lines)", alice_offer_text.lines().count() - 5);

    // Bob receives and parses the offer
    println!("\nStep 3: Bob receives and parses the offer");
    let parsed_offer = SessionDescription::parse(&alice_offer_text)?;
    println!("  ✓ Parsed successfully");
    println!("  Session: {}", parsed_offer.session_name);
    println!("  Media streams: {}", parsed_offer.media.len());

    // Bob creates his local capabilities (what he supports)
    println!("\nStep 4: Bob defines his local capabilities");
    let bob_capabilities = profiles::create_from_profile(
        profiles::SdpProfile::AudioOnly,
        "bob",
        "10.0.0.1",
        9000,
        None,
    );
    println!("  Bob supports: {} media streams", bob_capabilities.media.len());
    println!("  Audio port: {}", bob_capabilities.media[0].port);
    println!("  Audio codecs: {:?}", bob_capabilities.media[0].formats);

    // Bob negotiates answer using RFC 3264
    println!("\nStep 5: Bob negotiates answer per RFC 3264");
    let bob_answer = negotiate::negotiate_answer(
        &parsed_offer,
        "10.0.0.1",
        &bob_capabilities,
    )?;
    println!("  ✓ Negotiation successful");
    println!("  Answer has {} media streams", bob_answer.media.len());
    for media in &bob_answer.media {
        if media.port > 0 {
            println!("    ✓ {} accepted on port {} with formats {:?}",
                     media.media_type, media.port, media.formats);
        } else {
            println!("    ✗ {} rejected (port 0)", media.media_type);
        }
    }

    // Bob serializes answer
    println!("\nStep 6: Bob serializes answer to send in 200 OK");
    let bob_answer_text = bob_answer.to_string();
    println!("  SDP size: {} bytes", bob_answer_text.len());

    println!("\n  Result: Audio call established!");
    println!("    Alice sends RTP to 10.0.0.1:{}", bob_answer.media[0].port);
    println!("    Bob sends RTP to 192.168.1.100:{}", parsed_offer.media[0].port);

    // ================================================
    // Scenario 2: Audio+Video with Codec Mismatch
    // ================================================
    println!("\n\n╔════════════════════════════════════════════╗");
    println!("║  SCENARIO 2: AUDIO+VIDEO CODEC MISMATCH   ║");
    println!("╚════════════════════════════════════════════╝\n");

    // Alice offers both audio and video
    println!("Step 1: Alice creates audio+video offer");
    let alice_av_offer = profiles::create_from_profile(
        profiles::SdpProfile::AudioVideo,
        "alice",
        "192.168.1.100",
        8000,
        Some(8002),
    );
    println!("  ✓ Created offer with {} media streams", alice_av_offer.media.len());
    println!("    - Audio: port {} formats {:?}",
             alice_av_offer.media[0].port,
             alice_av_offer.media[0].formats);
    println!("    - Video: port {} formats {:?}",
             alice_av_offer.media[1].port,
             alice_av_offer.media[1].formats);

    // Bob only supports audio
    println!("\nStep 2: Bob only supports audio (no video codec)");
    let bob_audio_only = profiles::create_from_profile(
        profiles::SdpProfile::AudioOnly,
        "bob",
        "10.0.0.1",
        9000,
        None,
    );
    println!("  Bob capabilities: audio only");

    // Serialize and negotiate
    let offer_text = alice_av_offer.to_string();
    let parsed_av_offer = SessionDescription::parse(&offer_text)?;

    println!("\nStep 3: Negotiate answer (RFC 3264 handles mismatch)");
    let bob_partial_answer = negotiate::negotiate_answer(
        &parsed_av_offer,
        "10.0.0.1",
        &bob_audio_only,
    )?;
    println!("  ✓ Negotiation successful with partial rejection");
    for media in &bob_partial_answer.media {
        if media.port > 0 {
            println!("    ✓ {} accepted on port {}", media.media_type, media.port);
        } else {
            println!("    ✗ {} rejected (port 0 - no common codec)", media.media_type);
        }
    }

    println!("\n  Result: Audio-only call (video rejected)");
    println!("    Alice and Bob exchange audio only");
    println!("    Video stream rejected per RFC 3264 §6");

    // ================================================
    // Scenario 3: Direction Negotiation
    // ================================================
    println!("\n\n╔══════════════════════════════════════╗");
    println!("║  SCENARIO 3: DIRECTION NEGOTIATION  ║");
    println!("╚══════════════════════════════════════╝\n");

    println!("Demonstrating media direction negotiation:");

    let directions = [
        (negotiate::Direction::SendRecv, negotiate::Direction::SendRecv, "SendRecv + SendRecv"),
        (negotiate::Direction::SendRecv, negotiate::Direction::SendOnly, "SendRecv + SendOnly"),
        (negotiate::Direction::SendOnly, negotiate::Direction::RecvOnly, "SendOnly + RecvOnly"),
        (negotiate::Direction::Inactive, negotiate::Direction::SendRecv, "Inactive + SendRecv"),
    ];

    for (offer_dir, answer_dir, desc) in &directions {
        match offer_dir.reverse().negotiate(answer_dir) {
            Ok(result) => {
                println!("  ✓ {} → {:?}", desc, result);
            }
            Err(e) => {
                println!("  ✗ {} → Error: {}", desc, e);
            }
        }
    }

    // ================================================
    // Scenario 4: Complete Round-Trip
    // ================================================
    println!("\n\n╔══════════════════════════════════════╗");
    println!("║  SCENARIO 4: COMPLETE ROUND-TRIP    ║");
    println!("╚══════════════════════════════════════╝\n");

    println!("Testing parse → negotiate → serialize → parse round-trip:");

    // Create offer
    let original_offer = profiles::create_from_profile(
        profiles::SdpProfile::AudioOnly,
        "alice",
        "1.2.3.4",
        5000,
        None,
    );

    // Serialize
    let offer_text = original_offer.to_string();
    println!("  1. Serialize offer: {} bytes", offer_text.len());

    // Parse
    let parsed = SessionDescription::parse(&offer_text)?;
    println!("  2. Parse offer: ✓");

    // Create capabilities
    let capabilities = profiles::create_from_profile(
        profiles::SdpProfile::AudioOnly,
        "bob",
        "5.6.7.8",
        6000,
        None,
    );

    // Negotiate answer
    let answer = negotiate::negotiate_answer(&parsed, "5.6.7.8", &capabilities)?;
    println!("  3. Negotiate answer: ✓");

    // Serialize answer
    let answer_text = answer.to_string();
    println!("  4. Serialize answer: {} bytes", answer_text.len());

    // Parse answer again
    let reparsed = SessionDescription::parse(&answer_text)?;
    println!("  5. Parse answer: ✓");

    // Verify
    assert_eq!(reparsed.media.len(), answer.media.len());
    assert_eq!(reparsed.origin.username, answer.origin.username);
    println!("\n  ✓ Round-trip successful! SDP maintains integrity.");

    // Summary
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║            EXAMPLE COMPLETE                   ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    println!("Demonstrated features:");
    println!("  ✓ SDP profile templates (AudioOnly, AudioVideo)");
    println!("  ✓ RFC 4566 parsing and serialization");
    println!("  ✓ RFC 3264 offer/answer negotiation");
    println!("  ✓ Codec negotiation and rejection");
    println!("  ✓ Media direction negotiation");
    println!("  ✓ Complete round-trip integrity");
    println!("\nThese components are now integrated into IntegratedUAC and IntegratedUAS!");

    Ok(())
}
