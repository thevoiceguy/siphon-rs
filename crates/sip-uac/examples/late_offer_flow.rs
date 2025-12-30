// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Example demonstrating late offer call flow (RFC 3264).
///
/// In late offer:
/// 1. UAC sends INVITE without SDP
/// 2. UAS responds with 200 OK containing SDP offer
/// 3. UAC sends ACK with SDP answer
///
/// This is less common than early offer but useful when:
/// - UAC doesn't know its media capabilities in advance
/// - UAS wants to control the media negotiation
/// - Certain gateway/interop scenarios
use sip_core::SipUri;
use sip_uac::UserAgentClient;

fn main() {
    println!("=== Late Offer Call Flow Example ===\n");
    println!("RFC 3264 §5 - Generating the Initial Offer");
    println!();

    // Step 1: Create UAC
    let local_uri = SipUri::parse("sip:alice@example.com").expect("valid local URI");
    let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").expect("valid contact URI");

    let uac = UserAgentClient::new(local_uri, contact_uri)
        .with_display_name("Alice Smith".to_string())
        .expect("valid display name");

    println!("Created UAC for Alice Smith <sip:alice@example.com>");

    // Step 2: Create INVITE WITHOUT SDP (late offer)
    let target_uri = SipUri::parse("sip:bob@example.com").expect("valid target URI");
    let invite_request = uac.create_invite(&target_uri, None);

    println!("\n--- Step 1: INVITE without SDP (Late Offer) ---");
    println!("UAC -> UAS: INVITE");
    println!("Method: {:?}", invite_request.method());
    println!("Request-URI: {}", invite_request.uri().as_str());
    println!("From: {}", invite_request.headers().get("From").unwrap());
    println!("To: {}", invite_request.headers().get("To").unwrap());
    println!("Content-Length: {}", invite_request.body().len());
    println!("Content-Type: <not present>");
    println!();
    println!("Note: No SDP body in INVITE - this signals late offer");

    // Step 3: UAS processes request and sends provisional responses
    println!("\n--- Step 2: Provisional Responses ---");
    println!("UAS -> UAC: 100 Trying");
    println!("UAS -> UAC: 180 Ringing");

    // Step 4: UAS accepts and sends 200 OK WITH SDP offer
    println!("\n--- Step 3: 200 OK with SDP Offer ---");
    println!("UAS -> UAC: 200 OK");
    println!("To: <sip:bob@example.com>;tag=abc456");
    println!("Contact: <sip:bob@192.168.1.200:5060>");
    println!("Content-Type: application/sdp");
    println!();
    let sdp_offer = "\
v=0
o=bob 234567 890123 IN IP4 192.168.1.200
s=Call with Alice
c=IN IP4 192.168.1.200
t=0 0
m=audio 49172 RTP/AVP 0 8 18
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
";
    println!("SDP Offer from UAS:");
    println!("{}", sdp_offer);
    println!("Note: UAS provides the SDP offer in 200 OK");

    // In a real application:
    // let dialog = uac.process_invite_response(&invite_request, &ok_response)?;

    // Step 5: UAC sends ACK WITH SDP answer
    println!("--- Step 4: ACK with SDP Answer ---");
    println!("UAC -> UAS: ACK");
    println!("Content-Type: application/sdp");
    println!();

    let sdp_answer = "\
v=0
o=alice 345678 901234 IN IP4 192.168.1.100
s=Answer to Bob
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
";
    println!("SDP Answer from UAC:");
    println!("{}", sdp_answer);

    // In a real application:
    // let ack_request = uac.create_ack(&invite_request, &ok_response, Some(sdp_answer));

    println!("Note: UAC includes SDP answer in ACK to complete negotiation");

    // Step 6: Media session established
    println!("\n--- Step 5: Media Session Established ---");
    println!("RTP flows:");
    println!("  Alice (192.168.1.100:49170) <-> Bob (192.168.1.200:49172)");
    println!("  Codec: PCMU (G.711 μ-law)");

    println!("\n=== Comparison: Early vs Late Offer ===\n");

    println!("Early Offer (most common):");
    println!("  INVITE: Contains SDP offer from UAC");
    println!("  200 OK: Contains SDP answer from UAS");
    println!("  ACK:    Empty (no SDP)");
    println!();

    println!("Late Offer (this example):");
    println!("  INVITE: Empty (no SDP)");
    println!("  200 OK: Contains SDP offer from UAS");
    println!("  ACK:    Contains SDP answer from UAC");
    println!();

    println!("When to use Late Offer:");
    println!("  - Gateway scenarios where UAC doesn't control media");
    println!("  - UAS wants to dictate available codecs");
    println!("  - Delayed media capability determination");
    println!("  - IVR systems that need to offer specific media");

    println!("\n=== Example Complete ===");
}
