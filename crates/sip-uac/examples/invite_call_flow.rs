// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Example demonstrating UAC INVITE call flow with dialog management.
///
/// This example shows how to:
/// 1. Create an INVITE request with SDP
/// 2. Process responses to create a dialog
/// 3. Send ACK for 200 OK
/// 4. Send BYE to terminate the call
use sip_core::SipUri;
use sip_uac::UserAgentClient;

fn main() {
    println!("=== UAC INVITE Call Flow Example ===\n");

    // Step 1: Create a UAC
    let local_uri = SipUri::parse("sip:alice@example.com").expect("valid local URI");
    let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").expect("valid contact URI");

    let uac =
        UserAgentClient::new(local_uri, contact_uri).with_display_name("Alice Smith".to_string());

    println!("Created UAC for Alice Smith <sip:alice@example.com>");

    // Step 2: Create INVITE request with SDP offer
    let target_uri = SipUri::parse("sip:bob@example.com").expect("valid target URI");
    let sdp_offer = "\
v=0
o=alice 123456 789012 IN IP4 192.168.1.100
s=Call to Bob
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
";

    let invite_request = uac.create_invite(&target_uri, Some(sdp_offer));

    println!("\n--- INVITE Request ---");
    println!("Method: {:?}", invite_request.method());
    println!("Request-URI: {}", invite_request.uri().as_str());
    println!("From: {}", invite_request.headers().get("From").unwrap());
    println!("To: {}", invite_request.headers().get("To").unwrap());
    println!(
        "Contact: {}",
        invite_request.headers().get("Contact").unwrap()
    );
    println!("CSeq: {}", invite_request.headers().get("CSeq").unwrap());
    println!(
        "Content-Type: {}",
        invite_request.headers().get("Content-Type").unwrap()
    );
    println!("Content-Length: {}", invite_request.body().len());

    // Step 3: Simulate call flow
    println!("\n--- Call Flow ---");
    println!("1. UAC -> UAS: INVITE (with SDP offer)");
    println!("   From: \"Alice Smith\" <sip:alice@example.com>;tag=xyz123");
    println!("   To: <sip:bob@example.com>");
    println!("   CSeq: 1 INVITE");
    println!();

    println!("2. UAS -> UAC: 100 Trying");
    println!("   (Provisional response - processing request)");
    println!();

    println!("3. UAS -> UAC: 180 Ringing");
    println!("   (Provisional response - alerting user)");
    println!();

    println!("4. UAS -> UAC: 200 OK (with SDP answer)");
    println!("   To: <sip:bob@example.com>;tag=abc456");
    println!("   Contact: <sip:bob@192.168.1.200:5060>");
    println!("   (Dialog is now established!)");
    println!();

    // In a real application:
    // let dialog = uac.process_invite_response(&invite_request, &ok_response)
    //     .expect("create dialog");
    // println!("Dialog created: {}", dialog.id.call_id);

    println!("5. UAC -> UAS: ACK");
    println!("   (Acknowledges 200 OK - completes INVITE transaction)");
    println!();

    // Create ACK (in real app, after receiving 200 OK):
    // let ack_request = uac.create_ack(&invite_request, &ok_response, None);

    println!("6. [Media session established - RTP flows]");
    println!();

    println!("7. UAC -> UAS: BYE");
    println!("   (Terminates the dialog)");
    println!("   CSeq: 2 BYE");
    println!();

    // Create BYE (in real app, to terminate call):
    // let bye_request = uac.create_bye(&dialog);

    println!("8. UAS -> UAC: 200 OK");
    println!("   (Confirms dialog termination)");

    println!("\n--- Dialog Information ---");
    println!("Dialog ID consists of:");
    println!("- Call-ID: Unique identifier for the call");
    println!("- Local tag: From Alice's From header");
    println!("- Remote tag: From Bob's To header in response");
    println!();
    println!("The dialog tracks:");
    println!("- Remote target: Bob's Contact URI for subsequent requests");
    println!("- Route set: Any Record-Route headers from the INVITE");
    println!("- Local/remote CSeq: Sequence numbers for request ordering");

    println!("\n=== Example Complete ===");
}
