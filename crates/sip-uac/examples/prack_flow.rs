// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Example demonstrating PRACK (Provisional Response Acknowledgement) per RFC 3262.
///
/// PRACK flow scenario:
/// 1. Alice sends INVITE with Supported: 100rel
/// 2. Bob sends 180 Ringing with RSeq header and Require: 100rel
/// 3. Alice sends PRACK to acknowledge the 180 response
/// 4. Bob sends 200 OK to PRACK
/// 5. Bob sends 200 OK to INVITE
/// 6. Alice sends ACK
///
/// PRACK ensures reliable delivery of provisional responses, which is critical for:
/// - Early media (SDP in 183 Session Progress)
/// - QoS preconditions (ensuring media path before ringing)
/// - Reliable progress indication
use sip_core::SipUri;
use sip_uac::UserAgentClient;

fn main() {
    println!("=== PRACK (Provisional Response Acknowledgement) Example (RFC 3262) ===\n");

    // Setup: Alice wants to call Bob with reliable provisionals
    println!("--- Setup ---");
    println!("Alice wants to establish a call with Bob");
    println!("Alice requires reliable provisional responses for early media");
    println!();

    // Step 1: Alice creates INVITE with Supported: 100rel
    println!("--- Step 1: Alice Sends INVITE ---");

    let alice_uri = SipUri::parse("sip:alice@example.com").expect("valid Alice URI");
    let alice_contact = SipUri::parse("sip:alice@192.168.1.100:5060").expect("valid Alice contact");

    let alice_uac = UserAgentClient::new(alice_uri.clone(), alice_contact.clone())
        .with_display_name("Alice Smith".to_string());

    let bob_uri = SipUri::parse("sip:bob@example.com").expect("valid Bob URI");
    let invite_request = alice_uac.create_invite(
        &bob_uri,
        Some("v=0\r\no=- 123 456 IN IP4 192.168.1.100\r\n"),
    );

    println!("INVITE sip:bob@example.com SIP/2.0");
    println!("From: {}", invite_request.headers.get("From").unwrap());
    println!("To: <sip:bob@example.com>");
    println!("Supported: 100rel");
    println!("Content-Type: application/sdp");
    println!();
    println!("Note: Supported: 100rel indicates Alice can handle reliable provisionals");

    // Step 2: Bob sends 100 Trying (non-reliable)
    println!("\n--- Step 2: Bob Sends 100 Trying ---");
    println!("SIP/2.0 100 Trying");
    println!();
    println!("Note: 100 Trying is never sent reliably (RFC 3262 §3)");

    // Step 3: Bob sends 180 Ringing with RSeq (reliable provisional)
    println!("\n--- Step 3: Bob Sends Reliable 180 Ringing ---");
    println!("SIP/2.0 180 Ringing");
    println!("RSeq: 1");
    println!("Require: 100rel");
    println!("Contact: <sip:bob@192.168.1.200:5060>");
    println!("To: <sip:bob@example.com>;tag=bob-tag-123");
    println!();
    println!("Note: RSeq header makes this response reliable");
    println!("      Require: 100rel means PRACK is mandatory");
    println!("      Bob will retransmit until Alice sends PRACK");

    // Mock early dialog from 180 response
    use bytes::Bytes;
    use sip_core::{Headers, Response, StatusLine};
    use smol_str::SmolStr;

    let mut ringing_headers = Headers::new();
    ringing_headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
    );
    ringing_headers.push(
        SmolStr::new("From"),
        invite_request.headers.get("From").unwrap().clone(),
    );
    ringing_headers.push(
        SmolStr::new("To"),
        SmolStr::new("<sip:bob@example.com>;tag=bob-tag-123"),
    );
    ringing_headers.push(
        SmolStr::new("Call-ID"),
        invite_request.headers.get("Call-ID").unwrap().clone(),
    );
    ringing_headers.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"));
    ringing_headers.push(SmolStr::new("RSeq"), SmolStr::new("1"));
    ringing_headers.push(
        SmolStr::new("Contact"),
        SmolStr::new("<sip:bob@192.168.1.200:5060>"),
    );
    ringing_headers.push(SmolStr::new("Require"), SmolStr::new("100rel"));

    let ringing_response = Response::new(
        StatusLine::new(180, SmolStr::new("Ringing")),
        ringing_headers,
        Bytes::new(),
    );

    // Alice creates early dialog from 180 response
    let early_dialog = alice_uac
        .process_invite_response(&invite_request, &ringing_response)
        .expect("early dialog");

    println!("Alice creates early dialog from 180 response");
    println!("  State: {:?}", early_dialog.state);
    println!("  Remote tag: {}", early_dialog.id.remote_tag.as_str());

    // Step 4: Alice sends PRACK
    println!("\n--- Step 4: Alice Sends PRACK ---");
    let prack_request = alice_uac
        .create_prack(&invite_request, &ringing_response, &early_dialog)
        .expect("PRACK request");

    println!("PRACK sip:bob@192.168.1.200:5060 SIP/2.0");
    println!("From: {}", prack_request.headers.get("From").unwrap());
    println!("To: {}", prack_request.headers.get("To").unwrap());
    println!("Call-ID: {}", prack_request.headers.get("Call-ID").unwrap());
    println!("CSeq: {}", prack_request.headers.get("CSeq").unwrap());
    println!("RAck: {}", prack_request.headers.get("RAck").unwrap());
    println!();
    println!("RAck header breakdown: RSeq CSeq-number Method");
    println!("  RSeq: 1 (from 180 response)");
    println!("  CSeq-number: 1 (from original INVITE)");
    println!("  Method: INVITE");
    println!();
    println!("Note: PRACK acknowledges the 180 response");
    println!("      Bob can now stop retransmitting the 180");

    // Step 5: Bob sends 200 OK to PRACK
    println!("\n--- Step 5: Bob Sends 200 OK to PRACK ---");
    println!("SIP/2.0 200 OK");
    println!("CSeq: 2 PRACK");
    println!();
    println!("Note: PRACK transaction complete");

    // Step 6: Bob could send more reliable provisionals (e.g., 183 Session Progress)
    println!("--- Step 6: Optional Additional Reliable Provisionals ---");
    println!("Bob could send 183 Session Progress with RSeq: 2");
    println!("  This would include SDP for early media");
    println!("  Alice would send another PRACK with RAck: 2 1 INVITE");
    println!("  Useful for:");
    println!("    - Announcements before ringing");
    println!("    - Music on hold");
    println!("    - IVR prompts");
    println!();

    // Step 7: Bob finally answers
    println!("--- Step 7: Bob Sends Final 200 OK to INVITE ---");
    println!("SIP/2.0 200 OK");
    println!("CSeq: 1 INVITE");
    println!("Contact: <sip:bob@192.168.1.200:5060>");
    println!("Content-Type: application/sdp");
    println!();
    println!("Note: This is the final response, not reliable");
    println!("      Alice will send ACK (not PRACK)");

    // Step 8: Alice sends ACK
    println!("\n--- Step 8: Alice Sends ACK ---");
    println!("ACK sip:bob@192.168.1.200:5060 SIP/2.0");
    println!();
    println!("Call established!");

    println!("\n=== Key Concepts ===\n");

    println!("RSeq (Reliable Sequence Number):");
    println!("  - Starts at 1 for each dialog");
    println!("  - Increments for each reliable provisional");
    println!("  - Separate from CSeq sequence space");
    println!("  - Enables detection of lost/duplicate provisionals");
    println!();

    println!("RAck (Reliable Acknowledgement):");
    println!("  - Format: RSeq CSeq-number Method");
    println!("  - Acknowledges a specific reliable provisional");
    println!("  - MUST match the provisional being acknowledged");
    println!();

    println!("Require vs Supported:");
    println!("  - Supported: 100rel (UAC capability)");
    println!("  - Require: 100rel (UAS mandate)");
    println!("  - If UAC doesn't support, UAS gets 420 Bad Extension");
    println!();

    println!("Retransmission:");
    println!("  - UAS retransmits reliable provisional until PRACK received");
    println!("  - Uses Timer T1/T2 (like INVITE transaction)");
    println!("  - PRACK stops retransmission");
    println!();

    println!("When to Use PRACK:");
    println!("  - Early media (SDP in 183 Session Progress)");
    println!("  - QoS preconditions (IMS networks)");
    println!("  - Critical progress indication");
    println!("  - Guaranteed delivery of provisional info");
    println!();

    println!("Differences from Regular Provisionals:");
    println!();
    println!("Regular Provisionals (180 without RSeq):");
    println!("  - Best-effort delivery");
    println!("  - No acknowledgement");
    println!("  - Can be lost without detection");
    println!("  - No retransmission");
    println!();

    println!("Reliable Provisionals (180 with RSeq):");
    println!("  - Guaranteed delivery");
    println!("  - Requires PRACK acknowledgement");
    println!("  - Lost responses are retransmitted");
    println!("  - Sequence number prevents duplicates");
    println!();

    println!("Common Use Cases:");
    println!("  - IMS (IP Multimedia Subsystem) networks");
    println!("  - QoS reservation before call setup");
    println!("  - Early media (ringback tones, announcements)");
    println!("  - Multi-stage call setup with user feedback");
    println!("  - Gateway scenarios requiring reliable signaling");

    println!("\n=== Example Complete ===");
}
