// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Example demonstrating UAS handling INVITE requests.
///
/// This example shows how to:
/// 1. Create a UserAgentServer
/// 2. Handle an incoming INVITE request
/// 3. Send provisional responses (100 Trying, 180 Ringing)
/// 4. Accept or reject the call
/// 5. Handle BYE to terminate the dialog
use bytes::Bytes;
use sip_core::{Headers, Method, Request, RequestLine, SipUri};
use sip_uas::UserAgentServer;
use smol_str::SmolStr;

fn main() {
    println!("=== UAS INVITE Handler Example ===\n");

    // Step 1: Create a UAS
    let local_uri = SipUri::parse("sip:bob@example.com").expect("valid local URI");
    let contact_uri = SipUri::parse("sip:bob@192.168.1.200:5060").expect("valid contact URI");

    let uas = UserAgentServer::new(local_uri, contact_uri);

    println!("Created UAS for bob@example.com");

    // Step 2: Simulate receiving an INVITE request
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKnashds8"),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("\"Alice Smith\" <sip:alice@example.com>;tag=1928301774"),
    );
    headers.push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"));
    headers.push(
        SmolStr::new("Call-ID"),
        SmolStr::new("a84b4c76e66710@pc33.example.com"),
    );
    headers.push(SmolStr::new("CSeq"), SmolStr::new("314159 INVITE"));
    headers.push(
        SmolStr::new("Contact"),
        SmolStr::new("<sip:alice@192.168.1.100:5060>"),
    );
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
    headers.push(
        SmolStr::new("Content-Type"),
        SmolStr::new("application/sdp"),
    );

    let sdp_offer = "\
v=0
o=alice 123456 789012 IN IP4 192.168.1.100
s=Call to Bob
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0 8
";

    let invite_request = Request::new(
        RequestLine::new(
            Method::Invite,
            SipUri::parse("sip:bob@example.com").unwrap(),
        ),
        headers,
        Bytes::from(sdp_offer.as_bytes().to_vec()),
    );

    println!("\n--- Received INVITE Request ---");
    println!("From: {}", invite_request.headers.get("From").unwrap());
    println!("To: {}", invite_request.headers.get("To").unwrap());
    println!(
        "Call-ID: {}",
        invite_request.headers.get("Call-ID").unwrap()
    );
    println!("CSeq: {}", invite_request.headers.get("CSeq").unwrap());
    println!("SDP body length: {} bytes", invite_request.body.len());

    // Step 3: Send 100 Trying (immediately)
    let trying_response = UserAgentServer::create_trying(&invite_request);
    println!("\n--- Sending 100 Trying ---");
    println!(
        "Status: {} {}",
        trying_response.start.code, trying_response.start.reason
    );

    // Step 4: Send 180 Ringing (user is being alerted)
    let ringing_response = uas.create_ringing(&invite_request);
    println!("\n--- Sending 180 Ringing ---");
    println!(
        "Status: {} {}",
        ringing_response.start.code, ringing_response.start.reason
    );

    // Step 5: User accepts - send 200 OK with SDP answer
    let sdp_answer = "\
v=0
o=bob 234567 890123 IN IP4 192.168.1.200
s=Call accepted
c=IN IP4 192.168.1.200
t=0 0
m=audio 49172 RTP/AVP 0
a=rtpmap:0 PCMU/8000
";

    let result = uas.accept_invite(&invite_request, Some(sdp_answer));

    match result {
        Ok((response, dialog)) => {
            println!("\n--- Sending 200 OK (Call Accepted) ---");
            println!("Status: {} {}", response.start.code, response.start.reason);
            println!("Contact: {}", response.headers.get("Contact").unwrap());
            let to_header = response.headers.get("To").unwrap();
            println!("To: {} (tag added)", to_header);
            println!("Content-Type: application/sdp");
            println!("SDP body length: {} bytes", response.body.len());

            println!("\n--- Dialog Created ---");
            println!("Dialog ID:");
            println!("  Call-ID: {}", dialog.id.call_id);
            println!("  Local tag: {}", dialog.id.local_tag);
            println!("  Remote tag: {}", dialog.id.remote_tag);
            println!("Dialog state: {:?}", dialog.state);
            println!("Remote target: {}", dialog.remote_target.as_str());
        }
        Err(e) => {
            println!("Error accepting invite: {}", e);
        }
    }

    // Alternative: Reject the call
    println!("\n--- Alternative: Rejecting the Call ---");
    println!("If user is busy:");
    let busy_response = uas.create_busy(&invite_request);
    println!(
        "  {} {}",
        busy_response.start.code, busy_response.start.reason
    );

    println!("\nIf user declines:");
    let decline_response = uas.create_decline(&invite_request);
    println!(
        "  {} {}",
        decline_response.start.code, decline_response.start.reason
    );

    // Step 6: Later, handle BYE to terminate the call
    println!("\n--- Handling BYE Request ---");
    println!("When the remote party sends BYE:");
    println!("1. Verify BYE matches the dialog (Call-ID, tags)");
    println!("2. Remove dialog from DialogManager");
    println!("3. Send 200 OK response");
    println!("4. Clean up media session");

    // In a real application:
    // let bye_response = uas.handle_bye(&bye_request, &dialog)?;

    println!("\n=== Example Complete ===");
}
