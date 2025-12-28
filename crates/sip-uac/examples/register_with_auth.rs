// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Example demonstrating UAC REGISTER with Digest authentication.
///
/// This example shows how to:
/// 1. Create a UserAgentClient with credentials
/// 2. Send a REGISTER request
/// 3. Handle a 401 Unauthorized challenge
/// 4. Retry with authentication
use sip_core::SipUri;
use sip_uac::UserAgentClient;

fn main() {
    println!("=== UAC REGISTER with Authentication Example ===\n");

    // Step 1: Create a UAC with local and contact URIs
    let local_uri = SipUri::parse("sip:alice@example.com").expect("valid local URI");
    let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").expect("valid contact URI");

    let uac = UserAgentClient::new(local_uri, contact_uri).with_credentials("alice", "secret123");

    println!("Created UAC for alice@example.com");

    // Step 2: Create initial REGISTER request
    let registrar_uri = SipUri::parse("sip:example.com").expect("valid registrar URI");
    let register_request = uac.create_register(&registrar_uri, 3600);

    println!("\n--- Initial REGISTER Request ---");
    println!("Method: {:?}", register_request.method());
    println!("Request-URI: {}", register_request.uri().as_str());
    println!("From: {}", register_request.headers().get("From").unwrap());
    println!("To: {}", register_request.headers().get("To").unwrap());
    println!(
        "Contact: {}",
        register_request.headers().get("Contact").unwrap()
    );
    println!("CSeq: {}", register_request.headers().get("CSeq").unwrap());

    // Step 3: Simulate receiving 401 Unauthorized response
    println!("\n--- Simulating 401 Unauthorized Response ---");
    println!("WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\"");

    // In a real application, you would:
    // 1. Send the request via transport
    // 2. Receive the 401 response
    // 3. Parse the WWW-Authenticate header
    // 4. Call create_authenticated_request()

    // Example of creating an authenticated request:
    // let auth_request = uac.create_authenticated_request(&register_request, &challenge_response)?;

    println!("\n--- Authenticated REGISTER Request ---");
    println!("The authenticated request would include:");
    println!("- Same headers as original request");
    println!("- Authorization header with digest credentials");
    println!("- Incremented CSeq (from 1 to 2)");
    println!("- Same Call-ID for transaction correlation");

    println!("\nExample flow:");
    println!("1. UAC -> Registrar: REGISTER (CSeq: 1)");
    println!("2. Registrar -> UAC: 401 Unauthorized (WWW-Authenticate)");
    println!("3. UAC -> Registrar: REGISTER (CSeq: 2, Authorization)");
    println!("4. Registrar -> UAC: 200 OK (with Contact and expires)");

    println!("\n=== Example Complete ===");
}
