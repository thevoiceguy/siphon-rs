// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Example demonstrating tel URI support per RFC 3966.
///
/// tel URIs represent telephone numbers and can be used in SIP signaling:
/// - Global numbers: E.164 format with '+' prefix (e.g., tel:+1-555-123-4567)
/// - Local numbers: Require phone-context parameter (e.g., tel:555-1234;phone-context=example.com)
///
/// This example shows:
/// 1. Creating INVITE requests with tel URIs in To/From headers
/// 2. Parsing and handling tel URIs
/// 3. Common use cases (PSTN gateway scenarios, mobile networks)
/// 4. Interoperability between SIP URIs and tel URIs
use sip_core::{SipUri, TelUri, Uri};
use sip_uac::UserAgentClient;

fn main() {
    println!("=== tel URI Support Example (RFC 3966) ===\n");

    // ========================================================================
    // Scenario 1: Mobile User Calling PSTN Number via SIP Gateway
    // ========================================================================

    println!("--- Scenario 1: Mobile User to PSTN Gateway ---");
    println!("Alice (mobile SIP client) wants to call Bob's landline +1-555-123-4567");
    println!("The SIP gateway will route the call to the PSTN\n");

    // Alice's identity as SIP URI
    let alice_uri = SipUri::parse("sip:alice@mobile.example.com").expect("valid Alice URI");
    let alice_contact = SipUri::parse("sip:alice@192.168.1.100:5060").expect("valid contact");

    let alice_uac = UserAgentClient::new(alice_uri.clone(), alice_contact.clone())
        .with_display_name("Alice Smith".to_string())
        .expect("valid display name");

    // Bob's phone number as tel URI
    let bob_tel_uri = TelUri::parse("tel:+1-555-123-4567").expect("valid tel URI");
    println!("Bob's tel URI: {}", bob_tel_uri.as_str());
    println!("  Normalized number: {}", bob_tel_uri.number());
    println!("  Is global (E.164): {}", bob_tel_uri.is_global());
    println!();

    // The Request-URI is the SIP gateway that will route to PSTN
    let gateway_uri = SipUri::parse("sip:gateway.example.com").expect("valid gateway URI");
    let invite_request = alice_uac.create_invite(
        &gateway_uri,
        Some("v=0\r\no=- 123 456 IN IP4 192.168.1.100\r\n"),
    );

    println!("INVITE sip:gateway.example.com SIP/2.0");
    println!("From: {}", invite_request.headers().get("From").unwrap());
    println!("To: <sip:gateway.example.com>");
    println!(
        "Call-ID: {}",
        invite_request.headers().get("Call-ID").unwrap()
    );
    println!();
    println!("Note: The Request-URI is the gateway, but the application logic");
    println!("      would include Bob's tel URI in routing headers or SDP");
    println!();

    // ========================================================================
    // Scenario 2: Visual Separator Handling
    // ========================================================================

    println!("\n--- Scenario 2: Visual Separator Normalization ---");
    println!("tel URIs allow visual separators for human readability");
    println!("These are automatically normalized per RFC 3966 §5.1.1\n");

    let variants = vec![
        "tel:+1-555-123-4567", // Hyphens
        "tel:+1.555.123.4567", // Dots
        "tel:+1 555 123 4567", // Spaces
        "tel:+1(555)123-4567", // Parentheses
    ];

    for variant in &variants {
        let tel_uri = TelUri::parse(variant).expect("valid tel URI");
        println!("Original:   {}", variant);
        println!("Normalized: {}", tel_uri.number());
        println!();
    }

    println!("All variants normalize to: +15551234567");
    println!("Visual separators are removed for dialing and comparison\n");

    // ========================================================================
    // Scenario 3: Local Numbers with phone-context
    // ========================================================================

    println!("\n--- Scenario 3: Local Numbers with phone-context ---");
    println!("Local tel URIs require phone-context parameter per RFC 3966 §5.1.4\n");

    // Valid local tel URI with phone-context
    let local_tel =
        TelUri::parse("tel:5551234;phone-context=example.com").expect("valid local tel URI");
    println!("Local tel URI: {}", local_tel.as_str());
    println!("  Number: {}", local_tel.number());
    println!("  Is global: {}", local_tel.is_global());
    println!("  Phone context: {}", local_tel.phone_context().unwrap());
    println!();

    // Invalid: local number without phone-context
    println!("Invalid: tel:5551234 (no phone-context)");
    let invalid_local = TelUri::parse("tel:5551234");
    println!("Parse result: {:?}", invalid_local);
    println!("RFC 3966 requires phone-context for local numbers\n");

    // ========================================================================
    // Scenario 4: tel URI with Extension Parameter
    // ========================================================================

    println!("\n--- Scenario 4: Extension Parameters ---");
    println!("tel URIs can include extension and other parameters\n");

    let tel_with_ext =
        TelUri::parse("tel:+1-555-123-4567;ext=1234").expect("valid tel URI with extension");
    println!("tel URI with extension: {}", tel_with_ext.as_str());
    println!("  Main number: {}", tel_with_ext.number());
    println!(
        "  Extension: {}",
        tel_with_ext
            .parameters()
            .get("ext")
            .unwrap()
            .as_ref()
            .unwrap()
            .as_str()
    );
    println!();

    // Other common parameters
    let tel_with_isub = TelUri::new("+15551234567", true)
        .unwrap()
        .with_parameter("isub", Some("9876"))
        .unwrap();

    println!("tel URI with ISDN subaddress: {}", tel_with_isub.as_str());
    println!(
        "  isub parameter: {}",
        tel_with_isub
            .parameters()
            .get("isub")
            .unwrap()
            .as_ref()
            .unwrap()
            .as_str()
    );
    println!();

    // ========================================================================
    // Scenario 5: Uri Enum - Unified Handling
    // ========================================================================

    println!("\n--- Scenario 5: Unified URI Handling ---");
    println!("The Uri enum allows seamless handling of both SIP and tel URIs\n");

    let uris = vec![
        Uri::parse("sip:alice@example.com").unwrap(),
        Uri::parse("tel:+1-555-123-4567").unwrap(),
        Uri::parse("sips:bob@secure.example.com").unwrap(),
        Uri::parse("tel:5551234;phone-context=example.com").unwrap(),
    ];

    for uri in &uris {
        print!("URI: {} ", uri.as_str());

        if uri.is_sip() {
            let sip = uri.as_sip().unwrap();
            println!("(SIP)");
            println!("  Scheme: {}", if sip.is_sips() { "sips" } else { "sip" });
            println!("  Host: {}", sip.host());
            if let Some(user) = sip.user() {
                println!("  User: {}", user);
            }
        } else if uri.is_tel() {
            let tel = uri.as_tel().unwrap();
            println!("(tel)");
            println!("  Number: {}", tel.number());
            println!(
                "  Type: {}",
                if tel.is_global() {
                    "Global (E.164)"
                } else {
                    "Local"
                }
            );
            if let Some(context) = tel.phone_context() {
                println!("  Context: {}", context);
            }
        }
        println!();
    }

    // ========================================================================
    // Scenario 6: Programmatic Construction
    // ========================================================================

    println!("\n--- Scenario 6: Programmatic URI Construction ---");
    println!("Building tel URIs programmatically with builder pattern\n");

    // Global tel URI
    let global_tel = TelUri::new("+15551234567", true).unwrap();
    println!("Global tel URI: {}", global_tel.as_str());

    // Local tel URI with phone-context
    let local_tel = TelUri::new("5551234", false)
        .unwrap()
        .with_phone_context("example.com")
        .unwrap();
    println!("Local tel URI: {}", local_tel.as_str());

    // tel URI with multiple parameters
    let complex_tel = TelUri::new("+15551234567", true)
        .unwrap()
        .with_parameter("ext", Some("1234"))
        .unwrap()
        .with_parameter("isub", Some("9876"))
        .unwrap();
    println!("Complex tel URI: {}", complex_tel.as_str());
    println!();

    // ========================================================================
    // Scenario 7: Common Use Cases
    // ========================================================================

    println!("\n--- Scenario 7: Common Use Cases ---\n");

    println!("1. PSTN Gateway Routing:");
    println!("   Request-URI: sip:gateway.pstn.net");
    println!("   To: <tel:+1-555-123-4567>");
    println!("   From: <sip:alice@example.com>");
    println!("   → Gateway converts SIP call to PSTN call");
    println!();

    println!("2. Mobile Network (IMS):");
    println!("   Request-URI: tel:+1-555-123-4567");
    println!("   To: <tel:+1-555-123-4567>");
    println!("   From: <tel:+1-555-987-6543>");
    println!("   → Native tel URI routing in mobile core");
    println!();

    println!("3. Enterprise PBX:");
    println!("   Request-URI: sip:pbx.company.com");
    println!("   To: <tel:1234;phone-context=company.com>");
    println!("   From: <sip:alice@company.com>");
    println!("   → Internal extension routing");
    println!();

    println!("4. Click-to-Call Web Application:");
    println!("   User clicks tel:+1-555-123-4567 link");
    println!("   Web app initiates SIP INVITE to gateway");
    println!("   Gateway connects to PSTN number");
    println!();

    // ========================================================================
    // Key Concepts Summary
    // ========================================================================

    println!("\n=== Key Concepts ===\n");

    println!("Global Numbers (E.164):");
    println!("  - Start with '+' followed by country code");
    println!("  - Example: +1-555-123-4567 (US), +44-20-7946-0958 (UK)");
    println!("  - MUST NOT include phone-context parameter");
    println!("  - Visual separators normalized for comparison");
    println!();

    println!("Local Numbers:");
    println!("  - Do not start with '+'");
    println!("  - Example: 5551234, 1234 (extension)");
    println!("  - MUST include phone-context parameter");
    println!("  - Context can be domain or global number");
    println!();

    println!("Visual Separators:");
    println!("  - Allowed: hyphen (-), dot (.), space, parentheses");
    println!("  - Removed during normalization for global numbers");
    println!("  - Purely for human readability (RFC 3966 §5.1.1)");
    println!();

    println!("Common Parameters:");
    println!("  - ext: Extension number");
    println!("  - isub: ISDN subaddress");
    println!("  - phone-context: Required for local numbers");
    println!("  - postd: Post-dial sequence (for tone dialing)");
    println!();

    println!("Interoperability:");
    println!("  - tel URIs can be used in SIP From/To/Contact headers");
    println!("  - Gateways convert between SIP and PSTN addressing");
    println!("  - IMS networks use tel URIs natively");
    println!("  - Enterprise PBXs use local tel URIs for extensions");
    println!();

    println!("Validation Rules:");
    println!("  - Global numbers: Must start with '+', no phone-context");
    println!("  - Local numbers: Must have phone-context");
    println!("  - Visual separators allowed in any position");
    println!("  - Parameters follow semicolon (;) separator");
    println!();

    println!("RFC References:");
    println!("  - RFC 3966: The tel URI for Telephone Numbers");
    println!("  - RFC 3261: SIP - Defines SIP URI format");
    println!("  - RFC 2806: Obsoleted by RFC 3966");
    println!("  - E.164: ITU-T international numbering plan");

    println!("\n=== Example Complete ===");
}
