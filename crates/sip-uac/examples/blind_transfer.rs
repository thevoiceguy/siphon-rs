/// Example demonstrating blind call transfer using REFER (RFC 3515).
///
/// Blind transfer scenario:
/// 1. Alice calls Bob (established call)
/// 2. Bob sends REFER to Alice, referring her to Charlie
/// 3. Alice accepts with 202 Accepted
/// 4. Alice sends INVITE to Charlie (new call)
/// 5. Alice sends NOTIFY to Bob with transfer progress
/// 6. When Charlie answers, Alice sends final NOTIFY to Bob
/// 7. Alice and Bob's original call typically ends
///
/// This demonstrates the transferor (Bob) initiating a blind transfer
/// to send the transferee (Alice) to a transfer target (Charlie).

use sip_core::SipUri;
use sip_uac::UserAgentClient;

fn main() {
    println!("=== Blind Call Transfer Example (RFC 3515) ===\n");

    // Setup: Alice and Bob have an established call
    println!("--- Initial Setup ---");
    println!("Alice <-> Bob: Active call in progress");
    println!();

    // Step 1: Bob decides to transfer Alice to Charlie
    println!("--- Step 1: Bob Initiates Transfer ---");
    println!("Bob wants to transfer Alice to Charlie");
    println!();

    // Create UAC for Bob
    let bob_uri = SipUri::parse("sip:bob@example.com").expect("valid Bob URI");
    let bob_contact = SipUri::parse("sip:bob@192.168.1.200:5060").expect("valid contact URI");

    let bob_uac = UserAgentClient::new(bob_uri.clone(), bob_contact.clone())
        .with_display_name("Bob Jones".to_string());

    // Bob has a dialog with Alice (from the original INVITE)
    // In a real application, this would be created from the INVITE/200 OK exchange
    println!("Bob's dialog with Alice:");
    println!("  Call-ID: call-abc-123");
    println!("  Bob's tag: bob-tag-456");
    println!("  Alice's tag: alice-tag-789");
    println!();

    // Mock dialog for demonstration (in real code, this comes from accept_invite)
    use sip_core::RefresherRole;
    use sip_dialog::{Dialog, DialogId, DialogStateType};
    use std::time::Duration;

    let alice_uri = SipUri::parse("sip:alice@example.com").expect("valid Alice URI");
    let alice_contact = SipUri::parse("sip:alice@192.168.1.100:5060").expect("valid contact");

    let dialog = Dialog {
        id: DialogId {
            call_id: "call-abc-123".into(),
            local_tag: "bob-tag-456".into(),
            remote_tag: "alice-tag-789".into(),
        },
        state: DialogStateType::Confirmed,
        local_uri: bob_uri.clone(),
        remote_uri: alice_uri.clone(),
        remote_target: alice_contact.clone(),
        local_cseq: 1,
        remote_cseq: 1,
        route_set: vec![],
        secure: false,
        session_expires: Some(Duration::from_secs(1800)),
        refresher: Some(RefresherRole::Uac),
        is_uac: false, // Bob is UAS in original call (Alice called Bob)
    };

    // Step 2: Bob creates REFER request to Alice
    println!("--- Step 2: Bob Sends REFER to Alice ---");
    let charlie_uri = SipUri::parse("sip:charlie@example.com").expect("valid Charlie URI");
    let refer_request = bob_uac.create_refer(&dialog, &charlie_uri);

    println!("REFER sip:alice@192.168.1.100:5060 SIP/2.0");
    println!("From: {}", refer_request.headers.get("From").unwrap());
    println!("To: {}", refer_request.headers.get("To").unwrap());
    println!("Call-ID: {}", refer_request.headers.get("Call-ID").unwrap());
    println!("CSeq: {}", refer_request.headers.get("CSeq").unwrap());
    println!("Refer-To: {}", refer_request.headers.get("Refer-To").unwrap());
    println!();
    println!("Note: REFER tells Alice to call Charlie");
    println!("      This creates an implicit subscription to 'refer' event");

    // Step 3: Alice accepts the REFER
    println!("\n--- Step 3: Alice Accepts REFER ---");
    println!("SIP/2.0 202 Accepted");
    println!("To: <sip:alice@example.com>;tag=alice-tag-789");
    println!("Contact: <sip:alice@192.168.1.100:5060>");
    println!();
    println!("Note: 202 means Alice accepted the transfer request");
    println!("      Alice now has an obligation to attempt the transfer");

    // Step 4: Alice sends INVITE to Charlie
    println!("\n--- Step 4: Alice Calls Charlie ---");
    println!("Alice -> Charlie: INVITE sip:charlie@example.com");
    println!();

    // Alice creates new INVITE to Charlie
    let alice_uac = UserAgentClient::new(alice_uri.clone(), alice_contact);
    let invite_to_charlie = alice_uac.create_invite(&charlie_uri, Some("v=0\r\no=- 123 456 IN IP4 192.168.1.100\r\n"));

    println!("INVITE sip:charlie@example.com SIP/2.0");
    println!("From: {}", invite_to_charlie.headers.get("From").unwrap());
    println!("To: <sip:charlie@example.com>");
    println!("Referred-By: <sip:bob@example.com>");
    println!();

    // Step 5: Alice sends progress NOTIFYs to Bob
    println!("--- Step 5: Progress Notifications ---");

    // Mock subscription created from REFER (implicit subscription)
    use sip_dialog::{Subscription, SubscriptionId, SubscriptionState};
    let subscription = Subscription {
        id: SubscriptionId {
            call_id: "call-abc-123".into(),
            from_tag: "bob-tag-456".into(),
            to_tag: "alice-tag-789".into(),
            event: "refer".into(),
        },
        state: SubscriptionState::Active,
        local_uri: alice_uri.clone(),
        remote_uri: bob_uri.clone(),
        contact: bob_contact.clone(),
        expires: Duration::from_secs(300),
        local_cseq: 1,
        remote_cseq: 2, // REFER was CSeq 2
    };

    // Alice sends NOTIFY with 100 Trying
    println!("Alice -> Bob: NOTIFY (sipfrag: 100 Trying)");
    let _notify_100 = alice_uac.create_notify(&subscription, SubscriptionState::Active, Some("SIP/2.0 100 Trying\r\n"));
    println!("Event: refer");
    println!("Subscription-State: active");
    println!("Content-Type: message/sipfrag;version=2.0");
    println!();
    println!("Body: SIP/2.0 100 Trying");
    println!();

    println!("Charlie -> Alice: 180 Ringing");
    println!();

    // Alice sends NOTIFY with 180 Ringing
    println!("Alice -> Bob: NOTIFY (sipfrag: 180 Ringing)");
    println!("Subscription-State: active");
    println!("Body: SIP/2.0 180 Ringing");
    println!();

    // Step 6: Charlie answers
    println!("--- Step 6: Transfer Complete ---");
    println!("Charlie -> Alice: 200 OK");
    println!();

    // Alice sends final NOTIFY with 200 OK
    println!("Alice -> Bob: NOTIFY (sipfrag: 200 OK)");
    let _notify_200 = alice_uac.create_notify(&subscription, SubscriptionState::Terminated, Some("SIP/2.0 200 OK\r\n"));
    println!("Event: refer");
    println!("Subscription-State: terminated;reason=noresource");
    println!("Content-Type: message/sipfrag;version=2.0");
    println!();
    println!("Body: SIP/2.0 200 OK");
    println!();
    println!("Note: Subscription terminates after final response (2xx/3xx)");

    // Step 7: Original call ends
    println!("--- Step 7: Original Call Ends ---");
    println!("Bob -> Alice: BYE");
    println!("Alice -> Bob: 200 OK");
    println!();
    println!("Result: Alice <-> Charlie (new call established)");
    println!("        Bob disconnected");

    println!("\n=== Key Points ===\n");

    println!("REFER Method:");
    println!("  - Requests recipient to initiate a new SIP request");
    println!("  - Creates implicit subscription to 'refer' event");
    println!("  - 202 Accepted means recipient will attempt the request");
    println!();

    println!("Blind Transfer:");
    println!("  - Transferor doesn't consult with transfer target first");
    println!("  - Transferor sends REFER, then typically hangs up");
    println!("  - Simpler but transfer target might not answer");
    println!();

    println!("NOTIFY Progress:");
    println!("  - Uses message/sipfrag body format");
    println!("  - Contains just the SIP status line (e.g., 'SIP/2.0 180 Ringing')");
    println!("  - Subscription terminates when final response received");
    println!("  - Keeps transferor informed of transfer progress");
    println!();

    println!("Common Use Cases:");
    println!("  - Call center: Agent transfers to another department");
    println!("  - Receptionist: Transfers incoming call to extension");
    println!("  - IVR system: Transfers to appropriate destination");
    println!("  - Mobile handoff: Device transfers call to another device");

    println!("\n=== Example Complete ===");
}
