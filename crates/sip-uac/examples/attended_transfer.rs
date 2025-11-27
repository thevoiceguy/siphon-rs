/// Example demonstrating attended call transfer using REFER with Replaces (RFC 3515, RFC 3891).
///
/// Attended transfer scenario:
/// 1. Alice calls Bob (Call A: established)
/// 2. Bob puts Alice on hold
/// 3. Bob calls Charlie (Call B: established, consultation call)
/// 4. Bob sends REFER to Alice with Replaces header pointing to Call B
/// 5. Alice sends INVITE to Charlie with Replaces header
/// 6. Charlie's phone replaces Call B with new call to Alice
/// 7. Bob disconnects from both calls
///
/// Result: Alice and Charlie are connected, Bob is out of the picture.
///
/// This demonstrates attended transfer where the transferor (Bob) consults
/// with the transfer target (Charlie) before completing the transfer.
use sip_core::{RefresherRole, SipUri};
use sip_dialog::{
    Dialog, DialogId, DialogStateType, Subscription, SubscriptionId, SubscriptionState,
};
use sip_uac::UserAgentClient;
use std::time::Duration;

fn main() {
    println!("=== Attended Call Transfer Example (RFC 3515 + RFC 3891) ===\n");

    // Characters:
    // - Alice: Original caller (transferee)
    // - Bob: Transfer initiator (transferor)
    // - Charlie: Transfer target

    // Setup URIs
    let alice_uri = SipUri::parse("sip:alice@example.com").expect("valid Alice URI");
    let alice_contact = SipUri::parse("sip:alice@192.168.1.100:5060").expect("valid Alice contact");

    let bob_uri = SipUri::parse("sip:bob@example.com").expect("valid Bob URI");
    let bob_contact = SipUri::parse("sip:bob@192.168.1.200:5060").expect("valid Bob contact");

    let charlie_uri = SipUri::parse("sip:charlie@example.com").expect("valid Charlie URI");
    let charlie_contact =
        SipUri::parse("sip:charlie@192.168.1.150:5060").expect("valid Charlie contact");

    // Step 1: Call A - Alice calls Bob (established)
    println!("--- Step 1: Call A Established ---");
    println!("Alice <-> Bob: Active call");
    println!("Call-ID: call-alice-bob-123");
    println!("Alice's tag: alice-tag-111");
    println!("Bob's tag: bob-tag-222");
    println!();

    // Mock Call A dialog from Bob's perspective
    let dialog_a = Dialog {
        id: DialogId {
            call_id: "call-alice-bob-123".into(),
            local_tag: "bob-tag-222".into(),
            remote_tag: "alice-tag-111".into(),
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
        is_uac: false, // Bob is UAS (Alice called Bob)
    };

    // Step 2: Bob puts Alice on hold
    println!("--- Step 2: Bob Puts Alice On Hold ---");
    println!("Bob -> Alice: re-INVITE (sendonly SDP)");
    println!("Alice -> Bob: 200 OK");
    println!("Alice is now on hold (hearing music)");
    println!();

    // Step 3: Bob calls Charlie for consultation (Call B)
    println!("--- Step 3: Bob Calls Charlie (Consultation) ---");
    println!("Bob -> Charlie: INVITE");
    println!("Charlie -> Bob: 200 OK");
    println!("Bob <-> Charlie: Active call (Call B)");
    println!("Call-ID: call-bob-charlie-456");
    println!("Bob's tag: bob-tag-333");
    println!("Charlie's tag: charlie-tag-444");
    println!();

    let bob_uac = UserAgentClient::new(bob_uri.clone(), bob_contact.clone())
        .with_display_name("Bob Jones".to_string());

    // Mock Call B dialog from Bob's perspective
    let dialog_b = Dialog {
        id: DialogId {
            call_id: "call-bob-charlie-456".into(),
            local_tag: "bob-tag-333".into(),
            remote_tag: "charlie-tag-444".into(),
        },
        state: DialogStateType::Confirmed,
        local_uri: bob_uri.clone(),
        remote_uri: charlie_uri.clone(),
        remote_target: charlie_contact.clone(),
        local_cseq: 1,
        remote_cseq: 1,
        route_set: vec![],
        secure: false,
        session_expires: Some(Duration::from_secs(1800)),
        refresher: Some(RefresherRole::Uac),
        is_uac: true, // Bob is UAC (Bob called Charlie)
    };

    println!("Bob talks to Charlie: \"I have Alice on the line, can you take the call?\"");
    println!("Charlie: \"Yes, transfer her to me.\"");
    println!();

    // Step 4: Bob sends REFER to Alice with Replaces header
    println!("--- Step 4: Bob Sends REFER with Replaces ---");
    let refer_request = bob_uac.create_refer_with_replaces(&dialog_a, &charlie_uri, &dialog_b);

    println!("REFER sip:alice@192.168.1.100:5060 SIP/2.0");
    println!("From: {}", refer_request.headers.get("From").unwrap());
    println!("To: {}", refer_request.headers.get("To").unwrap());
    println!("Call-ID: {}", refer_request.headers.get("Call-ID").unwrap());
    println!("CSeq: {}", refer_request.headers.get("CSeq").unwrap());
    println!(
        "Refer-To: {}",
        refer_request.headers.get("Refer-To").unwrap()
    );
    println!();
    println!("Refer-To breakdown:");
    println!("  Target: sip:charlie@example.com");
    println!("  Replaces: call-bob-charlie-456;to-tag=charlie-tag-444;from-tag=bob-tag-333");
    println!();
    println!("Note: Replaces tells Alice which call to replace at Charlie's end");
    println!("      When Alice calls Charlie, Charlie will replace Call B with the new call");

    // Step 5: Alice accepts REFER
    println!("\n--- Step 5: Alice Accepts REFER ---");
    println!("SIP/2.0 202 Accepted");
    println!();

    // Step 6: Alice sends INVITE to Charlie with Replaces
    println!("--- Step 6: Alice Calls Charlie with Replaces ---");
    let alice_uac = UserAgentClient::new(alice_uri.clone(), alice_contact.clone());

    println!("Alice -> Charlie: INVITE sip:charlie@example.com");
    println!();
    println!("Key headers:");
    println!("  Replaces: call-bob-charlie-456;to-tag=charlie-tag-444;from-tag=bob-tag-333");
    println!("  Referred-By: <sip:bob@example.com>");
    println!();
    println!("Note: Replaces header tells Charlie's phone to:");
    println!("      1. Terminate Call B (Bob <-> Charlie)");
    println!("      2. Accept new call from Alice");
    println!("      3. Connect Alice and Charlie");

    // Step 7: Charlie accepts and replaces call
    println!("\n--- Step 7: Call Replacement ---");
    println!("Charlie's phone:");
    println!("  1. Validates Replaces header matches Call B");
    println!("  2. Sends BYE to Bob (ending Call B)");
    println!("  3. Sends 200 OK to Alice");
    println!();
    println!("Charlie -> Bob: BYE (Call B)");
    println!("Bob -> Charlie: 200 OK");
    println!();
    println!("Charlie -> Alice: 200 OK (new call)");
    println!("Alice -> Charlie: ACK");
    println!();

    // Step 8: Alice notifies Bob of transfer success
    println!("--- Step 8: Transfer Progress Notifications ---");

    // Mock subscription from REFER
    let subscription = Subscription {
        id: SubscriptionId {
            call_id: "call-alice-bob-123".into(),
            from_tag: "bob-tag-222".into(),
            to_tag: "alice-tag-111".into(),
            event: "refer".into(),
        },
        state: SubscriptionState::Active,
        local_uri: alice_uri.clone(),
        remote_uri: bob_uri.clone(),
        contact: bob_contact.clone(),
        expires: Duration::from_secs(300),
        local_cseq: 1,
        remote_cseq: 2,
    };

    println!("Alice -> Bob: NOTIFY (sipfrag: 100 Trying)");
    let _notify_100 = alice_uac.create_notify(
        &subscription,
        SubscriptionState::Active,
        Some("SIP/2.0 100 Trying\r\n"),
    );
    println!("Subscription-State: active");
    println!();

    println!("Alice -> Bob: NOTIFY (sipfrag: 180 Ringing)");
    let _notify_180 = alice_uac.create_notify(
        &subscription,
        SubscriptionState::Active,
        Some("SIP/2.0 180 Ringing\r\n"),
    );
    println!("Subscription-State: active");
    println!();

    println!("Alice -> Bob: NOTIFY (sipfrag: 200 OK)");
    let _notify_200 = alice_uac.create_notify(
        &subscription,
        SubscriptionState::Terminated,
        Some("SIP/2.0 200 OK\r\n"),
    );
    println!("Subscription-State: terminated;reason=noresource");
    println!();
    println!("Note: Subscription terminates - transfer successful");

    // Step 9: Bob hangs up Call A
    println!("\n--- Step 9: Bob Disconnects from Alice ---");
    println!("Bob -> Alice: BYE (Call A)");
    println!("Alice -> Bob: 200 OK");
    println!();

    println!("=== Final Result ===");
    println!("Alice <-> Charlie: Connected");
    println!("Bob: Disconnected from both calls");
    println!();

    println!("=== Key Differences: Attended vs Blind Transfer ===\n");

    println!("Attended Transfer (this example):");
    println!("  - Transferor consults with target before transfer");
    println!("  - Uses REFER with Replaces header");
    println!("  - Target knows transfer is coming");
    println!("  - More reliable (target confirmed availability)");
    println!("  - Two calls active during consultation");
    println!("  Replaces header format:");
    println!("    <target-uri?Replaces=call-id;to-tag=X;from-tag=Y>");
    println!();

    println!("Blind Transfer:");
    println!("  - No consultation with target");
    println!("  - Uses REFER without Replaces");
    println!("  - Target might not answer");
    println!("  - Faster but less reliable");
    println!("  - Only one call active");
    println!("  Refer-To format:");
    println!("    <target-uri>");
    println!();

    println!("=== RFC 3891 Replaces Header ===\n");

    println!("Purpose:");
    println!("  - Allows one dialog to replace another");
    println!("  - Essential for attended transfer");
    println!("  - Prevents multiple calls to same target");
    println!();

    println!("Components:");
    println!("  - Call-ID: Identifies the call to replace");
    println!("  - to-tag: Remote party's tag in call to be replaced");
    println!("  - from-tag: Local party's tag in call to be replaced");
    println!();

    println!("Security:");
    println!("  - Target MUST validate tags match existing dialog");
    println!("  - Prevents unauthorized call replacement");
    println!("  - MAY require authentication");
    println!();

    println!("Common Use Cases:");
    println!("  - Call center: Warm transfer to specialist");
    println!("  - Secretary: Screen call before transferring to boss");
    println!("  - Help desk: Consult with expert, then transfer");
    println!("  - Conference: Move participant between conferences");

    println!("\n=== Example Complete ===");
}
