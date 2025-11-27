//! Comprehensive call transfer example demonstrating blind and attended transfers.
//!
//! This example shows:
//! - Blind transfer using REFER (RFC 3515)
//! - Attended transfer using REFER with Replaces (RFC 3515 + RFC 3891)
//! - REFER subscription and NOTIFY progress reporting
//! - Multiple simultaneous calls and call leg management
//!
//! Scenario:
//! 1. Alice calls Bob
//! 2. Bob blind transfers Alice to Charlie
//! 3. Alice calls Bob again
//! 4. Bob calls Charlie (consultation call)
//! 5. Bob performs attended transfer (connects Alice to Charlie)
//!
//! Usage:
//! ```bash
//! cargo run --example call_transfer_scenario
//! ```

use anyhow::Result;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Call Transfer Scenarios Example ===\n");
    println!("This example demonstrates RFC 3515 (REFER) and RFC 3891 (Replaces)\n");

    println!("Simulating three participants:");
    println!("  • Alice: sip:alice@example.com");
    println!("  • Bob: sip:bob@example.com");
    println!("  • Charlie: sip:charlie@example.com\n");

    println!("In a real application, you would create IntegratedUAC for each:");
    println!("  let alice_uac = IntegratedUAC::builder()");
    println!("      .local_uri(\"sip:alice@example.com\")?");
    println!("      .local_addr(\"192.168.1.100:5060\")?");
    println!("      .transaction_manager(tx_mgr)");
    println!("      .resolver(resolver)");
    println!("      .dispatcher(dispatcher)");
    println!("      .credentials(\"alice\", \"secret123\")");
    println!("      .build()?;\n");

    // ==============================================
    // Scenario 1: Blind Transfer
    // ==============================================
    println!("\n╔══════════════════════════════════════════╗");
    println!("║  SCENARIO 1: BLIND TRANSFER (RFC 3515)  ║");
    println!("╚══════════════════════════════════════════╝\n");

    // Step 1: Alice calls Bob
    println!("Step 1: Alice → Bob (Initial Call)");
    println!("  Alice: Calling Bob...");
    let sdp = "v=0\r\no=- 100 0 IN IP4 192.168.1.100\r\ns=-\r\nc=IN IP4 192.168.1.100\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";

    sleep(Duration::from_millis(200)).await;
    println!("  Bob: ← INVITE from Alice");
    sleep(Duration::from_millis(100)).await;
    println!("  Bob: → 180 Ringing");
    sleep(Duration::from_millis(500)).await;
    println!("  Bob: → 200 OK");
    println!("  Alice: → ACK");
    println!("  ✓ Call established: Alice ↔ Bob\n");

    // Step 2: Bob decides to transfer Alice to Charlie (blind transfer)
    sleep(Duration::from_secs(2)).await;
    println!("Step 2: Bob performs BLIND TRANSFER (Alice → Charlie)");
    println!("  Bob: Sending REFER to Alice...");
    println!("        Refer-To: <sip:charlie@example.com>");
    println!("        (Alice should call Charlie)\n");

    sleep(Duration::from_millis(100)).await;
    println!("  Alice: ← REFER from Bob");
    println!("  Alice: Checking Refer-To header...");
    println!("         Target: sip:charlie@example.com");
    println!("  Alice: → 202 Accepted");
    println!("         (Creating implicit subscription for refer events)\n");

    // Step 3: Alice sends NOTIFY to report progress
    sleep(Duration::from_millis(200)).await;
    println!("Step 3: Alice reports transfer progress");
    println!("  Alice: → NOTIFY to Bob");
    println!("         Event: refer");
    println!("         Subscription-State: active");
    println!("         Content-Type: message/sipfrag");
    println!("         Body: SIP/2.0 100 Trying");
    println!("  Bob: ← NOTIFY (transfer attempt in progress)");
    println!("  Bob: → 200 OK\n");

    // Step 4: Alice calls Charlie
    sleep(Duration::from_millis(300)).await;
    println!("Step 4: Alice → Charlie (Transfer Target)");
    println!("  Alice: Initiating call to Charlie...");
    println!("         (As instructed by REFER)");
    sleep(Duration::from_millis(200)).await;
    println!("  Charlie: ← INVITE from Alice");
    sleep(Duration::from_millis(500)).await;
    println!("  Charlie: → 200 OK");
    println!("  Alice: → ACK");
    println!("  ✓ Transfer call established: Alice ↔ Charlie\n");

    // Step 5: Alice sends success NOTIFY
    sleep(Duration::from_millis(100)).await;
    println!("Step 5: Alice reports transfer success");
    println!("  Alice: → NOTIFY to Bob");
    println!("         Event: refer");
    println!("         Subscription-State: terminated;reason=noresource");
    println!("         Body: SIP/2.0 200 OK");
    println!("  Bob: ← NOTIFY (transfer successful!)");
    println!("  Bob: → 200 OK\n");

    // Step 6: Alice terminates original call with Bob
    sleep(Duration::from_millis(100)).await;
    println!("Step 6: Alice terminates original call with Bob");
    println!("  Alice: → BYE to Bob");
    println!("  Bob: ← BYE");
    println!("  Bob: → 200 OK");
    println!("  ✓ Original call terminated\n");

    sleep(Duration::from_millis(500)).await;
    println!("Result: Blind transfer complete!");
    println!("  Alice is now talking to Charlie (no longer Bob)");
    println!("  Bob's call with Alice is terminated");

    // ==============================================
    // Scenario 2: Attended Transfer
    // ==============================================
    sleep(Duration::from_secs(1)).await;
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║  SCENARIO 2: ATTENDED TRANSFER (RFC 3891)     ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Step 1: Alice calls Bob (again)
    println!("Step 1: Alice → Bob (New Call)");
    println!("  Alice: Calling Bob...");
    sleep(Duration::from_millis(500)).await;
    println!("  Bob: → 200 OK");
    println!("  Alice: → ACK");
    println!("  ✓ Call established: Alice ↔ Bob");
    println!("    Dialog: Call-ID=call-1, from-tag=alice-123, to-tag=bob-456\n");

    // Step 2: Bob puts Alice on hold and calls Charlie (consultation)
    sleep(Duration::from_secs(1)).await;
    println!("Step 2: Bob puts Alice on HOLD and calls Charlie (consultation)");
    println!("  Bob: → re-INVITE to Alice (sendonly SDP)");
    println!("  Alice: ← re-INVITE (on hold)");
    println!("  Alice: → 200 OK");
    println!("  Bob: → ACK");
    println!("  ✓ Alice is on hold\n");

    sleep(Duration::from_millis(300)).await;
    println!("  Bob: Calling Charlie for consultation...");
    sleep(Duration::from_millis(500)).await;
    println!("  Charlie: → 200 OK");
    println!("  Bob: → ACK");
    println!("  ✓ Consultation call established: Bob ↔ Charlie");
    println!("    Dialog: Call-ID=call-2, from-tag=bob-789, to-tag=charlie-321\n");

    // Step 3: Bob talks to Charlie to explain the transfer
    sleep(Duration::from_secs(1)).await;
    println!("Step 3: Bob explains situation to Charlie");
    println!("  Bob: 'Hey Charlie, Alice wants to talk to you about the project.'");
    println!("  Charlie: 'Sure, transfer her over.'\n");

    // Step 4: Bob performs attended transfer with Replaces
    sleep(Duration::from_millis(500)).await;
    println!("Step 4: Bob performs ATTENDED TRANSFER");
    println!("  Bob: Sending REFER to Alice with Replaces header...");
    println!("       Refer-To: <sip:charlie@example.com?");
    println!("                  Replaces=call-2%3Bfrom-tag%3Dbob-789%3Bto-tag%3Dcharlie-321>");
    println!("       (Alice should call Charlie and replace Bob's call)\n");

    sleep(Duration::from_millis(100)).await;
    println!("  Alice: ← REFER with Replaces from Bob");
    println!("  Alice: Parsing Replaces parameter...");
    println!("         Target call: Call-ID=call-2, from-tag=bob-789, to-tag=charlie-321");
    println!("  Alice: → 202 Accepted\n");

    // Step 5: Alice sends NOTIFY (trying)
    sleep(Duration::from_millis(100)).await;
    println!("Step 5: Alice reports transfer attempt");
    println!("  Alice: → NOTIFY to Bob (SIP/2.0 100 Trying)");
    println!("  Bob: → 200 OK\n");

    // Step 6: Alice calls Charlie with Replaces header
    sleep(Duration::from_millis(300)).await;
    println!("Step 6: Alice → Charlie with Replaces header");
    println!("  Alice: → INVITE to Charlie");
    println!("         Replaces: call-2;from-tag=bob-789;to-tag=charlie-321");
    println!("         (This INVITE will replace Charlie's call with Bob)");
    sleep(Duration::from_millis(200)).await;
    println!("  Charlie: ← INVITE with Replaces header");
    println!("  Charlie: Validating Replaces header...");
    println!("           - Call-ID matches active call with Bob ✓");
    println!("           - Tags match dialog identifiers ✓");
    println!("           - Dialog is in Confirmed state ✓");
    println!("  Charlie: → 200 OK (accepting transfer)");
    println!("  Alice: → ACK");
    println!("  ✓ Transfer call established: Alice ↔ Charlie\n");

    // Step 7: Charlie terminates call with Bob (being replaced)
    sleep(Duration::from_millis(100)).await;
    println!("Step 7: Charlie terminates replaced call with Bob");
    println!("  Charlie: → BYE to Bob (call being replaced)");
    println!("  Bob: ← BYE");
    println!("  Bob: → 200 OK");
    println!("  ✓ Consultation call terminated\n");

    // Step 8: Alice sends success NOTIFY
    sleep(Duration::from_millis(100)).await;
    println!("Step 8: Alice reports transfer success");
    println!("  Alice: → NOTIFY to Bob (SIP/2.0 200 OK)");
    println!("  Bob: → 200 OK\n");

    // Step 9: Alice terminates original call with Bob
    sleep(Duration::from_millis(100)).await;
    println!("Step 9: Alice terminates original call with Bob");
    println!("  Alice: → BYE to Bob");
    println!("  Bob: → 200 OK");
    println!("  ✓ Original call terminated\n");

    sleep(Duration::from_millis(500)).await;
    println!("Result: Attended transfer complete!");
    println!("  Alice is now talking to Charlie directly");
    println!("  Bob's calls are all terminated");
    println!("  Charlie's consultation call was replaced by transfer call");

    // Summary
    println!("\n╔═══════════════════════════════════════════════════════╗");
    println!("║                  EXAMPLE COMPLETE                     ║");
    println!("╚═══════════════════════════════════════════════════════╝\n");

    println!("This example demonstrated:\n");

    println!("Blind Transfer (RFC 3515):");
    println!("  ✓ REFER method to initiate transfer");
    println!("  ✓ Refer-To header with target URI");
    println!("  ✓ Implicit subscription to 'refer' event");
    println!("  ✓ NOTIFY with message/sipfrag progress reports");
    println!("  ✓ Transferee calls transfer target directly\n");

    println!("Attended Transfer (RFC 3515 + RFC 3891):");
    println!("  ✓ Consultation call establishment");
    println!("  ✓ REFER with Replaces header");
    println!("  ✓ URL-encoded Replaces parameters");
    println!("  ✓ Dialog matching and validation");
    println!("  ✓ Replacing existing call with transfer call");
    println!("  ✓ Automatic cleanup of consultation call\n");

    println!("Key Differences:");
    println!("  • Blind: Transferor doesn't talk to target first");
    println!("  • Attended: Transferor establishes consultation call");
    println!("  • Blind: Simple Refer-To with URI");
    println!("  • Attended: Refer-To includes Replaces parameter");
    println!("  • Attended: More reliable (target confirmed available)\n");

    println!("IntegratedUAC provides high-level methods for both scenarios!");
    println!("Use refer() for blind transfers and refer_with_replaces() for attended.");

    Ok(())
}
