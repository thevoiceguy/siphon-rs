//! PRACK and Session Timer Usage Examples
//!
//! Demonstrates:
//! - RFC 3262 PRACK (Provisional Response ACKnowledgement)
//! - RFC 4028 Session Timers with Min-SE negotiation
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example prack_and_session_timers
//! ```

use sip_core::{Headers, Method, Request, RequestLine, Response, StatusLine, SipUri};
use sip_dialog::prack_validator::{PrackValidator, RAck, is_reliable_provisional};
use sip_dialog::session_timer_manager::{
    SessionTimerManager, SessionTimerEvent, negotiate_session_expires,
    determine_refresher_role, MIN_SESSION_EXPIRES,
};
use sip_dialog::DialogId;
use bytes::Bytes;
use smol_str::SmolStr;
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║   PRACK and Session Timer Usage Examples                 ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    demonstrate_prack_flow().await;
    demonstrate_session_timer_negotiation();
    demonstrate_session_timer_refresh().await;
}

async fn demonstrate_prack_flow() {
    println!("═══ PRACK Flow (RFC 3262) ═══\n");

    println!("Scenario: INVITE with reliable 180 Ringing\n");

    let validator = PrackValidator::new();
    let dialog_id = "call-abc123";

    // Step 1: UAS sends 180 Ringing with RSeq
    println!("┌─ Step 1: UAS sends reliable provisional ─────────────────┐");
    println!("│ 180 Ringing                                               │");
    println!("│ RSeq: 1                                                   │");
    println!("│ Require: 100rel                                           │");
    println!("│ Contact: <sip:callee@192.168.1.100>                       │");
    println!("└───────────────────────────────────────────────────────────┘\n");

    // Register the reliable provisional
    validator.register_reliable_provisional(
        dialog_id,
        1,      // RSeq
        100,    // CSeq
        Method::Invite,
        180,    // Response code
    );

    println!("✓ Registered reliable provisional (RSeq=1)\n");

    // Step 2: UAC receives 180 and generates PRACK
    println!("┌─ Step 2: UAC generates PRACK ────────────────────────────┐");
    let rack = RAck {
        rseq: 1,
        cseq: 100,
        method: Method::Invite,
    };
    println!("│ PRACK sip:callee@192.168.1.100                            │");
    println!("│ RAck: {} {} {:?}                                        │", rack.rseq, rack.cseq, rack.method);
    println!("│ CSeq: 101 PRACK                                           │");
    println!("└───────────────────────────────────────────────────────────┘\n");

    // Create PRACK request
    let mut prack_headers = Headers::new();
    prack_headers.push(
        SmolStr::new("Call-ID"),
        SmolStr::new("call-abc123".to_owned())
    );
    prack_headers.push(
        SmolStr::new("CSeq"),
        SmolStr::new("101 PRACK".to_owned())
    );
    prack_headers.push(
        SmolStr::new("RAck"),
        SmolStr::new(rack.to_string())
    );

    let prack = Request::new(
        RequestLine::new(Method::Prack, SipUri::parse("sip:callee@192.168.1.100").unwrap()),
        prack_headers,
        Bytes::new(),
    );

    // Step 3: UAS validates PRACK
    println!("┌─ Step 3: UAS validates PRACK ────────────────────────────┐");
    match validator.validate_prack(dialog_id, &prack) {
        Ok(validated_rack) => {
            println!("│ ✓ PRACK is valid                                          │");
            println!("│   RSeq matches: {}                                          │", validated_rack.rseq);
            println!("│   CSeq matches: {}                                        │", validated_rack.cseq);
            println!("│   Method matches: {:?}                                   │", validated_rack.method);
            println!("└───────────────────────────────────────────────────────────┘\n");
        }
        Err(e) => {
            println!("│ ✗ PRACK validation failed: {}                             │", e);
            println!("└───────────────────────────────────────────────────────────┘\n");
        }
    }

    // Step 4: UAS sends 200 OK to PRACK
    println!("┌─ Step 4: UAS responds to PRACK ──────────────────────────┐");
    println!("│ 200 OK                                                    │");
    println!("│ CSeq: 101 PRACK                                           │");
    println!("└───────────────────────────────────────────────────────────┘\n");

    // Verify PRACK was marked as received
    assert!(validator.is_pracked(dialog_id, 1));
    println!("✓ PRACK tracking shows RSeq=1 has been acknowledged\n");

    // Attempt duplicate PRACK (should fail)
    println!("┌─ Edge Case: Duplicate PRACK ─────────────────────────────┐");
    match validator.validate_prack(dialog_id, &prack) {
        Ok(_) => println!("│ ✗ Duplicate PRACK incorrectly accepted                   │"),
        Err(e) => {
            println!("│ ✓ Duplicate PRACK correctly rejected                     │");
            println!("│   Error: {}                         │", e);
        }
    }
    println!("└───────────────────────────────────────────────────────────┘\n");

    // Check if response is reliable provisional
    println!("┌─ Helper: is_reliable_provisional() ──────────────────────┐");
    let mut reliable_headers = Headers::new();
    reliable_headers.push(SmolStr::new("RSeq"), SmolStr::new("1".to_owned()));
    let response_180 = Response::new(
        StatusLine::new(180, SmolStr::new("Ringing")),
        reliable_headers.clone(),
        Bytes::new(),
    );
    let response_100 = Response::new(
        StatusLine::new(100, SmolStr::new("Trying")),
        reliable_headers.clone(),
        Bytes::new(),
    );
    let response_200 = Response::new(
        StatusLine::new(200, SmolStr::new("OK")),
        reliable_headers,
        Bytes::new(),
    );

    println!("│ 180 Ringing with RSeq: {}                              │", is_reliable_provisional(&response_180));
    println!("│ 100 Trying with RSeq: {}                               │", is_reliable_provisional(&response_100));
    println!("│ 200 OK with RSeq: {}                                   │", is_reliable_provisional(&response_200));
    println!("│                                                           │");
    println!("│ Note: 100 Trying is NEVER reliable per RFC 3262 §3       │");
    println!("└───────────────────────────────────────────────────────────┘\n");
}

fn demonstrate_session_timer_negotiation() {
    println!("═══ Session Timer Negotiation (RFC 4028) ═══\n");

    println!("Scenario 1: UAC request accepted\n");
    println!("┌─ UAC Request ─────────────────────────────────────────────┐");
    println!("│ INVITE                                                    │");
    println!("│ Session-Expires: 1800                                     │");
    println!("│ Min-SE: 90                                                │");
    println!("│ Supported: timer                                          │");
    println!("└───────────────────────────────────────────────────────────┘\n");

    let result = negotiate_session_expires(
        Duration::from_secs(1800),  // Requested
        Duration::from_secs(90),    // Local Min-SE
        Some(Duration::from_secs(90)), // Remote Min-SE
        None,                       // No preference
    );

    println!("┌─ UAS Response ────────────────────────────────────────────┐");
    match result {
        Ok(negotiated) => {
            println!("│ 200 OK                                                    │");
            println!("│ Session-Expires: {};refresher=uac                       │", negotiated.as_secs());
            println!("│                                                           │");
            println!("│ ✓ UAC request accepted                                    │");
        }
        Err(min) => {
            println!("│ 422 Session Interval Too Small                            │");
            println!("│ Min-SE: {}                                                │", min.as_secs());
        }
    }
    println!("└───────────────────────────────────────────────────────────┘\n");

    println!("Scenario 2: UAC request too small (rejected)\n");
    println!("┌─ UAC Request ─────────────────────────────────────────────┐");
    println!("│ INVITE                                                    │");
    println!("│ Session-Expires: 60                                       │");
    println!("│ Min-SE: 60                                                │");
    println!("└───────────────────────────────────────────────────────────┘\n");

    let result = negotiate_session_expires(
        Duration::from_secs(60),    // Too small
        Duration::from_secs(90),    // Local Min-SE
        Some(Duration::from_secs(60)),
        None,
    );

    println!("┌─ UAS Response ────────────────────────────────────────────┐");
    match result {
        Ok(_) => println!("│ ✗ Should have been rejected                               │"),
        Err(min) => {
            println!("│ 422 Session Interval Too Small                            │");
            println!("│ Min-SE: {}                                                │", min.as_secs());
            println!("│                                                           │");
            println!("│ ✓ Correctly rejected (60s < 90s minimum)                  │");
        }
    }
    println!("└───────────────────────────────────────────────────────────┘\n");

    println!("Scenario 3: UAS applies preference\n");
    println!("┌─ UAC Request ─────────────────────────────────────────────┐");
    println!("│ INVITE                                                    │");
    println!("│ Session-Expires: 3600                                     │");
    println!("└───────────────────────────────────────────────────────────┘\n");

    let result = negotiate_session_expires(
        Duration::from_secs(3600),
        Duration::from_secs(90),
        None,
        Some(Duration::from_secs(1800)), // UAS prefers 30 min
    );

    println!("┌─ UAS Response ────────────────────────────────────────────┐");
    match result {
        Ok(negotiated) => {
            println!("│ 200 OK                                                    │");
            println!("│ Session-Expires: {};refresher=uac                      │", negotiated.as_secs());
            println!("│                                                           │");
            println!("│ ✓ UAS reduced from 3600s to preferred 1800s              │");
        }
        Err(_) => println!("│ ✗ Should have succeeded                                   │"),
    }
    println!("└───────────────────────────────────────────────────────────┘\n");

    // Refresher role determination
    println!("═══ Refresher Role Determination ═══\n");

    let scenarios = [
        (Some("uac"), true, true),   // UAC with refresher=uac → is refresher
        (Some("uac"), false, false), // UAS with refresher=uac → not refresher
        (Some("uas"), true, false),  // UAC with refresher=uas → not refresher
        (Some("uas"), false, true),  // UAS with refresher=uas → is refresher
        (None, true, true),          // UAC with no param → is refresher (default)
        (None, false, false),        // UAS with no param → not refresher (default)
    ];

    println!("┌─────────────────────┬───────────────┬─────────────────────┐");
    println!("│ Session-Expires     │ Perspective   │ Result              │");
    println!("├─────────────────────┼───────────────┼─────────────────────┤");
    for (param, is_uac, expected_is_refresher) in scenarios {
        let is_refresher = determine_refresher_role(param, is_uac);
        let param_str = param.unwrap_or("(none)");
        let perspective = if is_uac { "UAC" } else { "UAS" };
        println!("│ refresher={:<10} │ {:<13} │ {} │", param_str, perspective, if is_refresher { "✓ Refresher    " } else { "  Not refresher" });
        assert_eq!(is_refresher, expected_is_refresher, "Failed for param={:?}, is_uac={}", param, is_uac);
    }
    println!("└─────────────────────┴───────────────┴─────────────────────┘\n");

    println!("RFC 4028 Default: UAC is refresher if not specified\n");
}

async fn demonstrate_session_timer_refresh() {
    println!("═══ Session Timer Refresh Events ═══\n");

    let manager = SessionTimerManager::new();
    let dialog_id = DialogId::new("call-xyz789", "tag-uac", "tag-uas");

    println!("Starting session timer with 200ms expiration (for demo)\n");

    let mut events = manager.subscribe().await;

    // Start timer as refresher
    manager.start_timer(dialog_id.clone(), Duration::from_millis(200), true);

    println!("┌─ Session Timer Active ────────────────────────────────────┐");
    println!("│ Dialog: call-xyz789                                       │");
    println!("│ Session-Expires: 200ms (demo value)                      │");
    println!("│ Refresher: UAC                                            │");
    println!("│ Refresh at: 100ms (Session-Expires/2)                    │");
    println!("└───────────────────────────────────────────────────────────┘\n");

    // Wait for refresh event
    println!("Waiting for refresh event...\n");
    tokio::time::timeout(Duration::from_millis(150), async {
        if let Some(event) = events.recv().await {
            match event {
                SessionTimerEvent::RefreshNeeded(id) => {
                    println!("┌─ RefreshNeeded Event Fired ───────────────────────────────┐");
                    println!("│ Dialog: {}                            │", id.call_id.as_str());
                    println!("│ Time: ~100ms (Session-Expires/2)                          │");
                    println!("│                                                           │");
                    println!("│ Action: UAC should send session refresh                  │");
                    println!("│   Option 1: re-INVITE with SDP                            │");
                    println!("│   Option 2: UPDATE without SDP (RFC 3311)                │");
                    println!("│                                                           │");
                    println!("│ Example:                                                  │");
                    println!("│   UPDATE sip:callee@192.168.1.100                         │");
                    println!("│   Session-Expires: 1800;refresher=uac                    │");
                    println!("│   Supported: timer                                        │");
                    println!("└───────────────────────────────────────────────────────────┘\n");
                }
                _ => println!("Unexpected event\n"),
            }
        }
    }).await.expect("Should receive refresh event");

    // For demo, let expiration event fire too
    println!("Waiting for expiration event...\n");
    tokio::time::timeout(Duration::from_millis(150), async {
        if let Some(event) = events.recv().await {
            match event {
                SessionTimerEvent::SessionExpired(id) => {
                    println!("┌─ SessionExpired Event Fired ──────────────────────────────┐");
                    println!("│ Dialog: {}                            │", id.call_id.as_str());
                    println!("│ Time: ~200ms (Session-Expires)                            │");
                    println!("│                                                           │");
                    println!("│ Action: Session timed out - send BYE                      │");
                    println!("│   Reason: No refresh received in time                     │");
                    println!("│                                                           │");
                    println!("│ This prevents stuck dialogs from consuming resources      │");
                    println!("└───────────────────────────────────────────────────────────┘\n");
                }
                _ => println!("Unexpected event\n"),
            }
        }
    }).await.expect("Should receive expiration event");

    println!("═══ Summary ═══\n");
    println!("PRACK Benefits:");
    println!("  ✓ Reliable delivery of provisional responses");
    println!("  ✓ Early media with SDP in 183 Session Progress");
    println!("  ✓ QoS precondition support (IMS networks)");
    println!("  ✓ Duplicate detection via RSeq numbers\n");

    println!("Session Timer Benefits:");
    println!("  ✓ Prevents stuck dialogs (orphaned calls)");
    println!("  ✓ Min-SE negotiation ensures compatibility");
    println!("  ✓ Flexible refresh (re-INVITE or UPDATE)");
    println!("  ✓ Automatic cleanup on timeout\n");

    println!("Implementation:");
    println!("  • PRACK: {} constants", MIN_SESSION_EXPIRES.as_secs());
    println!("  • Default Session-Expires: 1800s (30 minutes)");
    println!("  • Min-SE: 90s (RFC 4028 minimum)");
    println!("  • Refresh at Session-Expires/2\n");
}
