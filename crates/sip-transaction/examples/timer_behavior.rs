//! RFC 3261 Transport-Aware Timer Behavior Examples
//!
//! Demonstrates how transaction timers behave differently based on transport type.
//!
//! ## Key Concepts
//!
//! - **Unreliable Transport (UDP)**: Requires retransmissions and wait times
//! - **Reliable Transport (TCP/TLS)**: No retransmissions, immediate completion
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example timer_behavior
//! ```

use sip_transaction::timers::{Transport, TransportAwareTimers, TimerDefaults};
use sip_transaction::TransactionTimer;
use std::time::Duration;

fn main() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║   RFC 3261 Transport-Aware Timer Behavior                ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    demonstrate_timer_differences();
    demonstrate_client_non_invite_flow();
    demonstrate_server_non_invite_flow();
    demonstrate_invite_transaction_flow();
    demonstrate_performance_benefits();
    demonstrate_custom_timer_values();
}

fn demonstrate_timer_differences() {
    println!("═══ Timer Value Comparison ═══\n");

    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);
    let tls = TransportAwareTimers::new(Transport::Tls);

    println!("Timer Values by Transport:\n");
    println!("┌─────────────┬─────────────┬─────────────┬─────────────┐");
    println!("│ Timer       │ UDP         │ TCP         │ TLS         │");
    println!("├─────────────┼─────────────┼─────────────┼─────────────┤");

    let timers = [
        (TransactionTimer::A, "A (retrans)"),
        (TransactionTimer::B, "B (timeout)"),
        (TransactionTimer::D, "D (wait)"),
        (TransactionTimer::E, "E (retrans)"),
        (TransactionTimer::F, "F (timeout)"),
        (TransactionTimer::K, "K (wait)"),
        (TransactionTimer::G, "G (retrans)"),
        (TransactionTimer::H, "H (timeout)"),
        (TransactionTimer::I, "I (wait)"),
        (TransactionTimer::J, "J (wait)"),
    ];

    for (timer, name) in timers {
        println!(
            "│ {:<11} │ {:>9.1?} │ {:>9.1?} │ {:>9.1?} │",
            name,
            udp.duration(timer),
            tcp.duration(timer),
            tls.duration(timer)
        );
    }

    println!("└─────────────┴─────────────┴─────────────┴─────────────┘\n");

    println!("Key Observations:");
    println!("  • Retransmission timers (A, E, G): 0 for TCP/TLS");
    println!("  • Wait timers (D, I, J, K): 0 for TCP/TLS");
    println!("  • Timeout timers (B, F, H): Same for all transports\n");
}

fn demonstrate_client_non_invite_flow() {
    println!("═══ Client Non-INVITE Transaction Flow ═══\n");

    println!("Scenario: Sending OPTIONS request\n");

    // UDP Flow
    println!("┌─ UDP Transaction ─────────────────────────────────────┐");
    let udp = TransportAwareTimers::new(Transport::Udp);

    println!("│ 1. Send OPTIONS request                               │");
    println!("│ 2. Start Timer E (retransmit): {:?}                 │", udp.duration(TransactionTimer::E));
    println!("│ 3. Start Timer F (timeout): {:?}                  │", udp.duration(TransactionTimer::F));
    println!("│ 4. Timer E fires → retransmit (then double interval) │");
    println!("│ 5. Receive 200 OK                                     │");
    println!("│ 6. Cancel Timers E and F                              │");
    println!("│ 7. Start Timer K (wait): {:?}                      │", udp.duration(TransactionTimer::K));
    println!("│ 8. Timer K fires → transaction terminates            │");
    println!("│                                                       │");
    println!("│ Total time after receiving response: 5 seconds       │");
    println!("└───────────────────────────────────────────────────────┘\n");

    // TCP Flow
    println!("┌─ TCP Transaction ─────────────────────────────────────┐");
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    println!("│ 1. Send OPTIONS request (once, no retransmission)    │");
    println!("│ 2. Timer E: {:?} (disabled)                        │", tcp.duration(TransactionTimer::E));
    println!("│ 3. Start Timer F (timeout): {:?}                  │", tcp.duration(TransactionTimer::F));
    println!("│ 4. Receive 200 OK                                     │");
    println!("│ 5. Cancel Timer F                                     │");
    println!("│ 6. Timer K: {:?} (immediate termination)           │", tcp.duration(TransactionTimer::K));
    println!("│                                                       │");
    println!("│ Total time after receiving response: 0 seconds       │");
    println!("│ ✓ 5 seconds faster than UDP!                          │");
    println!("└───────────────────────────────────────────────────────┘\n");
}

fn demonstrate_server_non_invite_flow() {
    println!("═══ Server Non-INVITE Transaction Flow ═══\n");

    println!("Scenario: Receiving and responding to OPTIONS\n");

    // UDP Flow
    println!("┌─ UDP Server Transaction ──────────────────────────────┐");
    let udp = TransportAwareTimers::new(Transport::Udp);

    println!("│ 1. Receive OPTIONS request                            │");
    println!("│ 2. Generate and send 200 OK                           │");
    println!("│ 3. Start Timer J (wait): {:?}                     │", udp.duration(TransactionTimer::J));
    println!("│ 4. If request retransmission arrives → retransmit OK │");
    println!("│ 5. Timer J fires after 32s → transaction terminates  │");
    println!("│                                                       │");
    println!("│ Transaction stays alive for: 32 seconds               │");
    println!("│ (to absorb retransmitted requests)                    │");
    println!("└───────────────────────────────────────────────────────┘\n");

    // TCP Flow
    println!("┌─ TCP Server Transaction ──────────────────────────────┐");
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    println!("│ 1. Receive OPTIONS request                            │");
    println!("│ 2. Generate and send 200 OK                           │");
    println!("│ 3. Timer J: {:?} (immediate termination)           │", tcp.duration(TransactionTimer::J));
    println!("│ 4. Transaction terminates immediately                 │");
    println!("│                                                       │");
    println!("│ Transaction stays alive for: 0 seconds                │");
    println!("│ ✓ No need to wait for retransmissions                 │");
    println!("└───────────────────────────────────────────────────────┘\n");
}

fn demonstrate_invite_transaction_flow() {
    println!("═══ INVITE Transaction Flow (Non-2xx Response) ═══\n");

    println!("Scenario: INVITE receives 486 Busy, then ACK\n");

    // Server side
    println!("┌─ Server INVITE Transaction (UDP) ─────────────────────┐");
    let udp = TransportAwareTimers::new(Transport::Udp);

    println!("│ 1. Receive INVITE                                      │");
    println!("│ 2. Send 100 Trying                                     │");
    println!("│ 3. Send 486 Busy Here (final response)                │");
    println!("│ 4. Start Timer G (retransmit): {:?}                 │", udp.duration(TransactionTimer::G));
    println!("│ 5. Start Timer H (ACK timeout): {:?}                │", udp.duration(TransactionTimer::H));
    println!("│ 6. Timer G fires → retransmit 486 (exponential)       │");
    println!("│ 7. Receive ACK                                         │");
    println!("│ 8. Cancel Timers G and H                               │");
    println!("│ 9. Start Timer I (wait): {:?}                       │", udp.duration(TransactionTimer::I));
    println!("│ 10. Timer I fires → transaction terminates            │");
    println!("│                                                        │");
    println!("│ Time from 486 to termination: 5+ seconds              │");
    println!("└────────────────────────────────────────────────────────┘\n");

    println!("┌─ Server INVITE Transaction (TCP) ─────────────────────┐");
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    println!("│ 1. Receive INVITE                                      │");
    println!("│ 2. Send 100 Trying                                     │");
    println!("│ 3. Send 486 Busy Here (sent once)                     │");
    println!("│ 4. Timer G: {:?} (no retransmission)              │", tcp.duration(TransactionTimer::G));
    println!("│ 5. Start Timer H (ACK timeout): {:?}                │", tcp.duration(TransactionTimer::H));
    println!("│ 6. Receive ACK                                         │");
    println!("│ 7. Cancel Timer H                                      │");
    println!("│ 8. Timer I: {:?} (immediate termination)            │", tcp.duration(TransactionTimer::I));
    println!("│                                                        │");
    println!("│ Time from 486 to termination: 0 seconds               │");
    println!("│ ✓ Much faster transaction completion!                 │");
    println!("└────────────────────────────────────────────────────────┘\n");
}

fn demonstrate_performance_benefits() {
    println!("═══ Performance Benefits of TCP/TLS ═══\n");

    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    println!("Wait Time Comparison (after receiving final response):\n");

    println!("Non-INVITE Transaction:");
    let udp_non_invite_wait = udp.duration(TransactionTimer::K);
    let tcp_non_invite_wait = tcp.duration(TransactionTimer::K);
    println!("  UDP: {:?}", udp_non_invite_wait);
    println!("  TCP: {:?}", tcp_non_invite_wait);
    println!("  Savings: {} seconds per transaction\n", udp_non_invite_wait.as_secs());

    println!("INVITE Transaction (server):");
    let udp_invite_wait = udp.duration(TransactionTimer::I);
    let tcp_invite_wait = tcp.duration(TransactionTimer::I);
    println!("  UDP: {:?}", udp_invite_wait);
    println!("  TCP: {:?}", tcp_invite_wait);
    println!("  Savings: {} seconds per call\n", udp_invite_wait.as_secs());

    println!("Server Non-INVITE Transaction:");
    let udp_server_wait = udp.duration(TransactionTimer::J);
    let tcp_server_wait = tcp.duration(TransactionTimer::J);
    println!("  UDP: {:?}", udp_server_wait);
    println!("  TCP: {:?}", tcp_server_wait);
    println!("  Savings: {} seconds per transaction\n", udp_server_wait.as_secs());

    println!("Real-World Impact:");
    println!("  • Call setup: 5+ seconds faster with TCP");
    println!("  • REGISTER: 5 seconds faster with TCP");
    println!("  • Call teardown (BYE): 5 seconds faster with TCP");
    println!("  • Lower memory usage (no timer tracking for K, J, I)");
    println!("  • Better scalability (transactions complete immediately)\n");
}

fn demonstrate_custom_timer_values() {
    println!("═══ Custom Timer Configuration ═══\n");

    // Default timers
    let default_tcp = TransportAwareTimers::new(Transport::Tcp);
    println!("Default Timer Values:");
    println!("  T1 (RTT estimate): {:?}", default_tcp.duration(TransactionTimer::T1));
    println!("  T2 (max retransmit interval): {:?}", default_tcp.duration(TransactionTimer::T2));
    println!("  T4 (max duration): {:?}", default_tcp.duration(TransactionTimer::T4));
    println!("  Timer F: {:?} (64*T1)\n", default_tcp.duration(TransactionTimer::F));

    // Custom timers for high-latency network
    let custom_defaults = TimerDefaults {
        t1: Duration::from_secs(1),   // Higher RTT estimate
        t2: Duration::from_secs(8),   // Higher max interval
        t4: Duration::from_secs(10),  // Longer wait time
    };
    let custom_tcp = TransportAwareTimers::with_defaults(Transport::Tcp, custom_defaults);

    println!("Custom Timer Values (high latency network):");
    println!("  T1: {:?}", custom_tcp.duration(TransactionTimer::T1));
    println!("  T2: {:?}", custom_tcp.duration(TransactionTimer::T2));
    println!("  T4: {:?}", custom_tcp.duration(TransactionTimer::T4));
    println!("  Timer F: {:?} (64*T1)\n", custom_tcp.duration(TransactionTimer::F));

    println!("Note: RFC 3261 requires T1 >= 500ms\n");
}
