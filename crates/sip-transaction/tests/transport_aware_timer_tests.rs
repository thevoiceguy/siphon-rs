//! Integration tests for transport-aware timers per RFC 3261 §17.
//!
//! Validates that timer values are correctly adjusted based on transport type:
//! - UDP: Full timer values with retransmissions
//! - TCP/TLS: Zero wait times, no retransmissions

use sip_transaction::timers::{Transport, TransportAwareTimers};
use sip_transaction::TransactionTimer;
use std::time::Duration;

#[test]
fn timer_k_transport_aware() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);
    let tls = TransportAwareTimers::new(Transport::Tls);

    // Timer K: Wait time after non-INVITE client transaction completes
    // UDP: T4 (5 seconds) - wait for response retransmissions
    // TCP/TLS: 0 seconds - reliable transport, no retransmissions expected
    assert_eq!(
        udp.duration(TransactionTimer::K),
        Duration::from_secs(5),
        "Timer K should be T4 (5s) for UDP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::K),
        Duration::ZERO,
        "Timer K should be 0 for TCP (no wait needed)"
    );
    assert_eq!(
        tls.duration(TransactionTimer::K),
        Duration::ZERO,
        "Timer K should be 0 for TLS (no wait needed)"
    );
}

#[test]
fn timer_j_transport_aware() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // Timer J: Wait time for server non-INVITE transaction after sending final response
    // UDP: 64*T1 (32 seconds) - absorb retransmitted requests
    // TCP/TLS: 0 seconds - reliable transport guarantees delivery
    assert_eq!(
        udp.duration(TransactionTimer::J),
        Duration::from_secs(32),
        "Timer J should be 64*T1 (32s) for UDP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::J),
        Duration::ZERO,
        "Timer J should be 0 for TCP (reliable delivery)"
    );
}

#[test]
fn timer_i_transport_aware() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // Timer I: Wait time for ACK retransmissions after sending non-2xx final to INVITE
    // UDP: T4 (5 seconds) - wait for ACK retransmissions
    // TCP/TLS: 0 seconds - ACK sent once over reliable transport
    assert_eq!(
        udp.duration(TransactionTimer::I),
        Duration::from_secs(5),
        "Timer I should be T4 (5s) for UDP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::I),
        Duration::ZERO,
        "Timer I should be 0 for TCP (ACK sent once)"
    );
}

#[test]
fn retransmission_timers_zero_for_reliable() {
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // Retransmission timers should be 0 for reliable transports
    // Timer A: INVITE retransmission for client
    // Timer E: Non-INVITE retransmission for client
    // Timer G: INVITE retransmission for server
    assert_eq!(
        tcp.duration(TransactionTimer::A),
        Duration::ZERO,
        "Timer A (INVITE retransmit) should be 0 for TCP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::E),
        Duration::ZERO,
        "Timer E (non-INVITE retransmit) should be 0 for TCP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::G),
        Duration::ZERO,
        "Timer G (server INVITE retransmit) should be 0 for TCP"
    );
}

#[test]
fn retransmission_timers_active_for_udp() {
    let udp = TransportAwareTimers::new(Transport::Udp);

    // Retransmission timers should have values for UDP
    assert_eq!(
        udp.duration(TransactionTimer::A),
        Duration::from_millis(500),
        "Timer A should be T1 (500ms) for UDP"
    );
    assert_eq!(
        udp.duration(TransactionTimer::E),
        Duration::from_millis(500),
        "Timer E should be T1 (500ms) for UDP"
    );
    assert_eq!(
        udp.duration(TransactionTimer::G),
        Duration::from_millis(500),
        "Timer G should be T1 (500ms) for UDP"
    );
}

#[test]
fn timeout_timers_same_across_transports() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // Timeout timers (B, F, H) should be the same for all transports
    // These govern how long to wait for a response before giving up
    let timeout = Duration::from_secs(32); // 64*T1

    assert_eq!(
        udp.duration(TransactionTimer::B),
        timeout,
        "Timer B should be 64*T1 (32s) for UDP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::B),
        timeout,
        "Timer B should be 64*T1 (32s) for TCP"
    );

    assert_eq!(
        udp.duration(TransactionTimer::F),
        timeout,
        "Timer F should be 64*T1 (32s) for UDP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::F),
        timeout,
        "Timer F should be 64*T1 (32s) for TCP"
    );

    assert_eq!(
        udp.duration(TransactionTimer::H),
        timeout,
        "Timer H should be 64*T1 (32s) for UDP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::H),
        timeout,
        "Timer H should be 64*T1 (32s) for TCP"
    );
}

#[test]
fn should_retransmit_by_transport() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);
    let tls = TransportAwareTimers::new(Transport::Tls);

    assert!(
        udp.should_retransmit(),
        "UDP should require retransmissions"
    );
    assert!(
        !tcp.should_retransmit(),
        "TCP should not require retransmissions"
    );
    assert!(
        !tls.should_retransmit(),
        "TLS should not require retransmissions"
    );
}

#[test]
fn timer_d_transport_aware() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // Timer D: Wait time after receiving final response to INVITE (client)
    // UDP: 32 seconds (fixed per RFC, greater than T4 to absorb retransmissions)
    // TCP/TLS: 0 seconds (no retransmissions)
    assert_eq!(
        udp.duration(TransactionTimer::D),
        Duration::from_secs(32),
        "Timer D should be 32s for UDP"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::D),
        Duration::ZERO,
        "Timer D should be 0 for TCP"
    );
}

#[test]
fn udp_client_non_invite_transaction_lifecycle() {
    let timers = TransportAwareTimers::new(Transport::Udp);

    // Simulate client non-INVITE transaction over UDP
    // 1. Send request
    // 2. Start Timer E (retransmission) at T1
    // 3. Start Timer F (transaction timeout) at 64*T1
    let timer_e_initial = timers.duration(TransactionTimer::E);
    let timer_f = timers.duration(TransactionTimer::F);

    assert_eq!(timer_e_initial, Duration::from_millis(500));
    assert_eq!(timer_f, Duration::from_secs(32));

    // 4. Receive final response
    // 5. Cancel Timer E and F
    // 6. Start Timer K (wait time)
    let timer_k = timers.duration(TransactionTimer::K);
    assert_eq!(timer_k, Duration::from_secs(5));

    // 7. After Timer K fires → transaction terminates
    // Total time from response to termination: 5 seconds
}

#[test]
fn tcp_client_non_invite_transaction_lifecycle() {
    let timers = TransportAwareTimers::new(Transport::Tcp);

    // Simulate client non-INVITE transaction over TCP
    // 1. Send request (no retransmission timer needed)
    let timer_e = timers.duration(TransactionTimer::E);
    assert_eq!(timer_e, Duration::ZERO);

    // 2. Start Timer F (transaction timeout) at 64*T1
    let timer_f = timers.duration(TransactionTimer::F);
    assert_eq!(timer_f, Duration::from_secs(32));

    // 3. Receive final response
    // 4. Start Timer K (wait time)
    let timer_k = timers.duration(TransactionTimer::K);
    assert_eq!(timer_k, Duration::ZERO);

    // 5. Timer K fires immediately → transaction terminates
    // Total time from response to termination: 0 seconds (immediate)
    // This is the key benefit: TCP transactions complete instantly
}

#[test]
fn performance_comparison_udp_vs_tcp() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // Calculate total wait time for non-INVITE transaction after receiving final response
    let udp_wait = udp.duration(TransactionTimer::K);
    let tcp_wait = tcp.duration(TransactionTimer::K);

    // UDP requires 5 second wait, TCP completes immediately
    assert_eq!(udp_wait, Duration::from_secs(5));
    assert_eq!(tcp_wait, Duration::ZERO);

    println!("Performance benefit:");
    println!("  UDP transaction completion time: {:?}", udp_wait);
    println!("  TCP transaction completion time: {:?}", tcp_wait);
    println!("  Speedup: 5 seconds faster per transaction over TCP");
}

#[test]
fn server_invite_transaction_timers() {
    let udp = TransportAwareTimers::new(Transport::Udp);
    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // Server INVITE transaction after sending non-2xx final response

    // Timer G: Retransmit final response
    assert_eq!(
        udp.duration(TransactionTimer::G),
        Duration::from_millis(500)
    );
    assert_eq!(tcp.duration(TransactionTimer::G), Duration::ZERO);

    // Timer H: Wait for ACK
    assert_eq!(udp.duration(TransactionTimer::H), Duration::from_secs(32));
    assert_eq!(tcp.duration(TransactionTimer::H), Duration::from_secs(32));

    // Timer I: Wait after receiving ACK
    assert_eq!(udp.duration(TransactionTimer::I), Duration::from_secs(5));
    assert_eq!(tcp.duration(TransactionTimer::I), Duration::ZERO);
}

#[test]
fn rfc_3261_compliance_verification() {
    // Verify RFC 3261 §17.1.2.2 compliance

    let tcp = TransportAwareTimers::new(Transport::Tcp);

    // From RFC 3261 §17.1.2.2:
    // "For a reliable transport, Timer E MUST be set to 0, and Timer F MUST be
    //  set to 64*T1. For a reliable transport, Timer G MUST be set to 0, Timer H
    //  MUST be set to 64*T1, and Timer I MUST be set to 0."

    assert_eq!(
        tcp.duration(TransactionTimer::E),
        Duration::ZERO,
        "RFC 3261 §17.1.2.2: Timer E MUST be 0 for reliable transport"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::F),
        Duration::from_secs(32),
        "RFC 3261 §17.1.2.2: Timer F MUST be 64*T1 for reliable transport"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::G),
        Duration::ZERO,
        "RFC 3261 §17.1.2.2: Timer G MUST be 0 for reliable transport"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::H),
        Duration::from_secs(32),
        "RFC 3261 §17.1.2.2: Timer H MUST be 64*T1 for reliable transport"
    );
    assert_eq!(
        tcp.duration(TransactionTimer::I),
        Duration::ZERO,
        "RFC 3261 §17.1.2.2: Timer I MUST be 0 for reliable transport"
    );
}
