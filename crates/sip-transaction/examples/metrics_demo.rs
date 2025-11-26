//! Demonstration of transaction performance metrics.
//!
//! Shows how to collect and analyze transaction performance metrics
//! including durations, timer behavior, and success rates by transport.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example metrics_demo
//! ```

use sip_transaction::metrics::{TransactionMetrics, TransactionOutcome, TransportType};
use sip_transaction::TransactionTimer;
use std::time::Duration;

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║   SIP Transaction Performance Metrics Demo          ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    demonstrate_basic_metrics();
    demonstrate_transport_comparison();
    demonstrate_timer_tracking();
    demonstrate_outcome_tracking();
}

fn demonstrate_basic_metrics() {
    println!("═══ Basic Metrics Collection ═══\n");

    let metrics = TransactionMetrics::new();

    // Simulate some transactions
    metrics.record_transaction_duration(
        TransportType::Udp,
        "INVITE",
        Duration::from_millis(5200),  // UDP: includes retransmissions
    );
    metrics.record_transaction_duration(
        TransportType::Tcp,
        "INVITE",
        Duration::from_millis(250),  // TCP: much faster
    );
    metrics.record_transaction_duration(
        TransportType::Udp,
        "REGISTER",
        Duration::from_millis(6100),
    );
    metrics.record_transaction_duration(
        TransportType::Tcp,
        "REGISTER",
        Duration::from_millis(180),
    );

    // Query individual averages
    if let Some(avg_udp) = metrics.avg_duration_for_transport(TransportType::Udp) {
        println!("Average UDP transaction:  {:?}", avg_udp);
    }
    if let Some(avg_tcp) = metrics.avg_duration_for_transport(TransportType::Tcp) {
        println!("Average TCP transaction:  {:?}", avg_tcp);
    }

    println!("Total transactions: {}\n", metrics.total_transactions());
}

fn demonstrate_transport_comparison() {
    println!("═══ Transport Performance Comparison ═══\n");

    let metrics = TransactionMetrics::new();

    // Simulate UDP transactions (with retransmissions and wait times)
    for i in 0..10 {
        let duration = Duration::from_millis(5000 + (i * 100));  // 5-6 seconds
        metrics.record_transaction_duration(TransportType::Udp, "OPTIONS", duration);
        metrics.record_transaction_outcome(TransportType::Udp, TransactionOutcome::Completed);
    }

    // Simulate TCP transactions (immediate completion)
    for i in 0..10 {
        let duration = Duration::from_millis(150 + (i * 10));  // 150-250ms
        metrics.record_transaction_duration(TransportType::Tcp, "OPTIONS", duration);
        metrics.record_transaction_outcome(TransportType::Tcp, TransactionOutcome::Completed);
    }

    let snapshot = metrics.snapshot();

    println!("┌────────────┬───────────┬─────────────┬─────────────┬─────────────┐");
    println!("│ Transport  │ Count     │ Avg         │ Min         │ Max         │");
    println!("├────────────┼───────────┼─────────────┼─────────────┼─────────────┤");

    for (transport, stats) in &snapshot.by_transport {
        println!(
            "│ {:10} │ {:9} │ {:11?} │ {:11?} │ {:11?} │",
            format!("{:?}", transport),
            stats.count,
            stats.avg_duration,
            stats.min_duration.unwrap_or(Duration::ZERO),
            stats.max_duration.unwrap_or(Duration::ZERO),
        );
    }

    println!("└────────────┴───────────┴─────────────┴─────────────┴─────────────┘\n");

    // Calculate speedup
    if let (Some(udp_stats), Some(tcp_stats)) = (
        snapshot.by_transport.get(&TransportType::Udp),
        snapshot.by_transport.get(&TransportType::Tcp),
    ) {
        let speedup = udp_stats.avg_duration.as_secs_f64() / tcp_stats.avg_duration.as_secs_f64();
        println!("TCP is {:.1}x faster than UDP for OPTIONS transactions\n", speedup);
    }
}

fn demonstrate_timer_tracking() {
    println!("═══ Timer Fire Count Tracking ═══\n");

    let metrics = TransactionMetrics::new();

    // Simulate timer firings
    metrics.record_timer_fired(TransactionTimer::E);  // Retransmission
    metrics.record_timer_fired(TransactionTimer::E);
    metrics.record_timer_fired(TransactionTimer::E);
    metrics.record_timer_fired(TransactionTimer::K);  // Wait complete
    metrics.record_timer_fired(TransactionTimer::K);
    metrics.record_timer_fired(TransactionTimer::F);  // Timeout

    let snapshot = metrics.snapshot();

    println!("Timer Firing Statistics:");
    println!("┌────────────────────────────────┬─────────────────┐");
    println!("│ Timer                          │ Fire Count      │");
    println!("├────────────────────────────────┼─────────────────┤");

    let timers_to_show = [
        (TransactionTimer::E, "E (retransmit)"),
        (TransactionTimer::F, "F (timeout)"),
        (TransactionTimer::K, "K (wait complete)"),
        (TransactionTimer::A, "A (INVITE retrans)"),
        (TransactionTimer::B, "B (INVITE timeout)"),
    ];

    for (timer, name) in timers_to_show {
        let count = snapshot.timer_stats.get(&timer)
            .map(|s| s.fire_count)
            .unwrap_or(0);
        println!("│ {:<30} │ {:>15} │", name, count);
    }

    println!("└────────────────────────────────┴─────────────────┘\n");

    println!("Interpretation:");
    println!("  • Timer E fired 3 times: 3 retransmissions occurred (UDP)");
    println!("  • Timer K fired 2 times: 2 transactions completed normally");
    println!("  • Timer F fired 1 time: 1 transaction timed out\n");
}

fn demonstrate_outcome_tracking() {
    println!("═══ Transaction Outcome Tracking ═══\n");

    let metrics = TransactionMetrics::new();

    // Simulate various outcomes
    for _ in 0..15 {
        metrics.record_transaction_duration(TransportType::Tcp, "INVITE", Duration::from_millis(200));
        metrics.record_transaction_outcome(TransportType::Tcp, TransactionOutcome::Completed);
    }
    for _ in 0..2 {
        metrics.record_transaction_duration(TransportType::Tcp, "INVITE", Duration::from_secs(33));
        metrics.record_transaction_outcome(TransportType::Tcp, TransactionOutcome::Timeout);
    }
    for _ in 0..1 {
        metrics.record_transaction_duration(TransportType::Tcp, "INVITE", Duration::from_millis(50));
        metrics.record_transaction_outcome(TransportType::Tcp, TransactionOutcome::TransportError);
    }

    let snapshot = metrics.snapshot();

    if let Some(tcp_stats) = snapshot.by_transport.get(&TransportType::Tcp) {
        println!("TCP INVITE Transaction Outcomes:");
        println!("┌────────────────────────────┬────────────┬─────────────┐");
        println!("│ Outcome                    │ Count      │ Percentage  │");
        println!("├────────────────────────────┼────────────┼─────────────┤");

        let total = tcp_stats.count as f64;
        for (outcome, count) in &tcp_stats.outcomes {
            let percentage = (*count as f64 / total) * 100.0;
            println!(
                "│ {:<26} │ {:>10} │ {:>10.1}% │",
                format!("{:?}", outcome),
                count,
                percentage
            );
        }

        println!("└────────────────────────────┴────────────┴─────────────┘\n");

        let success_rate = tcp_stats.outcomes.get(&TransactionOutcome::Completed)
            .map(|c| (*c as f64 / total) * 100.0)
            .unwrap_or(0.0);

        println!("Success Rate: {:.1}%", success_rate);
        println!("Total Transactions: {}\n", tcp_stats.count);
    }
}
