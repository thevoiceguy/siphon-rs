//! Transport-aware timer calculations per RFC 3261 §17.
//!
//! SIP transaction timers must be adjusted based on the transport protocol:
//! - **Unreliable transports (UDP)**: Full timer values per RFC 3261 Table 4
//! - **Reliable transports (TCP/TLS)**: Certain timers are set to zero
//!
//! # Performance Impact
//!
//! Transport-aware timer optimization provides significant performance benefits:
//! - **TCP/TLS transactions complete 5-37 seconds faster** than UDP
//! - **Timer K**: 0 for TCP/TLS (vs 5s for UDP) - instant completion after final response
//! - **Timer J**: 0 for TCP/TLS (vs 32s for UDP) - no wait for response retransmissions
//! - **Timer I**: 0 for TCP/TLS (vs 5s for UDP) - instant ACK processing
//! - **Reduced memory**: No timer tracking needed for zero-duration timers
//! - **Better scalability**: Transactions terminate immediately on reliable transports
//!
//! # RFC 3261 §17.1.2.2 - Reliable Transport Timer Adjustments
//!
//! > For unreliable transports (such as UDP), requests are retransmitted at an
//! > exponentially increasing rate until a response is received or the request
//! > times out.  For reliable transports (such as TCP), the request is sent once.
//! >
//! > For a reliable transport, Timer E MUST be set to 0, and Timer F MUST be
//! > set to 64*T1.  For a reliable transport, Timer G MUST be set to 0, Timer H
//! > MUST be set to 64*T1, and Timer I MUST be set to 0.
//!
//! # Usage
//!
//! ```rust
//! use sip_transaction::timers::{Transport, TransportAwareTimers};
//! use sip_transaction::TransactionTimer;
//!
//! // Create timer calculator for TCP
//! let timers = TransportAwareTimers::new(Transport::Tcp);
//!
//! // Timer K is 0 for TCP (instant completion)
//! assert_eq!(timers.duration(TransactionTimer::K), std::time::Duration::ZERO);
//!
//! // Timer F is still 32 seconds (timeout applies to all transports)
//! assert_eq!(timers.duration(TransactionTimer::F), std::time::Duration::from_secs(32));
//!
//! // Check if retransmissions are needed
//! assert!(!timers.should_retransmit());  // TCP doesn't need retransmissions
//! ```
//!
//! See `examples/timer_behavior.rs` for comprehensive demonstrations.
//!
//! ## Timer Adjustments by Transport
//!
//! ### Client Non-INVITE Transactions:
//! - **Timer E** (retransmission): 0 for TCP/TLS (no retransmissions needed)
//! - **Timer F** (transaction timeout): 64*T1 for all transports
//! - **Timer K** (wait time): 0 for TCP/TLS, T4 for UDP
//!
//! ### Server Non-INVITE Transactions:
//! - **Timer J** (wait time): 0 for TCP/TLS, 64*T1 for UDP
//!
//! ### Client INVITE Transactions:
//! - **Timer A** (retransmission): 0 for TCP/TLS (no retransmissions needed)
//! - **Timer B** (transaction timeout): 64*T1 for all transports
//! - **Timer D** (wait time): 0 for TCP/TLS, 32s for UDP
//!
//! ### Server INVITE Transactions:
//! - **Timer G** (retransmission): 0 for TCP/TLS (no retransmissions needed)
//! - **Timer H** (transaction timeout): 64*T1 for all transports
//! - **Timer I** (wait time for ACK): 0 for TCP/TLS, T4 for UDP

use crate::TransactionTimer;
use std::time::Duration;

/// Transport protocol for timer calculations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Unreliable transport (UDP) - uses full timer values
    Udp,
    /// Reliable transport (TCP) - certain timers set to zero
    Tcp,
    /// Reliable secure transport (TLS) - certain timers set to zero
    Tls,
}

impl Transport {
    /// Returns true if this is a reliable transport (TCP or TLS).
    pub fn is_reliable(self) -> bool {
        matches!(self, Transport::Tcp | Transport::Tls)
    }

    /// Returns true if this is an unreliable transport (UDP).
    pub fn is_unreliable(self) -> bool {
        matches!(self, Transport::Udp)
    }
}

/// RFC 3261 base timer values (Table 4).
///
/// These are the default values. Implementations may adjust T1 based on network
/// characteristics, but T1 MUST NOT be set lower than 500ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerDefaults {
    /// RTT estimate - default 500ms
    pub t1: Duration,
    /// Maximum retransmit interval for non-INVITE - default 4s
    pub t2: Duration,
    /// Maximum wait time for network to clear - default 5s
    pub t4: Duration,
}

impl Default for TimerDefaults {
    fn default() -> Self {
        Self {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
        }
    }
}

/// Transport-aware timer value calculator.
///
/// Adjusts timer values based on whether the transport is reliable (TCP/TLS)
/// or unreliable (UDP) per RFC 3261 §17.
pub struct TransportAwareTimers {
    transport: Transport,
    defaults: TimerDefaults,
}

impl TransportAwareTimers {
    /// Creates a new timer calculator for the specified transport.
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            defaults: TimerDefaults::default(),
        }
    }

    /// Creates a timer calculator with custom base timer values.
    pub fn with_defaults(transport: Transport, defaults: TimerDefaults) -> Self {
        Self {
            transport,
            defaults,
        }
    }

    /// Returns the appropriate duration for a given timer.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_transaction::timers::{TransportAwareTimers, Transport};
    /// use sip_transaction::TransactionTimer;
    /// use std::time::Duration;
    ///
    /// let udp_timers = TransportAwareTimers::new(Transport::Udp);
    /// let tcp_timers = TransportAwareTimers::new(Transport::Tcp);
    ///
    /// // Timer K is T4 (5s) for UDP, 0 for TCP
    /// assert_eq!(udp_timers.duration(TransactionTimer::K), Duration::from_secs(5));
    /// assert_eq!(tcp_timers.duration(TransactionTimer::K), Duration::ZERO);
    ///
    /// // Timer F is 64*T1 for both
    /// assert_eq!(udp_timers.duration(TransactionTimer::F), Duration::from_secs(32));
    /// assert_eq!(tcp_timers.duration(TransactionTimer::F), Duration::from_secs(32));
    /// ```
    pub fn duration(&self, timer: TransactionTimer) -> Duration {
        match timer {
            // Base timer values (same for all transports)
            TransactionTimer::T1 => self.defaults.t1,
            TransactionTimer::T2 => self.defaults.t2,
            TransactionTimer::T4 => self.defaults.t4,

            // Client INVITE timers
            TransactionTimer::A => {
                // Retransmission timer - 0 for reliable transports
                if self.transport.is_reliable() {
                    Duration::ZERO
                } else {
                    self.defaults.t1
                }
            }
            TransactionTimer::B => {
                // Transaction timeout - 64*T1 for all transports
                self.defaults.t1.saturating_mul(64)
            }
            TransactionTimer::D => {
                // Wait time for response retransmissions - 0 for reliable transports
                if self.transport.is_reliable() {
                    Duration::ZERO
                } else {
                    Duration::from_secs(32) // Fixed value per RFC 3261
                }
            }

            // Client non-INVITE timers
            TransactionTimer::E => {
                // Retransmission timer - 0 for reliable transports
                if self.transport.is_reliable() {
                    Duration::ZERO
                } else {
                    self.defaults.t1
                }
            }
            TransactionTimer::F => {
                // Transaction timeout - 64*T1 for all transports
                self.defaults.t1.saturating_mul(64)
            }
            TransactionTimer::K => {
                // Wait time - 0 for reliable transports, T4 for UDP
                if self.transport.is_reliable() {
                    Duration::ZERO
                } else {
                    self.defaults.t4
                }
            }

            // Server INVITE timers
            TransactionTimer::G => {
                // Retransmission timer - 0 for reliable transports
                if self.transport.is_reliable() {
                    Duration::ZERO
                } else {
                    self.defaults.t1
                }
            }
            TransactionTimer::H => {
                // Wait time for ACK - 64*T1 for all transports
                self.defaults.t1.saturating_mul(64)
            }
            TransactionTimer::I => {
                // Wait time for ACK retransmissions - 0 for reliable transports
                if self.transport.is_reliable() {
                    Duration::ZERO
                } else {
                    self.defaults.t4
                }
            }

            // Server non-INVITE timers
            TransactionTimer::J => {
                // Wait time - 0 for reliable transports, 64*T1 for UDP
                if self.transport.is_reliable() {
                    Duration::ZERO
                } else {
                    self.defaults.t1.saturating_mul(64)
                }
            }

            // INVITE-specific timers
            TransactionTimer::C => {
                // Proxy INVITE transaction timeout - 3 minutes
                Duration::from_secs(180)
            }
        }
    }

    /// Returns whether retransmissions should be performed for this transport.
    ///
    /// Retransmissions are only necessary for unreliable transports (UDP).
    pub fn should_retransmit(&self) -> bool {
        self.transport.is_unreliable()
    }

    /// Returns the transport type.
    pub fn transport(&self) -> Transport {
        self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_k_zero_for_tcp() {
        let timers = TransportAwareTimers::new(Transport::Tcp);
        assert_eq!(timers.duration(TransactionTimer::K), Duration::ZERO);
    }

    #[test]
    fn timer_k_zero_for_tls() {
        let timers = TransportAwareTimers::new(Transport::Tls);
        assert_eq!(timers.duration(TransactionTimer::K), Duration::ZERO);
    }

    #[test]
    fn timer_k_t4_for_udp() {
        let timers = TransportAwareTimers::new(Transport::Udp);
        assert_eq!(timers.duration(TransactionTimer::K), Duration::from_secs(5));
    }

    #[test]
    fn timer_j_zero_for_tcp() {
        let timers = TransportAwareTimers::new(Transport::Tcp);
        assert_eq!(timers.duration(TransactionTimer::J), Duration::ZERO);
    }

    #[test]
    fn timer_j_64t1_for_udp() {
        let timers = TransportAwareTimers::new(Transport::Udp);
        assert_eq!(
            timers.duration(TransactionTimer::J),
            Duration::from_secs(32)
        );
    }

    #[test]
    fn timer_i_zero_for_reliable() {
        let tcp_timers = TransportAwareTimers::new(Transport::Tcp);
        let tls_timers = TransportAwareTimers::new(Transport::Tls);
        assert_eq!(tcp_timers.duration(TransactionTimer::I), Duration::ZERO);
        assert_eq!(tls_timers.duration(TransactionTimer::I), Duration::ZERO);
    }

    #[test]
    fn timer_i_t4_for_udp() {
        let timers = TransportAwareTimers::new(Transport::Udp);
        assert_eq!(timers.duration(TransactionTimer::I), Duration::from_secs(5));
    }

    #[test]
    fn timer_a_zero_for_reliable() {
        let tcp_timers = TransportAwareTimers::new(Transport::Tcp);
        assert_eq!(tcp_timers.duration(TransactionTimer::A), Duration::ZERO);
    }

    #[test]
    fn timer_e_zero_for_reliable() {
        let tcp_timers = TransportAwareTimers::new(Transport::Tcp);
        assert_eq!(tcp_timers.duration(TransactionTimer::E), Duration::ZERO);
    }

    #[test]
    fn timer_g_zero_for_reliable() {
        let tcp_timers = TransportAwareTimers::new(Transport::Tcp);
        assert_eq!(tcp_timers.duration(TransactionTimer::G), Duration::ZERO);
    }

    #[test]
    fn timer_d_zero_for_reliable() {
        let tcp_timers = TransportAwareTimers::new(Transport::Tcp);
        assert_eq!(tcp_timers.duration(TransactionTimer::D), Duration::ZERO);
    }

    #[test]
    fn timer_f_same_for_all_transports() {
        let udp = TransportAwareTimers::new(Transport::Udp);
        let tcp = TransportAwareTimers::new(Transport::Tcp);
        let tls = TransportAwareTimers::new(Transport::Tls);

        let expected = Duration::from_secs(32); // 64*T1
        assert_eq!(udp.duration(TransactionTimer::F), expected);
        assert_eq!(tcp.duration(TransactionTimer::F), expected);
        assert_eq!(tls.duration(TransactionTimer::F), expected);
    }

    #[test]
    fn timer_b_same_for_all_transports() {
        let udp = TransportAwareTimers::new(Transport::Udp);
        let tcp = TransportAwareTimers::new(Transport::Tcp);

        let expected = Duration::from_secs(32); // 64*T1
        assert_eq!(udp.duration(TransactionTimer::B), expected);
        assert_eq!(tcp.duration(TransactionTimer::B), expected);
    }

    #[test]
    fn timer_h_same_for_all_transports() {
        let udp = TransportAwareTimers::new(Transport::Udp);
        let tcp = TransportAwareTimers::new(Transport::Tcp);

        let expected = Duration::from_secs(32); // 64*T1
        assert_eq!(udp.duration(TransactionTimer::H), expected);
        assert_eq!(tcp.duration(TransactionTimer::H), expected);
    }

    #[test]
    fn should_retransmit_only_for_udp() {
        let udp = TransportAwareTimers::new(Transport::Udp);
        let tcp = TransportAwareTimers::new(Transport::Tcp);
        let tls = TransportAwareTimers::new(Transport::Tls);

        assert!(udp.should_retransmit());
        assert!(!tcp.should_retransmit());
        assert!(!tls.should_retransmit());
    }

    #[test]
    fn custom_timer_defaults() {
        let custom = TimerDefaults {
            t1: Duration::from_secs(1),
            t2: Duration::from_secs(8),
            t4: Duration::from_secs(10),
        };
        let timers = TransportAwareTimers::with_defaults(Transport::Udp, custom);

        assert_eq!(
            timers.duration(TransactionTimer::T1),
            Duration::from_secs(1)
        );
        assert_eq!(
            timers.duration(TransactionTimer::K),
            Duration::from_secs(10)
        );
        assert_eq!(
            timers.duration(TransactionTimer::F),
            Duration::from_secs(64)
        ); // 64*T1
    }

    #[test]
    fn transport_detection() {
        assert!(Transport::Tcp.is_reliable());
        assert!(Transport::Tls.is_reliable());
        assert!(Transport::Udp.is_unreliable());
        assert!(!Transport::Tcp.is_unreliable());
    }
}
