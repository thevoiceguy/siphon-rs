// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP transaction state machines implementing RFC 3261 §17.
//!
//! This module provides the four transaction layer finite state machines (FSMs)
//! defined in RFC 3261, with transport-aware timer optimization per §17.1.2.2.
//!
//! # Transaction Types
//!
//! The SIP transaction layer defines four state machines based on role and method:
//!
//! - **Client Non-INVITE** (`ClientNonInviteFsm`) - For client sending OPTIONS, REGISTER, etc.
//! - **Client INVITE** (`ClientInviteFsm`) - For client sending INVITE requests
//! - **Server Non-INVITE** (`ServerNonInviteFsm`) - For server receiving OPTIONS, REGISTER, etc.
//! - **Server INVITE** (`ServerInviteFsm`) - For server receiving INVITE requests
//!
//! Each FSM implements its respective state machine diagram from RFC 3261 Figures 5-9.
//!
//! # Transport-Aware Timer Integration
//!
//! All FSMs now use `TransportAwareTimers` instead of raw timer values, providing
//! automatic optimization based on transport type:
//!
//! ## UDP (Unreliable Transport)
//! - Full retransmission timers (A, E, G) with exponential backoff
//! - Full wait timers (D, I, J, K) for absorbing retransmissions
//! - Transactions complete in 5-37 seconds depending on response timing
//!
//! ## TCP/TLS (Reliable Transport)
//! - Zero-duration retransmission timers (no retransmissions needed)
//! - Zero-duration wait timers (instant completion)
//! - Transactions complete in 150-500ms typically
//!
//! **Performance Impact**: TCP/TLS transactions complete 5-37 seconds faster than UDP.
//!
//! # FSM Architecture
//!
//! Each state machine follows the same pattern:
//!
//! 1. **State** - Current state enum (e.g., `Trying`, `Proceeding`, `Completed`)
//! 2. **Events** - Input events that drive state transitions (e.g., `SendRequest`, `ReceiveResponse`)
//! 3. **Actions** - Output actions to perform (e.g., `Transmit`, `Schedule`, `Terminate`)
//! 4. **Transitions** - `on_event()` method processes events and returns actions
//!
//! The FSMs are deterministic: given a state and event, they produce a new state and actions.
//!
//! # Example: Client Non-INVITE Transaction
//!
//! ```rust
//! use sip_transaction::fsm::{ClientNonInviteFsm, ClientNonInviteEvent, ClientAction};
//! use sip_transaction::timers::{TransportAwareTimers, Transport};
//! use sip_core::{Headers, Method, Request, RequestLine, SipUri};
//! use bytes::Bytes;
//!
//! # fn create_request() -> Request {
//! #     let uri = SipUri::parse("sip:user@example.com").unwrap();
//! #     let line = RequestLine::new(Method::Options, uri);
//! #     Request::new(line, Headers::new(), Bytes::new()).expect("valid request")
//! # }
//! // Create FSM with TCP timers (zero retransmissions)
//! let timers = TransportAwareTimers::new(Transport::Tcp);
//! let mut fsm = ClientNonInviteFsm::new(timers);
//!
//! // Send request
//! let request = create_request();
//! let actions = fsm.on_event(ClientNonInviteEvent::SendRequest(request));
//!
//! // Process actions
//! for action in actions {
//!     match action {
//!         ClientAction::Transmit { bytes, transport } => {
//!             // Send bytes over transport
//!         }
//!         ClientAction::Schedule { timer, duration } => {
//!             // Schedule timer (F=32s for TCP, E=0 for TCP)
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Example: Server INVITE Transaction
//!
//! ```rust
//! use sip_transaction::fsm::{ServerInviteFsm, ServerInviteEvent, ServerAction};
//! use sip_transaction::timers::{TransportAwareTimers, Transport};
//! use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri, StatusLine};
//! use bytes::Bytes;
//!
//! # fn create_request() -> Request {
//! #     let uri = SipUri::parse("sip:user@example.com").unwrap();
//! #     let line = RequestLine::new(Method::Invite, uri);
//! #     Request::new(line, Headers::new(), Bytes::new()).expect("valid request")
//! # }
//! # fn create_200_ok() -> Response {
//! #     Response::new(StatusLine::new(200, "OK").expect("valid status"), Headers::new(), Bytes::new()).expect("valid response")
//! # }
//! // Create FSM with UDP timers (full retransmissions)
//! let timers = TransportAwareTimers::new(Transport::Udp);
//! let mut fsm = ServerInviteFsm::new(timers);
//!
//! // Receive INVITE
//! let request = create_request();
//! let actions = fsm.on_event(ServerInviteEvent::ReceiveInvite(request));
//!
//! // ... send 100 Trying, 180 Ringing ...
//!
//! // Send 200 OK
//! let response = create_200_ok();
//! let actions = fsm.on_event(ServerInviteEvent::SendFinal(response));
//!
//! // For UDP, Timer G starts retransmitting 200 OK until ACK arrives
//! // For TCP, no retransmissions - ACK expected once
//! ```
//!
//! # Timer Behavior by FSM
//!
//! ## Client Non-INVITE
//! - **Timer E**: Retransmission (0 for TCP/TLS, T1→T2 exponential for UDP)
//! - **Timer F**: Transaction timeout (64*T1 = 32s for all transports)
//! - **Timer K**: Wait for retransmissions (0 for TCP/TLS, T4=5s for UDP)
//!
//! ## Client INVITE
//! - **Timer A**: INVITE retransmission (0 for TCP/TLS, T1→T2 exponential for UDP)
//! - **Timer B**: Transaction timeout (64*T1 = 32s for all transports)
//! - **Timer D**: Wait for response retransmissions (0 for TCP/TLS, 32s for UDP)
//!
//! ## Server Non-INVITE
//! - **Timer J**: Wait for request retransmissions (0 for TCP/TLS, 64*T1=32s for UDP)
//!
//! ## Server INVITE
//! - **Timer G**: Response retransmission (0 for TCP/TLS, T1→T2 exponential for UDP)
//! - **Timer H**: Wait for ACK (64*T1 = 32s for all transports)
//! - **Timer I**: Wait for ACK retransmissions (0 for TCP/TLS, T4=5s for UDP)
//!
//! # State Transition Diagrams
//!
//! ## Client Non-INVITE Transaction FSM
//!
//! ```text
//!                    +----------+
//!                    |          |
//!          +-------->|  Trying  |
//!          |         |          |
//!          |         +----------+
//!          |              |
//!          |              | 1xx response
//!          |              v
//!          |         +------------+
//!          | Timer E |            |
//!          +---------|Proceeding  |
//!                    |            |
//!                    +------------+
//!                         |
//!                         | 2xx-6xx response
//!                         v
//!                    +------------+
//!                    |            |
//!                    | Completed  |
//!                    |            |
//!                    +------------+
//!                         |
//!                         | Timer K
//!                         v
//!                    +------------+
//!                    | Terminated |
//!                    +------------+
//! ```
//!
//! ## Client INVITE Transaction FSM
//!
//! ```text
//!                    +----------+
//!                    |          |
//!          +-------->| Calling  |<------+
//!          |         |          |       |
//!          |         +----------+       | Timer A
//!          |              |             |
//!          |              | 1xx response|
//!          |              v             |
//!          |         +------------+     |
//!          |         |            |-----+
//!          |         |Proceeding  |
//!          |         |            |
//!          |         +------------+
//!          |              |
//!          |              | 3xx-6xx response
//!          |              v
//!          |         +------------+
//!          | Timer B |            |
//!          +---------|  Completed |
//!          timeout   |            |
//!             |      +------------+
//!             |           |
//!             |           | Timer D
//!             |           v
//!             |      +------------+
//!             +----->| Terminated |<---+
//!                    +------------+    |
//!                         ^            | 2xx response
//!                         +------------+ (immediate)
//! ```
//!
//! ## Server Non-INVITE Transaction FSM
//!
//! ```text
//!                    +----------+
//!          request   |          |
//!        +---------->|  Trying  |
//!                    |          |
//!                    +----------+
//!                         |
//!                         | send provisional (optional)
//!                         v
//!                    +------------+
//!                    |            |
//!                    |Proceeding  |
//!                    |            |
//!                    +------------+
//!                         |
//!                         | send final response
//!                         v
//!                    +------------+
//!                    |            |
//!                    | Completed  |
//!                    |            |
//!                    +------------+
//!                         |
//!                         | Timer J
//!                         v
//!                    +------------+
//!                    | Terminated |
//!                    +------------+
//! ```
//!
//! ## Server INVITE Transaction FSM
//!
//! ```text
//!                    +------------+
//!          INVITE    |            |
//!        +---------->|Proceeding  |
//!                    |            |
//!                    +------------+
//!                         |
//!                         | send 3xx-6xx response
//!                         v
//!                    +------------+
//!                    |            |<------+
//!                    | Completed  |       | Timer G
//!                    |            |-------+ (retransmit)
//!                    +------------+
//!                         |
//!                         | receive ACK
//!                         v
//!                    +------------+
//!                    |            |
//!                    | Confirmed  |
//!                    |            |
//!                    +------------+
//!                         |
//!                         | Timer I
//!                         v
//!                    +------------+
//!                    | Terminated |<---+
//!                    +------------+    |
//!                         ^            | send 2xx response
//!                         +------------+ (immediate)
//! ```
//!
//! # RFC 3261 Compliance
//!
//! These FSMs strictly follow RFC 3261 state machine diagrams:
//! - Figure 5: Client INVITE transaction
//! - Figure 6: Server INVITE transaction
//! - Figure 7: Client non-INVITE transaction (implied)
//! - Figure 8: Server non-INVITE transaction (implied)
//!
//! Timer adjustments for reliable transports follow RFC 3261 §17.1.2.2 exactly.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use sip_core::{Request, Response};
use sip_parse::{serialize_request, serialize_response};
use smol_str::SmolStr;
use tracing::{debug, warn};

use crate::timers::TransportAwareTimers;
use crate::{ClientNonInviteState, ServerNonInviteState, TransactionTimer};

/// Events that drive the client non-INVITE transaction state machine.
#[derive(Debug, Clone)]
pub enum ClientNonInviteEvent {
    SendRequest(Request),
    ReceiveProvisional(Response),
    ReceiveFinal(Response),
    TimerFired(TransactionTimer),
    TransportError,
}

/// Actions emitted by the client transaction state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAction {
    Transmit {
        bytes: Bytes,
        transport: TransportKind,
    },
    Deliver(Response),
    Schedule {
        timer: TransactionTimer,
        duration: Duration,
    },
    Cancel(TransactionTimer),
    Terminate {
        reason: SmolStr,
    },
}

/// Events that drive the client INVITE transaction state machine (RFC 3261 §17.1.1).
#[derive(Debug, Clone)]
pub enum ClientInviteEvent {
    SendInvite(Request),
    ReceiveProvisional(Response),
    ReceiveFinal(Response),
    TimerFired(TransactionTimer),
    TransportError,
}

/// Actions emitted by the client INVITE transaction state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientInviteAction {
    Transmit {
        bytes: Bytes,
        transport: TransportKind,
    },
    Deliver(Response),
    ExpectPrack(Response),
    GenerateAck {
        response: Response,
        is_2xx: bool,
    },
    Schedule {
        timer: TransactionTimer,
        duration: Duration,
    },
    Cancel(TransactionTimer),
    Terminate {
        reason: SmolStr,
    },
}

/// Input events for server non-INVITE transaction.
#[derive(Debug, Clone)]
pub enum ServerNonInviteEvent {
    ReceiveRequest(Request),
    SendProvisional(Response),
    SendFinal(Response),
    TimerFired(TransactionTimer),
    AckReceived,
    TransportError,
}

/// Actions emitted by the server transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAction {
    Transmit {
        bytes: Bytes,
        transport: TransportKind,
    },
    Schedule {
        timer: TransactionTimer,
        duration: Duration,
    },
    Cancel(TransactionTimer),
    Terminate {
        reason: SmolStr,
    },
}

/// Events that drive the server INVITE transaction state machine (RFC 3261 §17.2.1).
#[derive(Debug, Clone)]
pub enum ServerInviteEvent {
    ReceiveInvite(Request),
    ReceiveCancel,
    SendProvisional(Response),
    SendFinal(Response),
    ReceiveAck,
    TimerFired(TransactionTimer),
    TransportError,
}

/// Actions emitted by the server INVITE transaction state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerInviteAction {
    Transmit {
        bytes: Bytes,
        transport: TransportKind,
    },
    Schedule {
        timer: TransactionTimer,
        duration: Duration,
    },
    Cancel(TransactionTimer),
    Terminate {
        reason: SmolStr,
    },
}

/// A provisional is reliable only when it carries both `Require: 100rel`
/// and an RSeq, and a 100 never is (RFC 3262 §3, §4). An RSeq alone, or
/// beside `Supported: 100rel`, used to draw a PRACK the callee never asked
/// for and answered with 481.
fn response_requires_prack(response: &Response) -> bool {
    if response.code() == 100 || response.headers().get("RSeq").is_none() {
        return false;
    }
    response
        .headers()
        .get_all_smol("Require")
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("100rel"))
}

/// Implements RFC 3261 Figure 7 for non-INVITE client transactions.
///
/// # RFC 4320 Compliance
///
/// This implementation follows RFC 4320 "Actions Addressing Identified Issues
/// with SIP's Non-INVITE Transaction":
///
/// - **No 408 Responses**: Timer F expiration does NOT generate a 408 (Request
///   Timeout) response. RFC 4320 prohibits this because such responses always
///   arrive too late to be useful.
///
/// - **Timer E Exponential Backoff**: Retransmissions double from T1 to T2,
///   allowing servers time to send 100 Trying responses before blacklisting
///   occurs (per RFC 4320 recommendation).
///
/// - **Timer F Duration**: 64*T1 provides sufficient time for delayed servers
///   to respond, consistent with RFC 4320's goal of reducing false timeouts.
pub struct ClientNonInviteFsm {
    state: ClientNonInviteState,
    timers: TransportAwareTimers,
    e_interval: Duration,
    last_request: Option<Bytes>,
}

impl ClientNonInviteFsm {
    /// Returns the current state.
    pub fn state(&self) -> ClientNonInviteState {
        self.state
    }
}

/// Implements the client INVITE transaction state machine.
pub struct ClientInviteFsm {
    state: crate::ClientInviteState,
    timers: TransportAwareTimers,
    a_interval: Duration,
    last_invite: Option<Bytes>,
    /// Whether the final this transaction delivered was a 2xx: only then
    /// is a 2xx arriving once `Terminated` one of its retransmissions or
    /// forks, rather than a second final.
    answered: bool,
}

impl ClientInviteFsm {
    /// Returns the current state.
    pub fn state(&self) -> crate::ClientInviteState {
        self.state
    }
}

impl ClientInviteFsm {
    /// Creates a new INVITE transaction FSM with transport-aware timers.
    pub fn new(timers: TransportAwareTimers) -> Self {
        let a_initial = timers.duration(TransactionTimer::A);
        Self {
            state: crate::ClientInviteState::Calling,
            timers,
            a_interval: a_initial,
            last_invite: None,
            answered: false,
        }
    }

    /// Handles an INVITE transaction event and returns actions for the runtime.
    pub fn on_event(&mut self, event: ClientInviteEvent) -> Vec<ClientInviteAction> {
        use crate::ClientInviteState::*;
        match (&self.state, event) {
            (Calling, ClientInviteEvent::SendInvite(invite)) => self.handle_send_invite(invite),
            (Calling | Proceeding, ClientInviteEvent::ReceiveProvisional(response)) => {
                self.handle_provisional(response)
            }
            (
                state @ (Calling | Proceeding | Completed),
                ClientInviteEvent::ReceiveFinal(response),
            ) => self.handle_final(*state, response),
            (Terminated, ClientInviteEvent::ReceiveFinal(response)) => {
                if self.answered && (200..=299).contains(&response.code()) {
                    self.handle_final_2xx(response)
                } else {
                    Vec::new()
                }
            }
            (Calling, ClientInviteEvent::TimerFired(TransactionTimer::A)) => self.handle_timer_a(),
            (Calling | Proceeding, ClientInviteEvent::TimerFired(TransactionTimer::B)) => {
                self.handle_timer_b()
            }
            (Completed, ClientInviteEvent::TimerFired(TransactionTimer::D)) => {
                self.handle_timer_d()
            }
            (_, ClientInviteEvent::TransportError) => self.handle_transport_error(),
            (_, ClientInviteEvent::TimerFired(_)) => Vec::new(),
            _ => Vec::new(),
        }
    }

    fn handle_send_invite(&mut self, request: Request) -> Vec<ClientInviteAction> {
        let bytes = serialize_request(&request);
        self.last_invite = Some(bytes.clone());
        self.state = crate::ClientInviteState::Calling;

        let mut actions = vec![ClientInviteAction::Transmit {
            bytes,
            transport: TransportKind::Udp,
        }];

        // Only schedule Timer A if duration is non-zero (UDP only)
        let timer_a_duration = self.timers.duration(TransactionTimer::A);
        if !timer_a_duration.is_zero() {
            actions.push(ClientInviteAction::Schedule {
                timer: TransactionTimer::A,
                duration: timer_a_duration,
            });
        }

        // Always schedule Timer B (transaction timeout)
        actions.push(ClientInviteAction::Schedule {
            timer: TransactionTimer::B,
            duration: self.timers.duration(TransactionTimer::B),
        });

        actions
    }

    fn handle_provisional(&mut self, response: Response) -> Vec<ClientInviteAction> {
        self.state = crate::ClientInviteState::Proceeding;
        let mut actions = vec![
            ClientInviteAction::Cancel(TransactionTimer::A),
            ClientInviteAction::Deliver(response.clone()),
        ];
        if response_requires_prack(&response) {
            actions.push(ClientInviteAction::ExpectPrack(response));
        }
        actions
    }

    fn handle_final(
        &mut self,
        current_state: crate::ClientInviteState,
        response: Response,
    ) -> Vec<ClientInviteAction> {
        let code = response.code();
        if !(200..=299).contains(&code) {
            return self.handle_final_non_2xx(current_state, response);
        }
        // Completed takes only 300-699 (RFC 3261 Figure 5): the TU already
        // has this transaction's final, and a 2xx after it would be a second.
        if matches!(current_state, crate::ClientInviteState::Completed) {
            debug!(code, "dropping a 2xx received after a non-2xx final");
            return Vec::new();
        }
        self.handle_final_2xx(response)
    }

    fn handle_final_2xx(&mut self, response: Response) -> Vec<ClientInviteAction> {
        self.state = crate::ClientInviteState::Terminated;
        self.answered = true;
        vec![
            ClientInviteAction::Cancel(TransactionTimer::A),
            ClientInviteAction::Cancel(TransactionTimer::B),
            ClientInviteAction::Deliver(response.clone()),
            ClientInviteAction::GenerateAck {
                response,
                is_2xx: true,
            },
        ]
    }

    fn handle_final_non_2xx(
        &mut self,
        current_state: crate::ClientInviteState,
        response: Response,
    ) -> Vec<ClientInviteAction> {
        // A retransmission of the final while Completed: the ACK again, and
        // nothing for the TU (RFC 3261 §17.1.1.2). Delivered again, a 401
        // or 407 started another authenticated INVITE each time the server
        // resent its challenge.
        if matches!(current_state, crate::ClientInviteState::Completed) {
            return vec![ClientInviteAction::GenerateAck {
                response,
                is_2xx: false,
            }];
        }
        self.state = crate::ClientInviteState::Completed;
        let mut actions = vec![
            ClientInviteAction::Cancel(TransactionTimer::A),
            ClientInviteAction::Cancel(TransactionTimer::B),
            ClientInviteAction::Deliver(response.clone()),
            ClientInviteAction::GenerateAck {
                response,
                is_2xx: false,
            },
        ];
        if !matches!(current_state, crate::ClientInviteState::Completed) {
            actions.push(ClientInviteAction::Schedule {
                timer: TransactionTimer::D,
                duration: self.timers.duration(TransactionTimer::D), // 0 for TCP/TLS, 32s for UDP
            });
        }
        actions
    }

    fn handle_timer_a(&mut self) -> Vec<ClientInviteAction> {
        if !matches!(self.state, crate::ClientInviteState::Calling) {
            return Vec::new();
        }

        // Timer A should only fire on unreliable transports (UDP)
        // If we're here on a reliable transport, don't retransmit or reschedule
        if self.timers.duration(TransactionTimer::A).is_zero() {
            return Vec::new();
        }

        let t2 = self.timers.duration(TransactionTimer::T2);
        self.a_interval = (self.a_interval * 2).min(t2);
        if let Some(invite) = &self.last_invite {
            vec![
                ClientInviteAction::Transmit {
                    bytes: invite.clone(),
                    transport: TransportKind::Udp,
                },
                ClientInviteAction::Schedule {
                    timer: TransactionTimer::A,
                    duration: self.a_interval,
                },
            ]
        } else {
            Vec::new()
        }
    }

    fn handle_timer_b(&mut self) -> Vec<ClientInviteAction> {
        if matches!(self.state, crate::ClientInviteState::Terminated) {
            return Vec::new();
        }
        self.state = crate::ClientInviteState::Terminated;
        vec![
            ClientInviteAction::Cancel(TransactionTimer::A),
            ClientInviteAction::Terminate {
                reason: SmolStr::new("Timer B expired"),
            },
        ]
    }

    fn handle_timer_d(&mut self) -> Vec<ClientInviteAction> {
        self.state = crate::ClientInviteState::Terminated;
        vec![ClientInviteAction::Cancel(TransactionTimer::D)]
    }

    fn handle_transport_error(&mut self) -> Vec<ClientInviteAction> {
        // Already ended, and the TU already told (§17.1.1.2): a second
        // error, e.g. from a retransmission in flight, ends nothing.
        if matches!(self.state, crate::ClientInviteState::Terminated) {
            return Vec::new();
        }
        self.state = crate::ClientInviteState::Terminated;
        vec![ClientInviteAction::Terminate {
            reason: SmolStr::new("transport error"),
        }]
    }
}

impl ClientNonInviteFsm {
    /// Creates a new FSM ready to send a request with transport-aware timers.
    pub fn new(timers: TransportAwareTimers) -> Self {
        let e_initial = timers.duration(TransactionTimer::E);
        Self {
            state: ClientNonInviteState::Trying,
            timers,
            e_interval: e_initial,
            last_request: None,
        }
    }

    /// Handles an event, returning the resulting actions.
    pub fn on_event(&mut self, event: ClientNonInviteEvent) -> Vec<ClientAction> {
        match (&self.state, event) {
            (ClientNonInviteState::Trying, ClientNonInviteEvent::SendRequest(request)) => {
                self.handle_initial_send(request)
            }
            (
                ClientNonInviteState::Trying | ClientNonInviteState::Proceeding,
                ClientNonInviteEvent::ReceiveProvisional(response),
            ) => self.handle_provisional(response),
            (
                ClientNonInviteState::Trying | ClientNonInviteState::Proceeding,
                ClientNonInviteEvent::ReceiveFinal(response),
            ) => self.handle_final(response),
            (
                ClientNonInviteState::Trying | ClientNonInviteState::Proceeding,
                ClientNonInviteEvent::TimerFired(TransactionTimer::E),
            ) => self.handle_timer_e(),
            (
                ClientNonInviteState::Trying,
                ClientNonInviteEvent::TimerFired(TransactionTimer::F),
            ) => self.handle_timer_f(),
            (
                ClientNonInviteState::Proceeding,
                ClientNonInviteEvent::TimerFired(TransactionTimer::F),
            ) => self.handle_timer_f(),
            (
                ClientNonInviteState::Completed,
                ClientNonInviteEvent::TimerFired(TransactionTimer::K),
            ) => self.handle_timer_k(),
            (_, ClientNonInviteEvent::TransportError) => self.handle_transport_error(),
            (_, _) => Vec::new(),
        }
    }

    fn handle_initial_send(&mut self, request: Request) -> Vec<ClientAction> {
        let bytes = serialize_request(&request);
        self.last_request = Some(bytes.clone());
        self.state = ClientNonInviteState::Trying;

        let mut actions = vec![ClientAction::Transmit {
            bytes,
            transport: TransportKind::Udp,
        }];

        // Only schedule Timer E if duration is non-zero (UDP only)
        let timer_e_duration = self.timers.duration(TransactionTimer::E);
        if !timer_e_duration.is_zero() {
            actions.push(ClientAction::Schedule {
                timer: TransactionTimer::E,
                duration: timer_e_duration,
            });
        }

        // Always schedule Timer F (transaction timeout)
        actions.push(ClientAction::Schedule {
            timer: TransactionTimer::F,
            duration: self.timers.duration(TransactionTimer::F),
        });

        actions
    }

    fn handle_provisional(&mut self, response: Response) -> Vec<ClientAction> {
        self.state = ClientNonInviteState::Proceeding;
        vec![ClientAction::Deliver(response)]
    }

    fn handle_final(&mut self, response: Response) -> Vec<ClientAction> {
        self.state = ClientNonInviteState::Completed;
        vec![
            ClientAction::Deliver(response),
            ClientAction::Cancel(TransactionTimer::E),
            ClientAction::Cancel(TransactionTimer::F),
            ClientAction::Schedule {
                timer: TransactionTimer::K,
                duration: self.timers.duration(TransactionTimer::K), // 0 for TCP/TLS, T4 for UDP
            },
        ]
    }

    fn handle_timer_e(&mut self) -> Vec<ClientAction> {
        if self.state == ClientNonInviteState::Completed {
            return Vec::new();
        }

        // Timer E should only fire on unreliable transports (UDP)
        // If we're here on a reliable transport, don't retransmit or reschedule
        if self.timers.duration(TransactionTimer::E).is_zero() {
            return Vec::new();
        }

        let t2 = self.timers.duration(TransactionTimer::T2);
        self.e_interval = (self.e_interval * 2).min(t2);
        if let Some(payload) = &self.last_request {
            vec![
                ClientAction::Transmit {
                    bytes: payload.clone(),
                    transport: TransportKind::Udp,
                },
                ClientAction::Schedule {
                    timer: TransactionTimer::E,
                    duration: self.e_interval,
                },
            ]
        } else {
            Vec::new()
        }
    }

    /// Handles Timer F expiration (non-INVITE transaction timeout).
    ///
    /// # RFC 4320 Compliance
    ///
    /// RFC 4320 prohibits sending 408 (Request Timeout) responses for non-INVITE
    /// transactions because "a 408 to non-INVITE will always arrive too late to
    /// be useful." The client already understands the transaction timed out via
    /// Timer F expiration.
    ///
    /// This implementation correctly:
    /// - Terminates the transaction without generating a 408 response
    /// - Cancels Timer E (retransmission timer)
    /// - Reports timeout to the transaction user via Terminate action
    ///
    /// The transaction user receives the timeout notification and can take
    /// appropriate action (e.g., try alternate destinations, report failure).
    fn handle_timer_f(&mut self) -> Vec<ClientAction> {
        self.state = ClientNonInviteState::Terminated;
        vec![
            ClientAction::Cancel(TransactionTimer::E),
            ClientAction::Terminate {
                reason: SmolStr::new("Timer F expired"),
            },
        ]
    }

    fn handle_timer_k(&mut self) -> Vec<ClientAction> {
        self.state = ClientNonInviteState::Terminated;
        vec![ClientAction::Cancel(TransactionTimer::K)]
    }

    fn handle_transport_error(&mut self) -> Vec<ClientAction> {
        if self.state == ClientNonInviteState::Terminated {
            return Vec::new();
        }
        self.state = ClientNonInviteState::Terminated;
        vec![ClientAction::Terminate {
            reason: SmolStr::new("transport error"),
        }]
    }
}

/// Simplified server non-INVITE transaction following RFC 3261 Figure 7.
///
/// # RFC 4320 Compliance
///
/// This implementation follows RFC 4320 "Actions Addressing Identified Issues
/// with SIP's Non-INVITE Transaction":
///
/// - **No 408 Generation**: This FSM never generates 408 (Request Timeout)
///   responses. RFC 4320 explicitly prohibits servers from sending 408 for
///   non-INVITE transactions.
///
/// - **Transaction Termination**: Timer J expiration moves to Terminated state,
///   preventing late responses from being forwarded (RFC 4320 §4.1).
///
/// - **Strategic 100 Trying**: Applications should send 100 Trying responses
///   after Timer E reaches T2 to prevent requesters from blacklisting the
///   server (RFC 4320 §3.2). This is an application-level decision.
///
/// # Late Response Absorption
///
/// Per RFC 4320 §4.1, proxies must not forward responses unless there's a
/// matching server transaction that is not in Terminated state. The transaction
/// manager enforces this by checking transaction state before dispatching
/// responses.
pub struct ServerNonInviteFsm {
    state: ServerNonInviteState,
    timers: TransportAwareTimers,
    last_response: Option<Bytes>,
}

impl ServerNonInviteFsm {
    /// Returns the current state.
    pub fn state(&self) -> ServerNonInviteState {
        self.state
    }

    /// Creates a server FSM in the `Trying` state with transport-aware timers.
    pub fn new(timers: TransportAwareTimers) -> Self {
        Self {
            state: ServerNonInviteState::Trying,
            timers,
            last_response: None,
        }
    }

    /// Handles a server-side event.
    pub fn on_event(&mut self, event: ServerNonInviteEvent) -> Vec<ServerAction> {
        match (&self.state, event) {
            (ServerNonInviteState::Trying, ServerNonInviteEvent::ReceiveRequest(request)) => {
                self.handle_request(request)
            }
            (ServerNonInviteState::Proceeding, ServerNonInviteEvent::SendProvisional(response)) => {
                self.handle_provisional(response)
            }
            (
                ServerNonInviteState::Trying | ServerNonInviteState::Proceeding,
                ServerNonInviteEvent::SendFinal(response),
            ) => self.handle_final(response),
            (ServerNonInviteState::Completed, ServerNonInviteEvent::AckReceived) => {
                self.handle_ack()
            }
            (
                ServerNonInviteState::Completed,
                ServerNonInviteEvent::TimerFired(TransactionTimer::J),
            ) => self.handle_timer_j(),
            (_, ServerNonInviteEvent::TransportError) => self.handle_transport_error(),
            (_, _) => Vec::new(),
        }
    }

    pub fn on_retransmit(&self) -> Vec<ServerAction> {
        if matches!(
            self.state,
            ServerNonInviteState::Proceeding | ServerNonInviteState::Completed
        ) {
            if let Some(bytes) = &self.last_response {
                return vec![ServerAction::Transmit {
                    bytes: bytes.clone(),
                    transport: TransportKind::Udp,
                }];
            }
        }
        Vec::new()
    }

    fn handle_request(&mut self, request: Request) -> Vec<ServerAction> {
        let _ = request;
        self.state = ServerNonInviteState::Proceeding;
        Vec::new()
    }

    fn handle_provisional(&mut self, response: Response) -> Vec<ServerAction> {
        let bytes = serialize_response(&response);
        self.last_response = Some(bytes.clone());
        vec![ServerAction::Transmit {
            bytes,
            transport: TransportKind::Udp,
        }]
    }

    fn handle_final(&mut self, response: Response) -> Vec<ServerAction> {
        self.state = ServerNonInviteState::Completed;
        let bytes = serialize_response(&response);
        self.last_response = Some(bytes.clone());
        vec![
            ServerAction::Transmit {
                bytes,
                transport: TransportKind::Udp,
            },
            ServerAction::Schedule {
                timer: TransactionTimer::J,
                duration: self.timers.duration(TransactionTimer::J), // 0 for TCP/TLS, 32s for UDP
            },
        ]
    }

    fn handle_ack(&mut self) -> Vec<ServerAction> {
        self.state = ServerNonInviteState::Terminated;
        vec![
            ServerAction::Cancel(TransactionTimer::J),
            ServerAction::Terminate {
                reason: SmolStr::new("ACK received"),
            },
        ]
    }

    fn handle_timer_j(&mut self) -> Vec<ServerAction> {
        self.state = ServerNonInviteState::Terminated;
        vec![
            ServerAction::Cancel(TransactionTimer::J),
            ServerAction::Terminate {
                reason: SmolStr::new("Timer J expired"),
            },
        ]
    }

    fn handle_transport_error(&mut self) -> Vec<ServerAction> {
        if self.state == ServerNonInviteState::Terminated {
            return Vec::new();
        }
        self.state = ServerNonInviteState::Terminated;
        vec![ServerAction::Terminate {
            reason: SmolStr::new("transport error"),
        }]
    }
}

/// Marker indicating which transport to use for outbound actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Udp,
    Tcp,
    Tls,
    Ws,
    Wss,
    /// SCTP transport (RFC 4168)
    Sctp,
    /// TLS over SCTP transport (RFC 4168)
    TlsSctp,
}

/// Implements the server INVITE transaction state machine.
///
/// It also sends the UAS's reliable provisionals (RFC 3262 §3): a
/// provisional carrying `Require: 100rel` and an RSeq, or any non-100
/// provisional when the INVITE itself requires 100rel (the RSeq is then
/// this transaction's), is sent again from T1, doubling to T2, until
/// [`on_prack`](Self::on_prack) acknowledges it. One is outstanding at a
/// time: a provisional sent meanwhile waits its turn, and a 2xx waits for
/// the PRACK of an outstanding provisional that carried a session
/// description. After 64·T1 without a PRACK the provisional is no longer
/// sent and whatever waits behind it goes out; the request is not
/// rejected, as RFC 3262 suggests, because the transaction user is
/// relaying a call that may still be answered.
pub struct ServerInviteFsm {
    state: crate::ServerInviteState,
    timers: TransportAwareTimers,
    g_interval: Duration,
    last_response: Option<Bytes>,
    last_final: Option<Bytes>,
    /// The INVITE carried `Require: 100rel`.
    requires_100rel: bool,
    call_id: Option<SmolStr>,
    invite_cseq: Option<u32>,
    /// The RSeq this transaction gives its next reliable provisional.
    next_rseq: u32,
    /// The highest RSeq PRACKed, so that a repeated PRACK is answered too.
    last_pracked: Option<u32>,
    sent_reliable: bool,
    reliable: Option<OutstandingProvisional>,
    /// Provisionals sent while one was outstanding, in order.
    waiting: VecDeque<Response>,
    /// A 2xx held for the PRACK of a provisional with a session description.
    held_final: Option<Box<Response>>,
}

/// A reliable provisional sent and not yet PRACKed.
struct OutstandingProvisional {
    rseq: u32,
    bytes: Bytes,
    interval: Duration,
    has_body: bool,
}

/// An RSeq's first value (RFC 3262 §3: between 1 and 2**31 - 1), with
/// room left to count up.
fn first_rseq() -> u32 {
    use rand::RngExt;
    rand::rng().random_range(1..=(1u32 << 30))
}

fn rseq_of(response: &Response) -> Option<u32> {
    response.headers().get("RSeq")?.trim().parse().ok()
}

fn cseq_number(value: &str) -> Option<u32> {
    value.split_whitespace().next()?.parse().ok()
}

fn requires_100rel(request: &Request) -> bool {
    request
        .headers()
        .get_all_smol("Require")
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("100rel"))
}

impl ServerInviteFsm {
    /// Returns the current state.
    pub fn state(&self) -> crate::ServerInviteState {
        self.state
    }
}

impl ServerInviteFsm {
    /// Creates a new server INVITE FSM with transport-aware timers.
    pub fn new(timers: TransportAwareTimers) -> Self {
        let g_initial = timers.duration(TransactionTimer::G);
        Self {
            state: crate::ServerInviteState::Proceeding,
            timers,
            g_interval: g_initial,
            last_response: None,
            last_final: None,
            requires_100rel: false,
            call_id: None,
            invite_cseq: None,
            next_rseq: first_rseq(),
            last_pracked: None,
            sent_reliable: false,
            reliable: None,
            waiting: VecDeque::new(),
            held_final: None,
        }
    }

    /// The INVITE's Call-ID once it has sent a reliable provisional: the
    /// key a PRACK is matched by, for as long as the transaction lasts.
    pub fn prack_call_id(&self) -> Option<&SmolStr> {
        if self.sent_reliable {
            self.call_id.as_ref()
        } else {
            None
        }
    }

    /// A PRACK's RAck (RFC 3262 §7.2), its method already checked to be
    /// INVITE. `None` when it acknowledges nothing this transaction sent,
    /// to be answered 481 (§3); otherwise the actions it releases (the next
    /// provisional, a held 2xx), and the PRACK is answered 200.
    pub fn on_prack(&mut self, rseq: u32, cseq: u32) -> Option<Vec<ServerInviteAction>> {
        if self.state != crate::ServerInviteState::Proceeding || self.invite_cseq != Some(cseq) {
            return None;
        }
        match &self.reliable {
            Some(outstanding) if outstanding.rseq == rseq => {
                self.reliable = None;
                self.last_pracked = Some(rseq);
                let mut actions = vec![
                    ServerInviteAction::Cancel(TransactionTimer::ReliableProvisional),
                    ServerInviteAction::Cancel(TransactionTimer::ReliableProvisionalTimeout),
                ];
                actions.extend(self.release_waiting());
                Some(actions)
            }
            // A PRACK repeated on a new transaction: already acknowledged.
            _ if self.last_pracked.is_some_and(|last| rseq <= last) => Some(Vec::new()),
            _ => None,
        }
    }

    /// Handles an INVITE server-side event and yields actions.
    pub fn on_event(&mut self, event: ServerInviteEvent) -> Vec<ServerInviteAction> {
        use crate::ServerInviteState::*;
        match (&self.state, event) {
            (Proceeding, ServerInviteEvent::ReceiveInvite(invite)) => {
                self.handle_receive_invite(&invite)
            }
            (Proceeding | Completed, ServerInviteEvent::ReceiveCancel) => self.handle_cancel(),
            (Proceeding, ServerInviteEvent::SendProvisional(resp)) => self.send_provisional(resp),
            (Proceeding, ServerInviteEvent::SendFinal(resp)) => self.send_final(resp),
            (Proceeding, ServerInviteEvent::TimerFired(TransactionTimer::ReliableProvisional)) => {
                self.resend_reliable()
            }
            (
                Proceeding,
                ServerInviteEvent::TimerFired(TransactionTimer::ReliableProvisionalTimeout),
            ) => self.reliable_timed_out(),
            // One final per transaction (RFC 3261 Figure 7): once a 3xx-6xx
            // has gone out, only Timer G resends it. A second final from the
            // TU, e.g. a 200 racing the 487 for a CANCEL, is not sent.
            (Completed | Confirmed, ServerInviteEvent::SendFinal(resp)) => {
                debug!(
                    code = resp.code(),
                    "dropping a final sent after this transaction's final"
                );
                Vec::new()
            }
            (Completed, ServerInviteEvent::ReceiveAck) => self.handle_ack(),
            (Completed, ServerInviteEvent::TimerFired(TransactionTimer::G)) => {
                self.handle_timer_g()
            }
            (Completed, ServerInviteEvent::TimerFired(TransactionTimer::H)) => {
                self.handle_timer_h()
            }
            (Confirmed, ServerInviteEvent::TimerFired(TransactionTimer::I)) => {
                self.handle_timer_i()
            }
            (_, ServerInviteEvent::TransportError) => self.handle_transport_error(),
            (_, ServerInviteEvent::TimerFired(_)) => Vec::new(),
            (_, ServerInviteEvent::ReceiveAck) => Vec::new(),
            _ => Vec::new(),
        }
    }

    fn handle_receive_invite(&mut self, invite: &Request) -> Vec<ServerInviteAction> {
        // 100 Trying is TU responsibility; just remain in Proceeding.
        if self.call_id.is_none() {
            self.requires_100rel = requires_100rel(invite);
            self.call_id = sip_parse::header(invite.headers(), "Call-ID").cloned();
            self.invite_cseq = invite.headers().get("CSeq").and_then(cseq_number);
        }
        Vec::new()
    }

    pub fn on_retransmit(&self) -> Vec<ServerInviteAction> {
        if matches!(
            self.state,
            crate::ServerInviteState::Proceeding | crate::ServerInviteState::Completed
        ) {
            if let Some(bytes) = &self.last_response {
                return vec![ServerInviteAction::Transmit {
                    bytes: bytes.clone(),
                    transport: TransportKind::Udp,
                }];
            }
        }
        Vec::new()
    }

    fn handle_cancel(&mut self) -> Vec<ServerInviteAction> {
        // RFC 3261: TU should generate 487; transaction remains active until ACK.
        Vec::new()
    }

    fn send_provisional(&mut self, response: Response) -> Vec<ServerInviteAction> {
        // The outstanding one again, from a TU that resends it itself: the
        // transaction already does.
        if let Some(outstanding) = &self.reliable {
            if response_requires_prack(&response) && rseq_of(&response) == Some(outstanding.rseq) {
                return Vec::new();
            }
        }
        // Behind an outstanding reliable provisional, in order (RFC 3262 §3).
        if self.reliable.is_some() || !self.waiting.is_empty() {
            if self.held_final.is_none() {
                self.waiting.push_back(response);
            }
            return Vec::new();
        }
        self.transmit_provisional(response)
    }

    /// Sends a provisional now: reliably when it asks to be, or when the
    /// INVITE requires it of every provisional but a 100.
    fn transmit_provisional(&mut self, mut response: Response) -> Vec<ServerInviteAction> {
        if self.requires_100rel && response.code() != 100 && !response_requires_prack(&response) {
            response.headers_mut().remove("RSeq");
            let _ = response
                .headers_mut()
                .push(SmolStr::new("Require"), SmolStr::new("100rel"));
            let _ = response.headers_mut().push(
                SmolStr::new("RSeq"),
                SmolStr::new(self.next_rseq.to_string()),
            );
        }
        let bytes = serialize_response(&response);
        self.last_response = Some(bytes.clone());
        let mut actions = vec![ServerInviteAction::Transmit {
            bytes: bytes.clone(),
            transport: TransportKind::Udp,
        }];
        if response_requires_prack(&response) {
            if let Some(rseq) = rseq_of(&response) {
                self.next_rseq = rseq.wrapping_add(1).max(1);
                self.sent_reliable = true;
                let interval = self.timers.duration(TransactionTimer::ReliableProvisional);
                self.reliable = Some(OutstandingProvisional {
                    rseq,
                    bytes,
                    interval,
                    has_body: !response.body().is_empty(),
                });
                actions.push(ServerInviteAction::Schedule {
                    timer: TransactionTimer::ReliableProvisional,
                    duration: interval,
                });
                actions.push(ServerInviteAction::Schedule {
                    timer: TransactionTimer::ReliableProvisionalTimeout,
                    duration: self
                        .timers
                        .duration(TransactionTimer::ReliableProvisionalTimeout),
                });
            }
        }
        actions
    }

    /// What waited behind a reliable provisional now that it is done: the
    /// provisionals up to the next reliable one, then a held 2xx.
    fn release_waiting(&mut self) -> Vec<ServerInviteAction> {
        let mut actions = Vec::new();
        while self.reliable.is_none() {
            match self.waiting.pop_front() {
                Some(response) => actions.extend(self.transmit_provisional(response)),
                None => break,
            }
        }
        if self.reliable.is_none() {
            if let Some(response) = self.held_final.take() {
                actions.extend(self.send_final(*response));
            }
        }
        actions
    }

    fn resend_reliable(&mut self) -> Vec<ServerInviteAction> {
        let t2 = self.timers.duration(TransactionTimer::T2);
        let Some(outstanding) = &mut self.reliable else {
            return Vec::new();
        };
        outstanding.interval = (outstanding.interval * 2).min(t2);
        vec![
            ServerInviteAction::Transmit {
                bytes: outstanding.bytes.clone(),
                transport: TransportKind::Udp,
            },
            ServerInviteAction::Schedule {
                timer: TransactionTimer::ReliableProvisional,
                duration: outstanding.interval,
            },
        ]
    }

    fn reliable_timed_out(&mut self) -> Vec<ServerInviteAction> {
        let Some(outstanding) = self.reliable.take() else {
            return Vec::new();
        };
        warn!(
            call_id = ?self.call_id,
            rseq = outstanding.rseq,
            "a reliable provisional was never PRACKed; no longer sending it"
        );
        let mut actions = vec![ServerInviteAction::Cancel(
            TransactionTimer::ReliableProvisional,
        )];
        actions.extend(self.release_waiting());
        actions
    }

    fn send_final(&mut self, response: Response) -> Vec<ServerInviteAction> {
        if self.held_final.is_some() {
            debug!(
                code = response.code(),
                "dropping a final sent after a 2xx held for a PRACK"
            );
            return Vec::new();
        }
        // RFC 3262 §3: no 2xx while a provisional with a session
        // description is unacknowledged.
        if (200..=299).contains(&response.code())
            && self.reliable.as_ref().is_some_and(|r| r.has_body)
        {
            self.held_final = Some(Box::new(response));
            self.waiting.clear();
            return Vec::new();
        }
        let mut actions = Vec::new();
        if self.reliable.take().is_some() {
            actions.push(ServerInviteAction::Cancel(
                TransactionTimer::ReliableProvisional,
            ));
            actions.push(ServerInviteAction::Cancel(
                TransactionTimer::ReliableProvisionalTimeout,
            ));
        }
        self.waiting.clear();
        actions.extend(self.send_final_now(response));
        actions
    }

    fn send_final_now(&mut self, response: Response) -> Vec<ServerInviteAction> {
        let code = response.code();
        let bytes = serialize_response(&response);
        self.last_response = Some(bytes.clone());
        if (200..=299).contains(&code) {
            self.state = crate::ServerInviteState::Terminated;
            vec![
                ServerInviteAction::Transmit {
                    bytes,
                    transport: TransportKind::Udp,
                },
                ServerInviteAction::Terminate {
                    reason: SmolStr::new("2xx sent"),
                },
            ]
        } else {
            self.state = crate::ServerInviteState::Completed;
            self.last_final = Some(bytes.clone());
            self.g_interval = self.timers.duration(TransactionTimer::G);

            let mut actions = vec![ServerInviteAction::Transmit {
                bytes,
                transport: TransportKind::Udp,
            }];

            // Only schedule Timer G if duration is non-zero (UDP only)
            if !self.g_interval.is_zero() {
                actions.push(ServerInviteAction::Schedule {
                    timer: TransactionTimer::G,
                    duration: self.g_interval,
                });
            }

            // Always schedule Timer H (transaction timeout)
            actions.push(ServerInviteAction::Schedule {
                timer: TransactionTimer::H,
                duration: self.timers.duration(TransactionTimer::H),
            });

            actions
        }
    }

    fn handle_ack(&mut self) -> Vec<ServerInviteAction> {
        if self.state != crate::ServerInviteState::Completed {
            return Vec::new();
        }
        self.state = crate::ServerInviteState::Confirmed;
        vec![
            ServerInviteAction::Cancel(TransactionTimer::G),
            ServerInviteAction::Cancel(TransactionTimer::H),
            ServerInviteAction::Schedule {
                timer: TransactionTimer::I,
                duration: self.timers.duration(TransactionTimer::I), // 0 for TCP/TLS, T4 for UDP
            },
        ]
    }

    fn handle_timer_g(&mut self) -> Vec<ServerInviteAction> {
        if self.state != crate::ServerInviteState::Completed {
            return Vec::new();
        }

        // Timer G should only fire on unreliable transports (UDP)
        // If we're here on a reliable transport, don't retransmit or reschedule
        if self.timers.duration(TransactionTimer::G).is_zero() {
            return Vec::new();
        }

        if let Some(bytes) = &self.last_final {
            let action = ServerInviteAction::Transmit {
                bytes: bytes.clone(),
                transport: TransportKind::Udp,
            };
            let t2 = self.timers.duration(TransactionTimer::T2);
            self.g_interval = (self.g_interval * 2).min(t2);
            vec![
                action,
                ServerInviteAction::Schedule {
                    timer: TransactionTimer::G,
                    duration: self.g_interval,
                },
            ]
        } else {
            Vec::new()
        }
    }

    fn handle_timer_h(&mut self) -> Vec<ServerInviteAction> {
        self.state = crate::ServerInviteState::Terminated;
        vec![
            ServerInviteAction::Cancel(TransactionTimer::G),
            ServerInviteAction::Terminate {
                reason: SmolStr::new("Timer H expired"),
            },
        ]
    }

    fn handle_timer_i(&mut self) -> Vec<ServerInviteAction> {
        self.state = crate::ServerInviteState::Terminated;
        vec![
            ServerInviteAction::Cancel(TransactionTimer::I),
            ServerInviteAction::Terminate {
                reason: SmolStr::new("Timer I expired"),
            },
        ]
    }

    fn handle_transport_error(&mut self) -> Vec<ServerInviteAction> {
        if self.state == crate::ServerInviteState::Terminated {
            return Vec::new();
        }
        self.state = crate::ServerInviteState::Terminated;
        vec![ServerInviteAction::Terminate {
            reason: SmolStr::new("transport error"),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::{
        headers::Headers,
        method::Method,
        msg::{RequestLine, StatusLine},
        uri::SipUri,
    };

    fn sample_request() -> Request {
        Request::new(
            RequestLine::new(Method::Options, SipUri::parse("sip:example.com").unwrap()),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid request")
    }

    fn sample_response(code: u16) -> Response {
        Response::new(
            StatusLine::new(code, SmolStr::new("OK")).expect("valid status line"),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid response")
    }

    fn reliable_provisional(code: u16) -> Response {
        let mut response = sample_response(code);
        let _ = response
            .headers_mut()
            .push(SmolStr::new("Require"), SmolStr::new("100rel"));
        let _ = response
            .headers_mut()
            .push(SmolStr::new("RSeq"), SmolStr::new("1"));
        response
    }

    fn sample_invite() -> Request {
        Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:example.com").unwrap()),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid request")
    }

    #[test]
    fn client_non_invite_happy_path() {
        use crate::timers::{Transport, TransportAwareTimers};
        let req = sample_request();
        let resp = sample_response(200);
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ClientNonInviteFsm::new(timers);

        let actions = fsm.on_event(ClientNonInviteEvent::SendRequest(req.clone()));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::Transmit { .. })));

        let actions = fsm.on_event(ClientNonInviteEvent::ReceiveProvisional(sample_response(
            180,
        )));
        assert!(matches!(fsm.state, ClientNonInviteState::Proceeding));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::Deliver(_))));

        let actions = fsm.on_event(ClientNonInviteEvent::ReceiveFinal(resp.clone()));
        assert!(matches!(fsm.state, ClientNonInviteState::Completed));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::Deliver(_))));

        let actions = fsm.on_event(ClientNonInviteEvent::TimerFired(TransactionTimer::K));
        assert!(matches!(fsm.state, ClientNonInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::Cancel(TransactionTimer::K))));
    }

    #[test]
    fn client_invite_non2xx_flow() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ClientInviteFsm::new(timers);
        let actions = fsm.on_event(ClientInviteEvent::SendInvite(sample_invite()));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::Transmit { .. })));

        let actions = fsm.on_event(ClientInviteEvent::ReceiveProvisional(reliable_provisional(
            180,
        )));
        assert!(matches!(fsm.state, crate::ClientInviteState::Proceeding));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::ExpectPrack(_))));

        let final_resp = sample_response(486);
        let actions = fsm.on_event(ClientInviteEvent::ReceiveFinal(final_resp));
        assert!(matches!(fsm.state, crate::ClientInviteState::Completed));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::GenerateAck { is_2xx: false, .. })));
        assert!(actions.iter().any(|a| matches!(
            a,
            ClientInviteAction::Schedule {
                timer: TransactionTimer::D,
                ..
            }
        )));

        let actions = fsm.on_event(ClientInviteEvent::TimerFired(TransactionTimer::D));
        assert!(matches!(fsm.state, crate::ClientInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::Cancel(TransactionTimer::D))));
    }

    /// A server that never hears the ACK resends its final (Timer G). The
    /// client re-ACKs and tells the TU nothing (RFC 3261 §17.1.1.2): told
    /// again, a TU that answers a 401 with an authenticated INVITE sent one
    /// more for every retransmission.
    #[test]
    fn a_retransmitted_final_is_acked_again_and_not_delivered() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        fsm.on_event(ClientInviteEvent::SendInvite(sample_invite()));
        let first = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(401)));
        assert!(first
            .iter()
            .any(|a| matches!(a, ClientInviteAction::Deliver(_))));
        assert!(matches!(fsm.state, crate::ClientInviteState::Completed));

        let again = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(401)));
        assert!(
            !again
                .iter()
                .any(|a| matches!(a, ClientInviteAction::Deliver(_))),
            "a retransmitted final is not the TU's: {again:?}"
        );
        assert!(again
            .iter()
            .any(|a| matches!(a, ClientInviteAction::GenerateAck { is_2xx: false, .. })));
        assert!(matches!(fsm.state, crate::ClientInviteState::Completed));
    }

    /// After a 3xx-6xx the TU has the transaction's final. A 2xx that
    /// follows, in Completed or after Timer D, is not delivered as a
    /// second one (RFC 3261 Figure 5).
    #[test]
    fn a_2xx_after_a_non_2xx_final_is_not_delivered() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        fsm.on_event(ClientInviteEvent::SendInvite(sample_invite()));
        fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(486)));
        assert!(matches!(fsm.state, crate::ClientInviteState::Completed));

        let actions = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(200)));
        assert!(actions.is_empty(), "a 2xx in Completed: {actions:?}");
        assert!(matches!(fsm.state, crate::ClientInviteState::Completed));

        fsm.on_event(ClientInviteEvent::TimerFired(TransactionTimer::D));
        assert!(matches!(fsm.state, crate::ClientInviteState::Terminated));
        let actions = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(200)));
        assert!(actions.is_empty(), "a 2xx after Timer D: {actions:?}");
    }

    /// A 2xx retransmission still reaches the TU after the 2xx that ended
    /// the transaction, so it can re-ACK (RFC 3261 §13.2.2.4).
    #[test]
    fn a_retransmitted_2xx_is_still_delivered() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        fsm.on_event(ClientInviteEvent::SendInvite(sample_invite()));
        fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(200)));
        let again = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(200)));
        assert!(again
            .iter()
            .any(|a| matches!(a, ClientInviteAction::Deliver(_))));
    }

    /// A server transaction that sent a 3xx-6xx sends no other final: a
    /// 200 racing the 487 for a CANCEL would give the caller two.
    #[test]
    fn a_server_invite_sends_one_final() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        fsm.on_event(ServerInviteEvent::ReceiveInvite(sample_invite()));
        fsm.on_event(ServerInviteEvent::SendFinal(sample_response(487)));
        let actions = fsm.on_event(ServerInviteEvent::SendFinal(sample_response(200)));
        assert!(
            actions.is_empty(),
            "a second final in Completed: {actions:?}"
        );
        assert!(matches!(fsm.state, crate::ServerInviteState::Completed));

        fsm.on_event(ServerInviteEvent::ReceiveAck);
        let actions = fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));
        assert!(
            actions.is_empty(),
            "a second final in Confirmed: {actions:?}"
        );
        assert!(matches!(fsm.state, crate::ServerInviteState::Confirmed));
    }

    /// A transport error ends a transaction once. The second of two (two
    /// failed sends in flight) produces no `Terminate`, so the TU is not
    /// told twice.
    #[test]
    fn a_second_transport_error_ends_nothing() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = || TransportAwareTimers::new(Transport::Udp);

        let mut fsm = ClientInviteFsm::new(timers());
        fsm.on_event(ClientInviteEvent::SendInvite(sample_invite()));
        assert!(!fsm.on_event(ClientInviteEvent::TransportError).is_empty());
        assert!(fsm.on_event(ClientInviteEvent::TransportError).is_empty());

        let mut fsm = ClientNonInviteFsm::new(timers());
        fsm.on_event(ClientNonInviteEvent::SendRequest(sample_request()));
        assert!(!fsm
            .on_event(ClientNonInviteEvent::TransportError)
            .is_empty());
        assert!(fsm
            .on_event(ClientNonInviteEvent::TransportError)
            .is_empty());

        let mut fsm = ServerInviteFsm::new(timers());
        fsm.on_event(ServerInviteEvent::ReceiveInvite(sample_invite()));
        assert!(!fsm.on_event(ServerInviteEvent::TransportError).is_empty());
        assert!(fsm.on_event(ServerInviteEvent::TransportError).is_empty());

        let mut fsm = ServerNonInviteFsm::new(timers());
        fsm.on_event(ServerNonInviteEvent::ReceiveRequest(sample_request()));
        assert!(!fsm
            .on_event(ServerNonInviteEvent::TransportError)
            .is_empty());
        assert!(fsm
            .on_event(ServerNonInviteEvent::TransportError)
            .is_empty());
    }

    fn provisional_with(code: u16, headers: &[(&str, &str)]) -> Response {
        let mut response = sample_response(code);
        for (name, value) in headers {
            response
                .headers_mut()
                .push(SmolStr::new(*name), SmolStr::new(*value))
                .unwrap();
        }
        response
    }

    /// RFC 3262 §4: reliable means `Require: 100rel` and an RSeq, and a
    /// 100 is never reliable (§3).
    #[test]
    fn only_a_provisional_that_requires_100rel_is_pracked() {
        let reliable = [
            vec![("Require", "100rel"), ("RSeq", "1")],
            vec![("Require", "timer, 100REL"), ("RSeq", "1")],
            vec![("Require", "timer"), ("Require", "100rel"), ("RSeq", "1")],
        ];
        for headers in &reliable {
            assert!(
                response_requires_prack(&provisional_with(183, headers)),
                "{headers:?}"
            );
        }
        let unreliable = [
            vec![("RSeq", "1")],
            vec![("Supported", "100rel"), ("RSeq", "1")],
            vec![("Require", "timer"), ("RSeq", "1")],
            vec![("Require", "100rel")],
        ];
        for headers in &unreliable {
            assert!(
                !response_requires_prack(&provisional_with(183, headers)),
                "{headers:?}"
            );
        }
        assert!(!response_requires_prack(&provisional_with(
            100,
            &[("Require", "100rel"), ("RSeq", "1")]
        )));
    }

    #[test]
    fn client_invite_2xx_flow() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ClientInviteFsm::new(timers);
        fsm.on_event(ClientInviteEvent::SendInvite(sample_invite()));
        let actions = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(200)));
        assert!(matches!(fsm.state, crate::ClientInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::GenerateAck { is_2xx: true, .. })));
    }

    #[test]
    fn server_invite_non2xx_flow() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ServerInviteFsm::new(timers);
        fsm.on_event(ServerInviteEvent::ReceiveInvite(sample_invite()));
        let actions = fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));
        assert!(matches!(fsm.state, crate::ServerInviteState::Completed));
        assert!(actions.iter().any(|a| matches!(
            a,
            ServerInviteAction::Schedule {
                timer: TransactionTimer::G,
                ..
            }
        )));
        assert!(actions.iter().any(|a| matches!(
            a,
            ServerInviteAction::Schedule {
                timer: TransactionTimer::H,
                ..
            }
        )));

        let actions = fsm.on_event(ServerInviteEvent::TimerFired(TransactionTimer::G));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })));

        let actions = fsm.on_event(ServerInviteEvent::ReceiveAck);
        assert!(matches!(fsm.state, crate::ServerInviteState::Confirmed));
        assert!(actions.iter().any(|a| matches!(
            a,
            ServerInviteAction::Schedule {
                timer: TransactionTimer::I,
                ..
            }
        )));

        let actions = fsm.on_event(ServerInviteEvent::TimerFired(TransactionTimer::I));
        assert!(matches!(fsm.state, crate::ServerInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Cancel(TransactionTimer::I))));
    }

    #[test]
    fn server_invite_retransmits_last_final() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ServerInviteFsm::new(timers);
        fsm.on_event(ServerInviteEvent::ReceiveInvite(sample_invite()));
        fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));
        let actions = fsm.on_retransmit();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })));
    }

    #[test]
    fn server_invite_2xx_flow() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ServerInviteFsm::new(timers);
        fsm.on_event(ServerInviteEvent::ReceiveInvite(sample_invite()));
        let actions = fsm.on_event(ServerInviteEvent::SendFinal(sample_response(200)));
        assert!(matches!(fsm.state, crate::ServerInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })));
    }

    #[test]
    fn client_non_invite_timeout() {
        use crate::timers::{Transport, TransportAwareTimers};
        let req = sample_request();
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ClientNonInviteFsm::new(timers);
        fsm.on_event(ClientNonInviteEvent::SendRequest(req));
        let actions = fsm.on_event(ClientNonInviteEvent::TimerFired(TransactionTimer::F));
        assert!(matches!(fsm.state, ClientNonInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::Terminate { .. })));
    }

    #[test]
    fn server_non_invite_flow() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ServerNonInviteFsm::new(timers);
        let req = sample_request();
        let actions = fsm.on_event(ServerNonInviteEvent::ReceiveRequest(req));
        assert!(actions.is_empty());
        let resp = sample_response(200);
        let actions = fsm.on_event(ServerNonInviteEvent::SendFinal(resp));
        assert!(matches!(fsm.state, ServerNonInviteState::Completed));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerAction::Schedule { .. })));
        let actions = fsm.on_event(ServerNonInviteEvent::TimerFired(TransactionTimer::J));
        assert!(matches!(fsm.state, ServerNonInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerAction::Cancel(TransactionTimer::J))));
    }

    #[test]
    fn server_non_invite_retransmits_final() {
        use crate::timers::{Transport, TransportAwareTimers};
        let timers = TransportAwareTimers::new(Transport::Udp);
        let mut fsm = ServerNonInviteFsm::new(timers);
        let req = sample_request();
        fsm.on_event(ServerNonInviteEvent::ReceiveRequest(req));
        fsm.on_event(ServerNonInviteEvent::SendFinal(sample_response(200)));
        let actions = fsm.on_retransmit();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerAction::Transmit { .. })));
    }

    /// An INVITE carrying `Require: 100rel`, Call-ID and CSeq.
    fn invite_requiring_100rel() -> Request {
        let mut invite = sample_invite();
        for (name, value) in [
            ("Call-ID", "rel@example.com"),
            ("CSeq", "7 INVITE"),
            ("Require", "100rel"),
        ] {
            let _ = invite
                .headers_mut()
                .push(SmolStr::new(name), SmolStr::new(value));
        }
        invite
    }

    fn sent(actions: &[ServerInviteAction]) -> Vec<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                ServerInviteAction::Transmit { bytes, .. } => {
                    Some(String::from_utf8_lossy(bytes).into_owned())
                }
                _ => None,
            })
            .collect()
    }

    fn rseq_in(text: &str) -> u32 {
        text.lines()
            .find_map(|l| l.strip_prefix("RSeq: "))
            .expect("an RSeq")
            .trim()
            .parse()
            .unwrap()
    }

    fn schedules(actions: &[ServerInviteAction], timer: TransactionTimer) -> Option<Duration> {
        actions.iter().find_map(|a| match a {
            ServerInviteAction::Schedule { timer: t, duration } if *t == timer => Some(*duration),
            _ => None,
        })
    }

    fn with_body(response: Response) -> Response {
        Response::new(
            response.start_line().clone(),
            response.headers().clone(),
            Bytes::from_static(b"v=0\r\n"),
        )
        .unwrap()
    }

    /// RFC 3262 §3: the INVITE requires 100rel, so every provisional but a
    /// 100 goes out reliably, sent again from T1 doubling to T2, one at a
    /// time, until its PRACK.
    #[test]
    fn a_caller_requiring_100rel_gets_every_provisional_reliably() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        fsm.on_event(ServerInviteEvent::ReceiveInvite(invite_requiring_100rel()));

        let trying = sent(&fsm.on_event(ServerInviteEvent::SendProvisional(sample_response(100))));
        assert!(!trying[0].contains("RSeq"), "a 100 is never reliable");
        assert_eq!(fsm.prack_call_id(), None);

        let actions = fsm.on_event(ServerInviteEvent::SendProvisional(sample_response(180)));
        let ringing = &sent(&actions)[0];
        assert!(ringing.contains("Require: 100rel"), "{ringing}");
        let first = rseq_in(ringing);
        assert!((1..=1 << 30).contains(&first));
        assert_eq!(
            schedules(&actions, TransactionTimer::ReliableProvisional),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            schedules(&actions, TransactionTimer::ReliableProvisionalTimeout),
            Some(Duration::from_secs(32))
        );
        assert_eq!(
            fsm.prack_call_id().map(|c| c.as_str()),
            Some("rel@example.com")
        );

        // Sent again, the interval doubling to T2.
        let mut intervals = Vec::new();
        for _ in 0..5 {
            let actions = fsm.on_event(ServerInviteEvent::TimerFired(
                TransactionTimer::ReliableProvisional,
            ));
            assert_eq!(rseq_in(&sent(&actions)[0]), first);
            intervals.push(schedules(&actions, TransactionTimer::ReliableProvisional).unwrap());
        }
        assert_eq!(
            intervals,
            [1000, 2000, 4000, 4000, 4000].map(Duration::from_millis)
        );

        // A 183 meanwhile waits its turn.
        assert!(fsm
            .on_event(ServerInviteEvent::SendProvisional(sample_response(183)))
            .is_empty());

        // Neither another RSeq nor another INVITE's CSeq is a PRACK for it.
        assert!(fsm.on_prack(first + 1, 7).is_none());
        assert!(fsm.on_prack(first, 8).is_none());

        let actions = fsm.on_prack(first, 7).expect("the PRACK matches");
        assert!(actions.contains(&ServerInviteAction::Cancel(
            TransactionTimer::ReliableProvisional
        )));
        let progress = &sent(&actions)[0];
        assert!(progress.starts_with("SIP/2.0 183"), "{progress}");
        assert_eq!(rseq_in(progress), first + 1);

        // The same PRACK again is answered, and releases nothing.
        assert_eq!(fsm.on_prack(first, 7), Some(Vec::new()));
        // Once acknowledged, a provisional is not sent again.
        fsm.on_prack(first + 1, 7).expect("the 183's PRACK");
        assert!(fsm
            .on_event(ServerInviteEvent::TimerFired(
                TransactionTimer::ReliableProvisional
            ))
            .is_empty());
    }

    /// RFC 3262 §3: no 2xx while a provisional with a session description
    /// is unacknowledged; its PRACK lets the 2xx out.
    #[test]
    fn a_2xx_waits_for_the_prack_of_early_media() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        fsm.on_event(ServerInviteEvent::ReceiveInvite(invite_requiring_100rel()));
        let progress = sent(&fsm.on_event(ServerInviteEvent::SendProvisional(with_body(
            sample_response(183),
        ))));
        let rseq = rseq_in(&progress[0]);

        assert!(fsm
            .on_event(ServerInviteEvent::SendFinal(sample_response(200)))
            .is_empty());
        assert_eq!(fsm.state(), crate::ServerInviteState::Proceeding);
        // A final after it (a 487 racing the answer) is not sent.
        assert!(fsm
            .on_event(ServerInviteEvent::SendFinal(sample_response(487)))
            .is_empty());

        let actions = fsm.on_prack(rseq, 7).unwrap();
        assert!(sent(&actions)[0].starts_with("SIP/2.0 200"));
        assert_eq!(fsm.state(), crate::ServerInviteState::Terminated);
    }

    /// A provisional without a session description does not hold the 2xx;
    /// the 2xx stops it being sent again.
    #[test]
    fn a_2xx_after_ringing_goes_at_once() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Tcp));
        fsm.on_event(ServerInviteEvent::ReceiveInvite(invite_requiring_100rel()));
        let actions = fsm.on_event(ServerInviteEvent::SendProvisional(sample_response(180)));
        // Sent again on a reliable transport too: it is the UAS's to resend.
        assert_eq!(
            schedules(&actions, TransactionTimer::ReliableProvisional),
            Some(Duration::from_millis(500))
        );
        let actions = fsm.on_event(ServerInviteEvent::SendFinal(sample_response(200)));
        assert!(actions.contains(&ServerInviteAction::Cancel(
            TransactionTimer::ReliableProvisional
        )));
        assert!(sent(&actions)[0].starts_with("SIP/2.0 200"));
    }

    /// 64·T1 without a PRACK: the provisional is no longer sent and what
    /// waited behind it goes out; the call is not refused.
    #[test]
    fn a_provisional_never_pracked_stops_and_lets_the_rest_go() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        fsm.on_event(ServerInviteEvent::ReceiveInvite(invite_requiring_100rel()));
        fsm.on_event(ServerInviteEvent::SendProvisional(with_body(
            sample_response(183),
        )));
        fsm.on_event(ServerInviteEvent::SendFinal(sample_response(200)));
        let actions = fsm.on_event(ServerInviteEvent::TimerFired(
            TransactionTimer::ReliableProvisionalTimeout,
        ));
        assert!(actions.contains(&ServerInviteAction::Cancel(
            TransactionTimer::ReliableProvisional
        )));
        assert!(sent(&actions)[0].starts_with("SIP/2.0 200"));
    }

    /// Without `Require: 100rel` a provisional is sent as it is, and one the
    /// transaction user made reliable is kept to its own RSeq.
    #[test]
    fn a_caller_not_requiring_100rel_gets_what_the_tu_sends() {
        use crate::timers::{Transport, TransportAwareTimers};
        let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));
        let mut invite = invite_requiring_100rel();
        invite.headers_mut().remove("Require");
        fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));

        let actions = fsm.on_event(ServerInviteEvent::SendProvisional(sample_response(180)));
        assert!(!sent(&actions)[0].contains("RSeq"));
        assert_eq!(
            schedules(&actions, TransactionTimer::ReliableProvisional),
            None
        );

        let actions = fsm.on_event(ServerInviteEvent::SendProvisional(reliable_provisional(
            183,
        )));
        assert_eq!(rseq_in(&sent(&actions)[0]), 1);
        // The TU resending it is left to the transaction, not queued.
        assert!(fsm
            .on_event(ServerInviteEvent::SendProvisional(reliable_provisional(
                183
            )))
            .is_empty());
        assert!(fsm.on_prack(1, 7).is_some());
    }
}
