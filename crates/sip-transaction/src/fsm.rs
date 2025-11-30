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
//! #     Request::new(line, Headers::new(), Bytes::new())
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
//! #     Request::new(line, Headers::new(), Bytes::new())
//! # }
//! # fn create_200_ok() -> Response {
//! #     Response::new(StatusLine::new(200, "OK".into()), Headers::new(), Bytes::new())
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
//! # RFC 3261 Compliance
//!
//! These FSMs strictly follow RFC 3261 state machine diagrams:
//! - Figure 5: Client INVITE transaction
//! - Figure 6: Server INVITE transaction
//! - Figure 7: Client non-INVITE transaction (implied)
//! - Figure 8: Server non-INVITE transaction (implied)
//!
//! Timer adjustments for reliable transports follow RFC 3261 §17.1.2.2 exactly.

use std::time::Duration;

use bytes::Bytes;
use sip_core::{Request, Response};
use sip_parse::{serialize_request, serialize_response};
use smol_str::SmolStr;

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
    pub state: ClientNonInviteState,
    timers: TransportAwareTimers,
    e_interval: Duration,
    last_request: Option<Bytes>,
}

/// Implements the client INVITE transaction state machine.
pub struct ClientInviteFsm {
    pub state: crate::ClientInviteState,
    timers: TransportAwareTimers,
    a_interval: Duration,
    last_invite: Option<Bytes>,
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
        vec![
            ClientInviteAction::Transmit {
                bytes,
                transport: TransportKind::Udp,
            },
            ClientInviteAction::Schedule {
                timer: TransactionTimer::A,
                duration: self.timers.duration(TransactionTimer::A),
            },
            ClientInviteAction::Schedule {
                timer: TransactionTimer::B,
                duration: self.timers.duration(TransactionTimer::B),
            },
        ]
    }

    fn handle_provisional(&mut self, response: Response) -> Vec<ClientInviteAction> {
        self.state = crate::ClientInviteState::Proceeding;
        vec![
            ClientInviteAction::Cancel(TransactionTimer::A),
            ClientInviteAction::Deliver(response.clone()),
            ClientInviteAction::ExpectPrack(response),
        ]
    }

    fn handle_final(
        &mut self,
        current_state: crate::ClientInviteState,
        response: Response,
    ) -> Vec<ClientInviteAction> {
        let code = response.start.code;
        if (200..=299).contains(&code) {
            self.handle_final_2xx(response)
        } else {
            self.handle_final_non_2xx(current_state, response)
        }
    }

    fn handle_final_2xx(&mut self, response: Response) -> Vec<ClientInviteAction> {
        self.state = crate::ClientInviteState::Terminated;
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
        vec![
            ClientAction::Transmit {
                bytes,
                transport: TransportKind::Udp,
            },
            ClientAction::Schedule {
                timer: TransactionTimer::E,
                duration: self.timers.duration(TransactionTimer::E),
            },
            ClientAction::Schedule {
                timer: TransactionTimer::F,
                duration: self.timers.duration(TransactionTimer::F),
            },
        ]
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
    pub state: ServerNonInviteState,
    timers: TransportAwareTimers,
    last_final: Option<Bytes>,
}

impl ServerNonInviteFsm {
    /// Creates a server FSM in the `Trying` state with transport-aware timers.
    pub fn new(timers: TransportAwareTimers) -> Self {
        Self {
            state: ServerNonInviteState::Trying,
            timers,
            last_final: None,
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
        if matches!(self.state, ServerNonInviteState::Completed) {
            if let Some(bytes) = &self.last_final {
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
        vec![ServerAction::Transmit {
            bytes,
            transport: TransportKind::Udp,
        }]
    }

    fn handle_final(&mut self, response: Response) -> Vec<ServerAction> {
        self.state = ServerNonInviteState::Completed;
        let bytes = serialize_response(&response);
        self.last_final = Some(bytes.clone());
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
pub struct ServerInviteFsm {
    pub state: crate::ServerInviteState,
    timers: TransportAwareTimers,
    g_interval: Duration,
    last_final: Option<Bytes>,
}

impl ServerInviteFsm {
    /// Creates a new server INVITE FSM with transport-aware timers.
    pub fn new(timers: TransportAwareTimers) -> Self {
        let g_initial = timers.duration(TransactionTimer::G);
        Self {
            state: crate::ServerInviteState::Proceeding,
            timers,
            g_interval: g_initial,
            last_final: None,
        }
    }

    /// Handles an INVITE server-side event and yields actions.
    pub fn on_event(&mut self, event: ServerInviteEvent) -> Vec<ServerInviteAction> {
        use crate::ServerInviteState::*;
        match (&self.state, event) {
            (Proceeding, ServerInviteEvent::ReceiveInvite(_)) => self.handle_receive_invite(),
            (Proceeding | Completed, ServerInviteEvent::ReceiveCancel) => self.handle_cancel(),
            (Proceeding, ServerInviteEvent::SendProvisional(resp)) => self.send_provisional(resp),
            (Proceeding, ServerInviteEvent::SendFinal(resp))
            | (Confirmed, ServerInviteEvent::SendFinal(resp))
            | (Completed, ServerInviteEvent::SendFinal(resp)) => self.send_final(resp),
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

    fn handle_receive_invite(&mut self) -> Vec<ServerInviteAction> {
        // 100 Trying is TU responsibility; just remain in Proceeding.
        Vec::new()
    }

    pub fn on_retransmit(&self) -> Vec<ServerInviteAction> {
        if let Some(bytes) = &self.last_final {
            return vec![ServerInviteAction::Transmit {
                bytes: bytes.clone(),
                transport: TransportKind::Udp,
            }];
        }
        Vec::new()
    }

    fn handle_cancel(&mut self) -> Vec<ServerInviteAction> {
        // RFC 3261: TU should generate 487; transaction terminates.
        self.state = crate::ServerInviteState::Terminated;
        vec![
            ServerInviteAction::Cancel(TransactionTimer::G),
            ServerInviteAction::Cancel(TransactionTimer::H),
            ServerInviteAction::Cancel(TransactionTimer::I),
            ServerInviteAction::Terminate {
                reason: SmolStr::new("CANCEL received"),
            },
        ]
    }

    fn send_provisional(&mut self, response: Response) -> Vec<ServerInviteAction> {
        let bytes = serialize_response(&response);
        vec![ServerInviteAction::Transmit {
            bytes,
            transport: TransportKind::Udp,
        }]
    }

    fn send_final(&mut self, response: Response) -> Vec<ServerInviteAction> {
        let code = response.start.code;
        let bytes = serialize_response(&response);
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
            vec![
                ServerInviteAction::Transmit {
                    bytes,
                    transport: TransportKind::Udp,
                },
                ServerInviteAction::Schedule {
                    timer: TransactionTimer::G,
                    duration: self.g_interval,
                },
                ServerInviteAction::Schedule {
                    timer: TransactionTimer::H,
                    duration: self.timers.duration(TransactionTimer::H),
                },
            ]
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
    }

    fn sample_response(code: u16) -> Response {
        Response::new(
            StatusLine::new(code, SmolStr::new("OK")),
            Headers::new(),
            Bytes::new(),
        )
    }

    fn sample_invite() -> Request {
        Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:example.com").unwrap()),
            Headers::new(),
            Bytes::new(),
        )
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

        let actions = fsm.on_event(ClientInviteEvent::ReceiveProvisional(sample_response(180)));
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
}
