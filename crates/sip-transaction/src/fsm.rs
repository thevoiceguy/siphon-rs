use std::time::Duration;

use bytes::Bytes;
use sip_core::{Request, Response};
use sip_parse::{serialize_request, serialize_response};
use smol_str::SmolStr;

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
pub struct ClientNonInviteFsm {
    pub state: ClientNonInviteState,
    t1: Duration,
    t2: Duration,
    t4: Duration,
    e_interval: Duration,
    last_request: Option<Bytes>,
}

/// Implements the client INVITE transaction state machine.
pub struct ClientInviteFsm {
    pub state: crate::ClientInviteState,
    t1: Duration,
    t2: Duration,
    a_interval: Duration,
    last_invite: Option<Bytes>,
}

impl ClientInviteFsm {
    /// Creates a new INVITE transaction FSM with the provided T1/T2 timers.
    pub fn new(t1: Duration, t2: Duration) -> Self {
        Self {
            state: crate::ClientInviteState::Calling,
            t1,
            t2,
            a_interval: t1,
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
                duration: self.t1,
            },
            ClientInviteAction::Schedule {
                timer: TransactionTimer::B,
                duration: self.t1.saturating_mul(64),
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
                duration: Duration::from_secs(32),
            });
        }
        actions
    }

    fn handle_timer_a(&mut self) -> Vec<ClientInviteAction> {
        if !matches!(self.state, crate::ClientInviteState::Calling) {
            return Vec::new();
        }
        self.a_interval = (self.a_interval * 2).min(self.t2);
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
    /// Creates a new FSM ready to send a request with the provided T1/T2/T4 timers.
    pub fn new(t1: Duration, t2: Duration, t4: Duration) -> Self {
        Self {
            state: ClientNonInviteState::Trying,
            t1,
            t2,
            t4,
            e_interval: t1,
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
                duration: self.t1,
            },
            ClientAction::Schedule {
                timer: TransactionTimer::F,
                duration: self.t1.saturating_mul(64),
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
                duration: self.t4,  // RFC 3261 Table 4: T4 for UDP (5s), 0 for TCP
            },
        ]
    }

    fn handle_timer_e(&mut self) -> Vec<ClientAction> {
        if self.state == ClientNonInviteState::Completed {
            return Vec::new();
        }
        self.e_interval = (self.e_interval * 2).min(self.t2);
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
pub struct ServerNonInviteFsm {
    pub state: ServerNonInviteState,
    t1: Duration,
    last_final: Option<Bytes>,
}

impl ServerNonInviteFsm {
    /// Creates a server FSM in the `Trying` state.
    pub fn new(t1: Duration) -> Self {
        Self {
            state: ServerNonInviteState::Trying,
            t1,
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
                duration: self.t1.saturating_mul(64),  // RFC 3261 Table 4: 64*T1 for UDP (32s)
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
}

/// Implements the server INVITE transaction state machine.
pub struct ServerInviteFsm {
    pub state: crate::ServerInviteState,
    t1: Duration,
    t2: Duration,
    t4: Duration,
    g_interval: Duration,
    last_final: Option<Bytes>,
}

impl ServerInviteFsm {
    /// Creates a new server INVITE FSM.
    pub fn new(t1: Duration, t2: Duration, t4: Duration) -> Self {
        Self {
            state: crate::ServerInviteState::Proceeding,
            t1,
            t2,
            t4,
            g_interval: t1,
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
            self.g_interval = self.t1;
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
                    duration: self.t1.saturating_mul(64),
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
                duration: self.t4,  // RFC 3261 Table 4: T4 for UDP (5s), 0 for TCP
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
            self.g_interval = (self.g_interval * 2).min(self.t2);
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
        let req = sample_request();
        let resp = sample_response(200);
        let mut fsm = ClientNonInviteFsm::new(Duration::from_millis(500), Duration::from_secs(4), Duration::from_secs(5));

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
        let mut fsm = ClientInviteFsm::new(Duration::from_millis(500), Duration::from_secs(4));
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
        let mut fsm = ClientInviteFsm::new(Duration::from_millis(500), Duration::from_secs(4));
        fsm.on_event(ClientInviteEvent::SendInvite(sample_invite()));
        let actions = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(200)));
        assert!(matches!(fsm.state, crate::ClientInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::GenerateAck { is_2xx: true, .. })));
    }

    #[test]
    fn server_invite_non2xx_flow() {
        let mut fsm = ServerInviteFsm::new(Duration::from_millis(500), Duration::from_secs(4), Duration::from_secs(5));
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
        let mut fsm = ServerInviteFsm::new(Duration::from_millis(500), Duration::from_secs(4), Duration::from_secs(5));
        fsm.on_event(ServerInviteEvent::ReceiveInvite(sample_invite()));
        fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));
        let actions = fsm.on_retransmit();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })));
    }

    #[test]
    fn server_invite_2xx_flow() {
        let mut fsm = ServerInviteFsm::new(Duration::from_millis(500), Duration::from_secs(4), Duration::from_secs(5));
        fsm.on_event(ServerInviteEvent::ReceiveInvite(sample_invite()));
        let actions = fsm.on_event(ServerInviteEvent::SendFinal(sample_response(200)));
        assert!(matches!(fsm.state, crate::ServerInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })));
    }

    #[test]
    fn client_non_invite_timeout() {
        let req = sample_request();
        let mut fsm = ClientNonInviteFsm::new(Duration::from_millis(500), Duration::from_secs(4), Duration::from_secs(5));
        fsm.on_event(ClientNonInviteEvent::SendRequest(req));
        let actions = fsm.on_event(ClientNonInviteEvent::TimerFired(TransactionTimer::F));
        assert!(matches!(fsm.state, ClientNonInviteState::Terminated));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::Terminate { .. })));
    }

    #[test]
    fn server_non_invite_flow() {
        let mut fsm = ServerNonInviteFsm::new(Duration::from_millis(500));
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
        let mut fsm = ServerNonInviteFsm::new(Duration::from_millis(500));
        let req = sample_request();
        fsm.on_event(ServerNonInviteEvent::ReceiveRequest(req));
        fsm.on_event(ServerNonInviteEvent::SendFinal(sample_response(200)));
        let actions = fsm.on_retransmit();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ServerAction::Transmit { .. })));
    }
}
