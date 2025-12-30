// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use bytes::Bytes;
use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri, StatusLine};
use sip_transaction::fsm::{
    ClientAction, ClientInviteAction, ClientInviteEvent, ClientInviteFsm, ClientNonInviteEvent,
    ClientNonInviteFsm, ServerAction, ServerInviteAction, ServerInviteEvent, ServerInviteFsm,
    ServerNonInviteEvent, ServerNonInviteFsm,
};
use sip_transaction::timers::{Transport, TransportAwareTimers};
use sip_transaction::{ClientNonInviteState, ServerNonInviteState, TransactionTimer};
use smol_str::SmolStr;
use std::time::Duration;

// Helper functions for creating test messages
fn sample_request() -> Request {
    Request::new(
        RequestLine::new(Method::Options, SipUri::parse("sip:example.com").unwrap()),
        Headers::new(),
        Bytes::new(),
    )
    .expect("valid request")
}

fn sample_invite() -> Request {
    Request::new(
        RequestLine::new(Method::Invite, SipUri::parse("sip:example.com").unwrap()),
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

// ==========================
// Client Non-INVITE Tests
// ==========================

#[test]
fn client_non_invite_retransmission_on_timer_e() {
    let req = sample_request();
    let mut fsm = ClientNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    // Send request
    fsm.on_event(ClientNonInviteEvent::SendRequest(req.clone()));

    // Move to Trying state, then Timer E should trigger retransmission
    let actions = fsm.on_event(ClientNonInviteEvent::TimerFired(TransactionTimer::E));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientAction::Transmit { .. })),
        "Timer E should trigger retransmission"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ClientAction::Schedule {
                timer: TransactionTimer::E,
                ..
            }
        )),
        "Timer E should be rescheduled"
    );
}

#[test]
fn client_non_invite_duplicate_final_response_ignored() {
    let req = sample_request();
    let resp = sample_response(200);
    let mut fsm = ClientNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientNonInviteEvent::SendRequest(req));
    fsm.on_event(ClientNonInviteEvent::ReceiveFinal(resp.clone()));
    assert!(matches!(fsm.state(), ClientNonInviteState::Completed));

    // Duplicate final response should be absorbed
    let actions = fsm.on_event(ClientNonInviteEvent::ReceiveFinal(resp.clone()));
    assert!(
        actions.is_empty()
            || !actions
                .iter()
                .any(|a| matches!(a, ClientAction::Deliver(_))),
        "Duplicate final responses should not be delivered again"
    );
}

#[test]
fn client_non_invite_transport_error() {
    let req = sample_request();
    let mut fsm = ClientNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientNonInviteEvent::SendRequest(req));

    let actions = fsm.on_event(ClientNonInviteEvent::TransportError);
    assert!(matches!(fsm.state(), ClientNonInviteState::Terminated));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientAction::Terminate { .. })),
        "Transport error should terminate transaction"
    );
}

#[test]
fn client_non_invite_timer_f_timeout() {
    let req = sample_request();
    let mut fsm = ClientNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientNonInviteEvent::SendRequest(req));

    // Timer F fires when no response received
    let actions = fsm.on_event(ClientNonInviteEvent::TimerFired(TransactionTimer::F));
    assert!(matches!(fsm.state(), ClientNonInviteState::Terminated));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientAction::Terminate { .. })),
        "Timer F should terminate transaction on timeout"
    );
}

#[test]
fn client_non_invite_proceeding_to_completed() {
    let req = sample_request();
    let mut fsm = ClientNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientNonInviteEvent::SendRequest(req));

    // Receive provisional
    let actions = fsm.on_event(ClientNonInviteEvent::ReceiveProvisional(sample_response(
        180,
    )));
    assert!(matches!(fsm.state(), ClientNonInviteState::Proceeding));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientAction::Deliver(_))),
        "Provisional response should be delivered"
    );

    // Additional provisionals should also be delivered
    let actions = fsm.on_event(ClientNonInviteEvent::ReceiveProvisional(sample_response(
        183,
    )));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientAction::Deliver(_))),
        "Additional provisionals should be delivered"
    );

    // Final response
    let actions = fsm.on_event(ClientNonInviteEvent::ReceiveFinal(sample_response(200)));
    assert!(matches!(fsm.state(), ClientNonInviteState::Completed));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientAction::Deliver(_))),
        "Final response should be delivered"
    );
}

// ==========================
// Client INVITE Tests
// ==========================

#[test]
fn client_invite_timer_a_retransmission() {
    let invite = sample_invite();
    let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientInviteEvent::SendInvite(invite));

    // Timer A should trigger retransmission
    let actions = fsm.on_event(ClientInviteEvent::TimerFired(TransactionTimer::A));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::Transmit { .. })),
        "Timer A should trigger INVITE retransmission"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ClientInviteAction::Schedule {
                timer: TransactionTimer::A,
                duration
            } if duration > &Duration::from_millis(500)
        )),
        "Timer A should be rescheduled with exponential backoff"
    );
}

#[test]
fn client_invite_timer_b_timeout() {
    let invite = sample_invite();
    let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientInviteEvent::SendInvite(invite));

    // Timer B fires when no final response received
    let actions = fsm.on_event(ClientInviteEvent::TimerFired(TransactionTimer::B));
    assert!(matches!(
        fsm.state(),
        sip_transaction::ClientInviteState::Terminated
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::Terminate { .. })),
        "Timer B should terminate transaction"
    );
}

#[test]
fn client_invite_provisional_with_rseq() {
    let invite = sample_invite();
    let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientInviteEvent::SendInvite(invite));

    // Receive reliable provisional (with RSeq and Require: 100rel per RFC 3262)
    let mut headers = Headers::new();
    headers
        .push(SmolStr::new("RSeq"), SmolStr::new("1"))
        .unwrap();
    headers
        .push(SmolStr::new("Require"), SmolStr::new("100rel"))
        .unwrap();
    let mut resp = sample_response(183);
    *resp.headers_mut() = headers;

    let actions = fsm.on_event(ClientInviteEvent::ReceiveProvisional(resp.clone()));
    assert!(matches!(
        fsm.state(),
        sip_transaction::ClientInviteState::Proceeding
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::ExpectPrack(_))),
        "Reliable provisional should trigger PRACK expectation"
    );
}

#[test]
fn client_invite_3xx_4xx_5xx_6xx_requires_ack() {
    for code in [300, 404, 503, 603] {
        let invite = sample_invite();
        let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

        fsm.on_event(ClientInviteEvent::SendInvite(invite));
        let actions = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(code)));

        assert!(
            matches!(fsm.state(), sip_transaction::ClientInviteState::Completed),
            "Non-2xx final should move to Completed for code {}",
            code
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, ClientInviteAction::GenerateAck { is_2xx: false, .. })),
            "Non-2xx final should generate ACK for code {}",
            code
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                ClientInviteAction::Schedule {
                    timer: TransactionTimer::D,
                    ..
                }
            )),
            "Timer D should be scheduled for code {}",
            code
        );
    }
}

#[test]
fn client_invite_2xx_immediate_termination() {
    let invite = sample_invite();
    let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientInviteEvent::SendInvite(invite));
    let actions = fsm.on_event(ClientInviteEvent::ReceiveFinal(sample_response(200)));

    assert!(matches!(
        fsm.state(),
        sip_transaction::ClientInviteState::Terminated
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::GenerateAck { is_2xx: true, .. })),
        "2xx should generate ACK"
    );
    assert!(
        !actions.iter().any(|a| matches!(
            a,
            ClientInviteAction::Schedule {
                timer: TransactionTimer::D,
                ..
            }
        )),
        "Timer D should NOT be scheduled for 2xx"
    );
}

#[test]
fn client_invite_transport_error_in_calling() {
    let invite = sample_invite();
    let mut fsm = ClientInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ClientInviteEvent::SendInvite(invite));
    let actions = fsm.on_event(ClientInviteEvent::TransportError);

    assert!(matches!(
        fsm.state(),
        sip_transaction::ClientInviteState::Terminated
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ClientInviteAction::Terminate { .. })),
        "Transport error should terminate transaction"
    );
}

// ==========================
// Server Non-INVITE Tests
// ==========================

#[test]
fn server_non_invite_absorbs_retransmitted_request() {
    let req = sample_request();
    let mut fsm = ServerNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerNonInviteEvent::ReceiveRequest(req.clone()));
    fsm.on_event(ServerNonInviteEvent::SendFinal(sample_response(200)));
    assert!(matches!(fsm.state(), ServerNonInviteState::Completed));

    // Retransmitted request in Completed state
    let actions = fsm.on_retransmit();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerAction::Transmit { .. })),
        "Should retransmit final response for duplicate request"
    );
}

#[test]
fn server_non_invite_timer_j_termination() {
    let req = sample_request();
    let mut fsm = ServerNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerNonInviteEvent::ReceiveRequest(req));
    fsm.on_event(ServerNonInviteEvent::SendFinal(sample_response(200)));

    let actions = fsm.on_event(ServerNonInviteEvent::TimerFired(TransactionTimer::J));
    assert!(matches!(fsm.state(), ServerNonInviteState::Terminated));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerAction::Cancel(TransactionTimer::J))),
        "Timer J should terminate transaction"
    );
}

#[test]
fn server_non_invite_provisional_then_final() {
    let req = sample_request();
    let mut fsm = ServerNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerNonInviteEvent::ReceiveRequest(req));

    // Send provisional (should be in Proceeding state after receiving request)
    let actions = fsm.on_event(ServerNonInviteEvent::SendProvisional(sample_response(180)));
    assert!(matches!(fsm.state(), ServerNonInviteState::Proceeding));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerAction::Transmit { .. })),
        "Provisional should be transmitted"
    );

    // Send final
    let actions = fsm.on_event(ServerNonInviteEvent::SendFinal(sample_response(200)));
    assert!(matches!(fsm.state(), ServerNonInviteState::Completed));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerAction::Transmit { .. })),
        "Final response should be transmitted"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ServerAction::Schedule {
                timer: TransactionTimer::J,
                ..
            }
        )),
        "Timer J should be scheduled"
    );
}

#[test]
fn server_non_invite_transport_error() {
    let req = sample_request();
    let mut fsm = ServerNonInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerNonInviteEvent::ReceiveRequest(req));
    let actions = fsm.on_event(ServerNonInviteEvent::TransportError);

    assert!(matches!(fsm.state(), ServerNonInviteState::Terminated));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerAction::Terminate { .. })),
        "Transport error should terminate transaction"
    );
}

// ==========================
// Server INVITE Tests
// ==========================

#[test]
fn server_invite_timer_g_retransmission() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));
    fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));
    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Completed
    ));

    // Timer G should trigger retransmission of final response
    let actions = fsm.on_event(ServerInviteEvent::TimerFired(TransactionTimer::G));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })),
        "Timer G should retransmit final response"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ServerInviteAction::Schedule {
                timer: TransactionTimer::G,
                duration
            } if duration > &Duration::from_millis(500)
        )),
        "Timer G should be rescheduled with exponential backoff"
    );
}

#[test]
fn server_invite_timer_h_timeout() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));
    fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));

    // Timer H fires when ACK not received
    let actions = fsm.on_event(ServerInviteEvent::TimerFired(TransactionTimer::H));
    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Terminated
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Terminate { .. })),
        "Timer H should terminate transaction"
    );
}

#[test]
fn server_invite_ack_moves_to_confirmed() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));
    fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));
    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Completed
    ));

    let actions = fsm.on_event(ServerInviteEvent::ReceiveAck);
    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Confirmed
    ));
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ServerInviteAction::Schedule {
                timer: TransactionTimer::I,
                ..
            }
        )),
        "Timer I should be scheduled on ACK receipt"
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Cancel(TransactionTimer::G))),
        "Timer G should be cancelled on ACK receipt"
    );
}

#[test]
fn server_invite_timer_i_termination() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));
    fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));
    fsm.on_event(ServerInviteEvent::ReceiveAck);
    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Confirmed
    ));

    let actions = fsm.on_event(ServerInviteEvent::TimerFired(TransactionTimer::I));
    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Terminated
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Cancel(TransactionTimer::I))),
        "Timer I should terminate transaction"
    );
}

#[test]
fn server_invite_2xx_immediate_termination() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));
    let actions = fsm.on_event(ServerInviteEvent::SendFinal(sample_response(200)));

    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Terminated
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })),
        "2xx should be transmitted"
    );
    assert!(
        !actions.iter().any(|a| matches!(
            a,
            ServerInviteAction::Schedule {
                timer: TransactionTimer::G,
                ..
            }
        )),
        "Timer G should NOT be scheduled for 2xx"
    );
}

#[test]
fn server_invite_retransmit_in_completed() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite.clone()));
    fsm.on_event(ServerInviteEvent::SendFinal(sample_response(486)));

    // Retransmitted INVITE in Completed state
    let actions = fsm.on_retransmit();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })),
        "Should retransmit final response for duplicate INVITE"
    );
}

#[test]
fn server_invite_provisional_response() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));

    // Send provisional
    let actions = fsm.on_event(ServerInviteEvent::SendProvisional(sample_response(180)));
    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Proceeding
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })),
        "Provisional should be transmitted"
    );

    // Send another provisional
    let actions = fsm.on_event(ServerInviteEvent::SendProvisional(sample_response(183)));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Transmit { .. })),
        "Additional provisionals should be transmitted"
    );
}

#[test]
fn server_invite_transport_error() {
    let invite = sample_invite();
    let mut fsm = ServerInviteFsm::new(TransportAwareTimers::new(Transport::Udp));

    fsm.on_event(ServerInviteEvent::ReceiveInvite(invite));
    let actions = fsm.on_event(ServerInviteEvent::TransportError);

    assert!(matches!(
        fsm.state(),
        sip_transaction::ServerInviteState::Terminated
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ServerInviteAction::Terminate { .. })),
        "Transport error should terminate transaction"
    );
}
