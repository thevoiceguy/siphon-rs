// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Integration test harness and SIPp scenario bindings.
//!
//! Provides utilities for building test requests/responses and running
//! SIPp scenarios for protocol compliance testing.
//!
//! # Example
//! ```
//! use sip_testkit::build_options;
//! let req = build_options("sip:test@example.com");
//! assert_eq!(req.start.method.as_str(), "OPTIONS");
//! ```

use bytes::Bytes;
use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri, StatusLine};
use sip_parse::{serialize_request, serialize_response};
use smol_str::SmolStr;

/// Constructs a minimal OPTIONS request for the provided URI string.
pub fn build_options(uri: &str) -> Request {
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKtest"),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("<sip:alice@example.com>;tag=1234"),
    );
    headers.push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"));
    headers.push(
        SmolStr::new("Call-ID"),
        SmolStr::new("test-callid@example.com"),
    );
    headers.push(SmolStr::new("CSeq"), SmolStr::new("1 OPTIONS"));
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
    headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

    Request::new(
        RequestLine::new(Method::Options, SipUri::parse(uri).unwrap()),
        headers,
        Bytes::new(),
    )
}

/// Constructs a minimal INVITE request for the provided URI string.
pub fn build_invite(uri: &str, branch: &str, call_id: &str) -> Request {
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new(format!(
            "SIP/2.0/UDP client.example.com:5060;branch={}",
            branch
        )),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("<sip:alice@example.com>;tag=1234"),
    );
    headers.push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"));
    headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id.to_owned()));
    headers.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"));
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
    headers.push(
        SmolStr::new("Contact"),
        SmolStr::new("<sip:alice@client.example.com:5060>"),
    );
    headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

    Request::new(
        RequestLine::new(Method::Invite, SipUri::parse(uri).unwrap()),
        headers,
        Bytes::new(),
    )
}

/// Constructs a PRACK request for the provided URI and RAck header value.
pub fn build_prack(uri: &str, rack: &str, call_id: &str, cseq: u32) -> Request {
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKprack"),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("<sip:alice@example.com>;tag=1234"),
    );
    headers.push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"));
    headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id.to_owned()));
    headers.push(SmolStr::new("CSeq"), SmolStr::new(format!("{} PRACK", cseq)));
    headers.push(SmolStr::new("RAck"), SmolStr::new(rack.to_owned()));
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
    headers.push(
        SmolStr::new("Contact"),
        SmolStr::new("<sip:alice@client.example.com:5060>"),
    );
    headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

    Request::new(
        RequestLine::new(Method::Prack, SipUri::parse(uri).unwrap()),
        headers,
        Bytes::new(),
    )
}

/// Constructs a REFER request for transfer scenarios.
pub fn build_refer(uri: &str, refer_to: &str, call_id: &str, cseq: u32) -> Request {
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKrefer"),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("<sip:alice@example.com>;tag=1234"),
    );
    headers.push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"));
    headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id.to_owned()));
    headers.push(SmolStr::new("CSeq"), SmolStr::new(format!("{} REFER", cseq)));
    headers.push(
        SmolStr::new("Contact"),
        SmolStr::new("<sip:alice@client.example.com:5060>"),
    );
    headers.push(SmolStr::new("Refer-To"), SmolStr::new(refer_to.to_owned()));
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
    headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

    Request::new(
        RequestLine::new(Method::Refer, SipUri::parse(uri).unwrap()),
        headers,
        Bytes::new(),
    )
}

/// Builds a reliable provisional response carrying RSeq for PRACK scenarios.
pub fn build_provisional_with_rseq(code: u16, reason: &str, rack_cseq: u32) -> Response {
    let mut resp = build_response(code, reason);
    resp.headers.push(SmolStr::new("Require"), SmolStr::new("100rel"));
    resp.headers
        .push(SmolStr::new("RSeq"), SmolStr::new(rack_cseq.to_string()));
    resp
}

/// Constructs a minimal REGISTER request.
pub fn build_register(uri: &str, contact: &str) -> Request {
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKreg123"),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("<sip:alice@example.com>;tag=reg1"),
    );
    headers.push(SmolStr::new("To"), SmolStr::new("<sip:alice@example.com>"));
    headers.push(
        SmolStr::new("Call-ID"),
        SmolStr::new("register-callid@example.com"),
    );
    headers.push(SmolStr::new("CSeq"), SmolStr::new("1 REGISTER"));
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
    headers.push(SmolStr::new("Contact"), SmolStr::new(contact.to_owned()));
    headers.push(SmolStr::new("Expires"), SmolStr::new("3600"));
    headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

    Request::new(
        RequestLine::new(Method::Register, SipUri::parse(uri).unwrap()),
        headers,
        Bytes::new(),
    )
}

/// Constructs a minimal response with the given status code.
pub fn build_response(code: u16, reason: &str) -> Response {
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP server.example.com:5060;branch=z9hG4bKtest"),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("<sip:alice@example.com>;tag=1234"),
    );
    headers.push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"));
    headers.push(
        SmolStr::new("Call-ID"),
        SmolStr::new("test-callid@example.com"),
    );
    headers.push(SmolStr::new("CSeq"), SmolStr::new("1 OPTIONS"));
    headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

    Response::new(
        StatusLine::new(code, SmolStr::new(reason)),
        headers,
        Bytes::new(),
    )
}

/// Serializes a request to bytes for transport-layer testing.
pub fn as_bytes(request: &Request) -> Bytes {
    serialize_request(request)
}

/// Serializes a response to bytes for transport-layer testing.
pub fn response_as_bytes(response: &Response) -> Bytes {
    serialize_response(response)
}

/// End-to-end helper: builds a simple INVITE -> 180 (with RSeq) -> PRACK exchange.
pub fn scenario_invite_prack(target: &str) -> (Request, Response, Request) {
    let invite = build_invite(target, "z9hG4bKinv1", "call-prack@example.com");
    let provisional = build_provisional_with_rseq(180, "Ringing", 1);
    let prack = build_prack(target, "1 1 INVITE", "call-prack@example.com", 2);
    (invite, provisional, prack)
}

/// End-to-end helper: builds a simple REFER transfer request with matching headers.
pub fn scenario_refer(target: &str, refer_to: &str) -> Request {
    build_refer(target, refer_to, "call-refer@example.com", 3)
}

/// Builds a NOTIFY for a REFER subscription with a given body/state.
pub fn build_notify_for_refer(
    refer_sub_call_id: &str,
    refer_to: &str,
    notify_state: &str,
) -> Request {
    let refer_uri = refer_to.trim_matches('<').trim_matches('>');
    let mut headers = Headers::new();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP notifier.example.com:5060;branch=z9hG4bKnotify"),
    );
    headers.push(
        SmolStr::new("From"),
        SmolStr::new("<sip:notifier@example.com>;tag=refnot"),
    );
    headers.push(
        SmolStr::new("To"),
        SmolStr::new(format!("<{}>;tag=subscriber", refer_to)),
    );
    headers.push(
        SmolStr::new("Call-ID"),
        SmolStr::new(refer_sub_call_id.to_owned()),
    );
    headers.push(SmolStr::new("CSeq"), SmolStr::new("1 NOTIFY"));
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
    headers.push(
        SmolStr::new("Contact"),
        SmolStr::new("<sip:notifier@notifier.example.com:5060>"),
    );
    headers.push(SmolStr::new("Event"), SmolStr::new("refer"));
    headers.push(
        SmolStr::new("Subscription-State"),
        SmolStr::new(format!("{};expires=300", notify_state)),
    );
    headers.push(SmolStr::new("Content-Type"), SmolStr::new("message/sipfrag"));
    headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

    Request::new(
        RequestLine::new(Method::Notify, SipUri::parse(refer_uri).unwrap()),
        headers,
        Bytes::new(),
    )
}

/// REFER scenario with 202 Accepted and an initial NOTIFY.
pub fn scenario_refer_with_notify(
    target: &str,
    refer_to: &str,
) -> (Request, Response, Request) {
    let refer = scenario_refer(target, refer_to);
    let accepted = build_response(202, "Accepted");
    let notify = build_notify_for_refer("call-refer@example.com", refer_to, "active");
    (refer, accepted, notify)
}

/// Builds an initial REGISTER and a retry with a placeholder Authorization header.
pub fn scenario_register_with_auth(uri: &str, contact: &str, realm: &str) -> (Request, Response, Request) {
    let first = build_register(uri, contact);
    let mut challenge = build_response(401, "Unauthorized");
    challenge.headers.push(
        SmolStr::new("WWW-Authenticate"),
        SmolStr::new(format!("Digest realm=\"{}\", nonce=\"abc123\"", realm)),
    );

    let mut retry = build_register(uri, contact);
    retry.headers.push(
        SmolStr::new("Authorization"),
        SmolStr::new("Digest username=\"alice\", realm=\"example.com\", nonce=\"abc123\", uri=\"sip:registrar.example.com\", response=\"deadbeef\""),
    );
    (first, challenge, retry)
}
