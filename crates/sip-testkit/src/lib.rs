use bytes::Bytes;
use sip_core::{Headers, Method, Request, RequestLine, Response, StatusLine, SipUri};
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
        SmolStr::new(format!("SIP/2.0/UDP client.example.com:5060;branch={}", branch)),
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

    Response::new(StatusLine::new(code, SmolStr::new(reason)), headers, Bytes::new())
}

/// Serializes a request to bytes for transport-layer testing.
pub fn as_bytes(request: &Request) -> Bytes {
    serialize_request(request)
}

/// Serializes a response to bytes for transport-layer testing.
pub fn response_as_bytes(response: &Response) -> Bytes {
    serialize_response(response)
}
