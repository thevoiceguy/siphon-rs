use bytes::Bytes;
use sip_core::{Method, Request, Response};
use sip_parse::{parse_request, parse_response, serialize_request, serialize_response};
use sip_testkit::{as_bytes, build_invite, build_options, build_register, build_response};

/// Test that OPTIONS requests can be built, serialized, parsed, and round-tripped.
#[test]
fn options_request_roundtrip() {
    let original = build_options("sip:example.com");

    // Serialize to bytes
    let bytes = as_bytes(&original);
    assert!(!bytes.is_empty(), "Serialized request should not be empty");

    // Parse back
    let parsed = parse_request(&bytes).expect("Should parse OPTIONS request");

    // Verify method
    assert_eq!(parsed.start.method, Method::Options);
    assert_eq!(parsed.start.uri.as_str(), "sip:example.com");

    // Verify essential headers are present
    assert!(parsed.headers.get("Via").is_some());
    assert!(parsed.headers.get("From").is_some());
    assert!(parsed.headers.get("To").is_some());
    assert!(parsed.headers.get("Call-ID").is_some());
    assert!(parsed.headers.get("CSeq").is_some());
}

/// Test that INVITE requests can be built and parsed correctly.
#[test]
fn invite_request_creation_and_parsing() {
    let original =
        build_invite("sip:bob@example.com", "z9hG4bKinvite1", "invite-call-id@example.com");

    let bytes = serialize_request(&original);
    let parsed = parse_request(&bytes).expect("Should parse INVITE request");

    assert_eq!(parsed.start.method, Method::Invite);
    assert_eq!(parsed.start.uri.as_str(), "sip:bob@example.com");

    // Verify INVITE-specific headers
    assert!(parsed.headers.get("Contact").is_some());
    let via = parsed.headers.get("Via").expect("Via header required");
    assert!(via.contains("z9hG4bKinvite1"), "Branch parameter should be present");
}

/// Test that REGISTER requests contain the expected headers.
#[test]
fn register_request_structure() {
    let original = build_register(
        "sip:registrar.example.com",
        "<sip:alice@client.example.com:5060>",
    );

    let bytes = serialize_request(&original);
    let parsed = parse_request(&bytes).expect("Should parse REGISTER request");

    assert_eq!(parsed.start.method, Method::Register);

    // Verify REGISTER-specific headers
    assert!(parsed.headers.get("Contact").is_some());
    assert!(parsed.headers.get("Expires").is_some());

    let contact = parsed
        .headers
        .get("Contact")
        .expect("REGISTER must have Contact");
    assert!(contact.contains("alice@client.example.com"));
}

/// Test response creation and parsing.
#[test]
fn response_roundtrip() {
    let original = build_response(200, "OK");

    let bytes = sip_testkit::response_as_bytes(&original);
    let parsed = parse_response(&bytes).expect("Should parse response");

    assert_eq!(parsed.start.code, 200);
    assert_eq!(parsed.start.reason.as_str(), "OK");

    // Verify headers
    assert!(parsed.headers.get("Via").is_some());
    assert!(parsed.headers.get("From").is_some());
    assert!(parsed.headers.get("To").is_some());
}

/// Test various response codes.
#[test]
fn response_status_codes() {
    let test_cases = vec![
        (100, "Trying"),
        (180, "Ringing"),
        (200, "OK"),
        (404, "Not Found"),
        (486, "Busy Here"),
        (503, "Service Unavailable"),
    ];

    for (code, reason) in test_cases {
        let response = build_response(code, reason);
        let bytes = serialize_response(&response);
        let parsed = parse_response(&bytes).expect("Should parse response");

        assert_eq!(parsed.start.code, code);
        assert_eq!(parsed.start.reason.as_str(), reason);
    }
}

/// Test that Via header branch parameters are preserved through serialization.
#[test]
fn via_branch_preservation() {
    let request = build_invite("sip:test.com", "z9hG4bKunique123", "test-call@example.com");

    let bytes = serialize_request(&request);
    let parsed = parse_request(&bytes).expect("Should parse");

    let via = parsed.headers.get("Via").expect("Via required");
    assert!(
        via.contains("branch=z9hG4bKunique123"),
        "Branch parameter must be preserved"
    );
}

/// Test that Call-ID is preserved.
#[test]
fn call_id_preservation() {
    let call_id = "unique-call-id-12345@example.com";
    let request = build_invite("sip:test.com", "z9hG4bKbranch", call_id);

    let bytes = serialize_request(&request);
    let parsed = parse_request(&bytes).expect("Should parse");

    let parsed_call_id = parsed.headers.get("Call-ID").expect("Call-ID required");
    assert_eq!(parsed_call_id.as_str(), call_id);
}

/// Test that From and To headers with tags are preserved.
#[test]
fn from_to_tag_preservation() {
    let request = build_options("sip:example.com");

    let bytes = serialize_request(&request);
    let parsed = parse_request(&bytes).expect("Should parse");

    let from = parsed.headers.get("From").expect("From required");
    assert!(from.contains("tag=1234"), "From tag should be preserved");

    let to = parsed.headers.get("To").expect("To required");
    // To tag is typically added by UAS, so not checking for tag here
    assert!(to.contains("bob@example.com"));
}

/// Test CSeq header structure.
#[test]
fn cseq_structure() {
    let request = build_options("sip:example.com");

    let bytes = serialize_request(&request);
    let parsed = parse_request(&bytes).expect("Should parse");

    let cseq = parsed.headers.get("CSeq").expect("CSeq required");
    assert!(cseq.contains("1"), "CSeq should contain sequence number");
    assert!(cseq.contains("OPTIONS"), "CSeq should contain method");
}

/// Test Max-Forwards header.
#[test]
fn max_forwards_present() {
    let request = build_options("sip:example.com");

    let bytes = serialize_request(&request);
    let parsed = parse_request(&bytes).expect("Should parse");

    let max_forwards = parsed
        .headers
        .get("Max-Forwards")
        .expect("Max-Forwards required");
    assert_eq!(max_forwards.as_str(), "70");
}

/// Test that multiple requests can be created with different parameters.
#[test]
fn multiple_distinct_requests() {
    let req1 = build_invite("sip:alice@example.com", "z9hG4bK1", "call1@test.com");
    let req2 = build_invite("sip:bob@example.com", "z9hG4bK2", "call2@test.com");

    let bytes1 = serialize_request(&req1);
    let bytes2 = serialize_request(&req2);

    // Ensure they're different
    assert_ne!(bytes1, bytes2);

    let parsed1 = parse_request(&bytes1).expect("Should parse req1");
    let parsed2 = parse_request(&bytes2).expect("Should parse req2");

    assert_ne!(
        parsed1.start.uri.as_str(),
        parsed2.start.uri.as_str()
    );
    assert_ne!(
        parsed1.headers.get("Via").unwrap().as_str(),
        parsed2.headers.get("Via").unwrap().as_str()
    );
}

/// Test parsing a raw SIP OPTIONS request.
#[test]
fn parse_raw_options() {
    let raw = b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP client.com:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@test.com>;tag=123\r\n\
To: <sip:bob@test.com>\r\n\
Call-ID: abc@test.com\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n";

    let parsed = parse_request(&Bytes::from_static(raw)).expect("Should parse raw OPTIONS");

    assert_eq!(parsed.start.method, Method::Options);
    assert_eq!(parsed.start.uri.as_str(), "sip:example.com");
}

/// Test parsing a raw SIP response.
#[test]
fn parse_raw_response() {
    let raw = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP client.com:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@test.com>;tag=123\r\n\
To: <sip:bob@test.com>;tag=456\r\n\
Call-ID: abc@test.com\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n";

    let parsed = parse_response(&Bytes::from_static(raw)).expect("Should parse raw response");

    assert_eq!(parsed.start.code, 200);
    assert_eq!(parsed.start.reason.as_str(), "OK");
}

/// Test that empty body is handled correctly.
#[test]
fn empty_body_handling() {
    let request = build_options("sip:example.com");
    assert!(request.body.is_empty());

    let bytes = serialize_request(&request);
    let parsed = parse_request(&bytes).expect("Should parse");

    assert!(parsed.body.is_empty());
    let content_length = parsed.headers.get("Content-Length").expect("Content-Length required");
    assert_eq!(content_length.as_str(), "0");
}
