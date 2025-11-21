//! Integration tests for tel URI support (RFC 3966)
//!
//! These tests verify that tel URIs work correctly throughout the SIP stack,
//! including in Request-URI, From/To headers, and Contact headers.

use sip_core::{Request, RequestLine, Headers, Method, TelUri, Uri, SipUri};
use bytes::Bytes;
use smol_str::SmolStr;

#[test]
fn request_with_tel_uri_in_request_line() {
    // Create a request with a tel URI in the Request-URI
    // This is less common but valid per RFC 3966
    let tel_uri = TelUri::parse("tel:+1-555-123-4567").expect("valid tel URI");
    let uri: Uri = tel_uri.into();

    let request_line = RequestLine::new(Method::Invite, uri);

    assert!(request_line.uri.is_tel());
    assert_eq!(request_line.uri.as_str(), "tel:+1-555-123-4567");

    let tel = request_line.uri.as_tel().unwrap();
    assert!(tel.is_global);
    assert_eq!(tel.number.as_str(), "+15551234567");
}

#[test]
fn request_with_sip_uri_still_works() {
    // Verify backward compatibility - SipUri should still work
    let sip_uri = SipUri::parse("sip:bob@example.com").expect("valid SIP URI");

    let request_line = RequestLine::new(Method::Invite, sip_uri.clone());

    assert!(request_line.uri.is_sip());
    assert_eq!(request_line.uri.as_str(), "sip:bob@example.com");

    let sip = request_line.uri.as_sip().unwrap();
    assert_eq!(sip.host.as_str(), "example.com");
    assert_eq!(sip.user.as_ref().unwrap().as_str(), "bob");
}

#[test]
fn request_with_mixed_uri_types() {
    // Test a scenario where different URI types are used
    // Request-URI is SIP, but To header could contain tel URI

    let sip_uri = SipUri::parse("sip:gateway@example.com").expect("valid SIP URI");
    let request_line = RequestLine::new(Method::Invite, sip_uri);

    let mut headers = Headers::new();
    headers.push(SmolStr::new("From"), SmolStr::new("<sip:alice@example.com>;tag=123"));
    // To header with tel URI
    headers.push(SmolStr::new("To"), SmolStr::new("<tel:+1-555-123-4567>"));
    headers.push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"));
    headers.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"));

    let request = Request::new(request_line, headers, Bytes::new());

    // Request-URI is SIP
    assert!(request.start.uri.is_sip());

    // To header contains tel URI (as string)
    let to_header = request.headers.get("To").unwrap();
    assert!(to_header.contains("tel:+1-555-123-4567"));
}

#[test]
fn tel_uri_with_phone_context() {
    // Test local tel URI with phone-context
    let tel_uri = TelUri::parse("tel:5551234;phone-context=example.com").expect("valid tel URI");
    let uri: Uri = tel_uri.into();

    assert!(uri.is_tel());

    let tel = uri.as_tel().unwrap();
    assert!(!tel.is_global);
    assert_eq!(tel.number.as_str(), "5551234");
    assert_eq!(tel.phone_context.as_ref().unwrap().as_str(), "example.com");
}

#[test]
fn tel_uri_with_extension() {
    // Test tel URI with extension parameter
    let tel_uri = TelUri::parse("tel:+1-555-123-4567;ext=1234").expect("valid tel URI");

    assert!(tel_uri.is_global);
    assert_eq!(tel_uri.number.as_str(), "+15551234567");

    let ext = tel_uri.parameters.get("ext").unwrap();
    assert_eq!(ext.as_ref().unwrap().as_str(), "1234");
}

#[test]
fn uri_parse_automatically_detects_scheme() {
    // Uri::parse should automatically detect the scheme
    let sip_uri = Uri::parse("sip:alice@example.com").expect("valid URI");
    assert!(sip_uri.is_sip());

    let tel_uri = Uri::parse("tel:+15551234567").expect("valid URI");
    assert!(tel_uri.is_tel());

    let sips_uri = Uri::parse("sips:bob@example.com").expect("valid URI");
    assert!(sips_uri.is_sip());
    assert!(sips_uri.as_sip().unwrap().sips);
}

#[test]
fn tel_uri_rejects_invalid_formats() {
    // Local tel URI without phone-context should be rejected
    assert!(TelUri::parse("tel:5551234").is_none());

    // Global tel URI with phone-context should be rejected
    assert!(TelUri::parse("tel:+15551234;phone-context=example.com").is_none());

    // Non-tel scheme should be rejected
    assert!(TelUri::parse("sip:user@example.com").is_none());
}

#[test]
fn tel_uri_builder_methods() {
    // Test programmatic construction of tel URIs
    let tel_uri = TelUri::new("+15551234567", true);
    assert!(tel_uri.is_global);
    assert_eq!(tel_uri.as_str(), "tel:+15551234567");

    let local_tel = TelUri::new("5551234", false)
        .with_phone_context("example.com");
    assert!(!local_tel.is_global);
    assert_eq!(local_tel.phone_context.as_ref().unwrap().as_str(), "example.com");

    let tel_with_ext = TelUri::new("+15551234567", true)
        .with_parameter("ext", Some("1234"));
    assert_eq!(tel_with_ext.parameters.get("ext").unwrap().as_ref().unwrap().as_str(), "1234");
}

#[test]
fn tel_uri_visual_separators_normalized() {
    // Visual separators should be normalized in global numbers
    let variants = vec![
        "tel:+1-555-123-4567",
        "tel:+1.555.123.4567",
        "tel:+1 555 123 4567",
        "tel:+1(555)123-4567",
    ];

    for variant in variants {
        let tel_uri = TelUri::parse(variant).expect("valid tel URI");
        assert_eq!(tel_uri.number.as_str(), "+15551234567", "failed for {}", variant);
    }
}
