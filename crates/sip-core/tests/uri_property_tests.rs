// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use proptest::prelude::*;
use sip_core::SipUri;

proptest! {
    /// Test that valid URIs can be parsed and reconstructed.
    #[test]
    fn uri_roundtrip(
        scheme in prop::bool::ANY,
        user in proptest::option::of("[a-z0-9]{1,8}"),
        host in "[a-z0-9][a-z0-9\\-]{0,10}",
        port in proptest::option::of(1024u16..65535),
    ) {
        let scheme_str = if scheme { "sips" } else { "sip" };
        let user_part = user.as_ref().map(|u| format!("{}@", u)).unwrap_or_default();
        let port_part = port.map(|p| format!(":{}", p)).unwrap_or_default();

        let uri_str = format!("{}:{}{}{}", scheme_str, user_part, host, port_part);

        let parsed = SipUri::parse(&uri_str);
        prop_assert!(parsed.is_some(), "Failed to parse: {}", uri_str);

        let uri = parsed.unwrap();
        prop_assert_eq!(uri.sips, scheme);
        prop_assert_eq!(uri.user.as_ref().map(|s| s.as_str()), user.as_deref());
        prop_assert_eq!(uri.host.as_str(), &host);
        prop_assert_eq!(uri.port, port);

        // Verify string representation
        let reconstructed = uri.as_str();
        prop_assert!(reconstructed.contains(&host));
        if let Some(u) = &user {
            prop_assert!(reconstructed.contains(u));
        }
    }

    /// Test URI parameters preservation.
    #[test]
    fn uri_params_preserved(
        host in "[a-z]{2,8}",
        transport in prop::sample::select(vec!["udp", "tcp", "tls", "ws"]),
        lr in prop::bool::ANY,
    ) {
        let lr_part = if lr { ";lr" } else { "" };
        let uri_str = format!("sip:{};transport={}{}", host, transport, lr_part);

        let parsed = SipUri::parse(&uri_str).expect("parse");

        // Verify params are in the map
        let params_str = parsed.as_str();
        prop_assert!(params_str.contains("transport="));
        if lr {
            prop_assert!(params_str.contains("lr"));
        }
    }

    /// Test that various host formats are handled.
    #[test]
    fn uri_host_formats(
        host_type in 0u8..3,
        octet in 1u8..255,
    ) {
        let host_str = match host_type {
            0 => format!("example{}.com", octet),  // Domain name
            1 => format!("192.168.1.{}", octet),   // IPv4
            _ => format!("[2001:db8::{}]", octet), // IPv6
        };

        let uri_str = format!("sip:{}", host_str);
        let parsed = SipUri::parse(&uri_str);

        // All should parse successfully
        prop_assert!(parsed.is_some(), "Failed to parse: {}", uri_str);
    }

    /// Test various valid SIP URI edge cases.
    #[test]
    fn uri_special_chars_in_user(
        user_prefix in "[a-z]{1,4}",
        separator in prop::sample::select(vec![".", "_", "-", "+"]),
        user_suffix in "[0-9]{1,4}",
    ) {
        let uri_str = format!("sip:{}{}{}@example.com", user_prefix, separator, user_suffix);
        let parsed = SipUri::parse(&uri_str);

        prop_assert!(parsed.is_some(), "Failed to parse: {}", uri_str);
        let uri = parsed.unwrap();
        let user_part = uri.user.expect("user should be present");
        prop_assert!(user_part.contains(&user_prefix));
        prop_assert!(user_part.contains(&user_suffix));
    }

    /// Test port number ranges.
    #[test]
    fn uri_port_ranges(port in 1u16..65535) {
        let uri_str = format!("sip:example.com:{}", port);
        let parsed = SipUri::parse(&uri_str);

        prop_assert!(parsed.is_some());
        let uri = parsed.unwrap();
        prop_assert_eq!(uri.port, Some(port));
    }

    /// Test scheme case insensitivity (sip vs SIP).
    #[test]
    fn uri_scheme_case(
        scheme_case in prop::sample::select(vec!["sip", "SIP", "Sip", "sIp"]),
        host in "[a-z]{3,8}",
    ) {
        let uri_str = format!("{}:{}", scheme_case, host);
        let parsed = SipUri::parse(&uri_str);

        prop_assert!(parsed.is_some(), "Failed to parse: {}", uri_str);
        // Should always normalize to lowercase
        let uri = parsed.unwrap();
        prop_assert_eq!(uri.sips, false);
    }
}

#[test]
fn uri_reject_invalid() {
    // These should fail to parse
    let invalid_uris = vec![
        "",                      // Empty
        "example.com",           // Missing scheme
        "http://example.com",    // Wrong scheme
        "sip:",                  // No host
        "sip:user@",             // No host after @
        "sip:example.com:99999", // Invalid port (too large)
    ];

    for uri_str in invalid_uris {
        assert!(
            SipUri::parse(uri_str).is_none(),
            "Should reject invalid URI: {}",
            uri_str
        );
    }
}

#[test]
fn uri_default_ports() {
    let sip_uri = SipUri::parse("sip:example.com").expect("parse");
    assert_eq!(sip_uri.port, None); // Port should be None (defaults to 5060)

    let sips_uri = SipUri::parse("sips:example.com").expect("parse");
    assert_eq!(sips_uri.port, None); // Port should be None (defaults to 5061)
    assert!(sips_uri.sips);
}

#[test]
fn uri_with_multiple_params() {
    let uri_str = "sip:alice@example.com;transport=tcp;lr;maddr=192.168.1.1";
    let uri = SipUri::parse(uri_str).expect("parse");

    assert_eq!(uri.user.as_ref().map(|s| s.as_str()), Some("alice"));
    assert_eq!(uri.host.as_str(), "example.com");

    // Params should be preserved in string representation
    let reconstructed = uri.as_str();
    assert!(reconstructed.contains("transport"));
    assert!(reconstructed.contains("lr"));
}
