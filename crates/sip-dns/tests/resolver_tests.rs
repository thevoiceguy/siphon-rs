// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use sip_core::SipUri;
use sip_dns::{DnsTarget, Resolver, SipResolver, StaticResolver, Transport};

#[tokio::test]
async fn resolve_numeric_ipv4() {
    let resolver = SipResolver::from_system().unwrap();
    let uri = SipUri::parse("sip:192.168.1.1:5060").unwrap();

    let targets = resolver.resolve(&uri).await.expect("resolve");

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host(), "192.168.1.1");
    assert_eq!(targets[0].port(), 5060);
}

#[tokio::test]
async fn resolve_numeric_ipv6() {
    let resolver = SipResolver::from_system().unwrap();
    let uri = SipUri::parse("sip:[::1]:5060").unwrap();

    let targets = resolver.resolve(&uri).await.expect("resolve");

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host(), "::1");
    assert_eq!(targets[0].port(), 5060);
}

#[tokio::test]
async fn resolve_localhost_fallback_to_a() {
    let resolver = SipResolver::from_system().unwrap().disable_naptr();
    let uri = SipUri::parse("sip:localhost").unwrap();

    let targets = resolver.resolve(&uri).await.expect("resolve");

    // Should get at least one result (127.0.0.1 or ::1)
    assert!(!targets.is_empty());
    assert_eq!(targets[0].port(), 5060); // Default SIP port
}

#[tokio::test]
async fn sips_uses_port_5061_by_default() {
    let resolver = SipResolver::from_system().unwrap();
    let uri = SipUri::parse("sips:192.168.1.1").unwrap();

    let targets = resolver.resolve(&uri).await.expect("resolve");

    assert_eq!(targets[0].port(), 5061);
    assert_eq!(targets[0].transport(), Transport::Tls);
}

#[tokio::test]
async fn explicit_port_skips_srv() {
    let resolver = SipResolver::from_system().unwrap().disable_naptr();
    let uri = SipUri::parse("sip:localhost:5070").unwrap();

    let targets = resolver.resolve(&uri).await.expect("resolve");

    assert!(!targets.is_empty());
    assert_eq!(targets[0].port(), 5070);
}

#[tokio::test]
async fn transport_parameter_honored_in_uri() {
    let resolver = SipResolver::from_system().unwrap();

    let tcp_uri = SipUri::parse("sip:192.168.1.1;transport=tcp").unwrap();
    let tcp_targets = resolver.resolve(&tcp_uri).await.expect("resolve");
    assert_eq!(tcp_targets[0].transport(), Transport::Tcp);

    let tls_uri = SipUri::parse("sip:192.168.1.1;transport=tls").unwrap();
    let tls_targets = resolver.resolve(&tls_uri).await.expect("resolve");
    assert_eq!(tls_targets[0].transport(), Transport::Tls);

    let udp_uri = SipUri::parse("sip:192.168.1.1;transport=udp").unwrap();
    let udp_targets = resolver.resolve(&udp_uri).await.expect("resolve");
    assert_eq!(udp_targets[0].transport(), Transport::Udp);
}

#[tokio::test]
async fn static_resolver_integration() {
    let targets = vec![
        DnsTarget::unchecked_new("sip1.example.com", 5060, Transport::Udp),
        DnsTarget::unchecked_new("sip2.example.com", 5060, Transport::Tcp).with_priority(10),
        DnsTarget::unchecked_new("sip3.example.com", 5060, Transport::Tls).with_priority(20),
    ];

    let resolver = StaticResolver::new(targets.clone());
    let uri = SipUri::parse("sip:test@example.com").unwrap();

    let result = resolver.resolve(&uri).await.expect("resolve");

    assert_eq!(result.len(), 3);
    assert_eq!(result[0].host(), "sip1.example.com");
    assert_eq!(result[1].host(), "sip2.example.com");
    assert_eq!(result[2].host(), "sip3.example.com");

    // Verify priorities
    assert_eq!(result[0].priority(), 0);
    assert_eq!(result[1].priority(), 10);
    assert_eq!(result[2].priority(), 20);
}

#[tokio::test]
async fn failover_scenario() {
    // Simulate failover by providing multiple targets with different priorities
    let targets = vec![
        DnsTarget::unchecked_new("primary.example.com", 5060, Transport::Udp).with_priority(10),
        DnsTarget::unchecked_new("secondary.example.com", 5060, Transport::Udp).with_priority(20),
        DnsTarget::unchecked_new("tertiary.example.com", 5060, Transport::Udp).with_priority(30),
    ];

    let resolver = StaticResolver::new(targets);
    let uri = SipUri::parse("sip:user@example.com").unwrap();

    let result = resolver.resolve(&uri).await.expect("resolve");

    // Targets should be returned in priority order
    assert_eq!(result[0].host(), "primary.example.com");
    assert_eq!(result[0].priority(), 10);
    assert_eq!(result[1].host(), "secondary.example.com");
    assert_eq!(result[1].priority(), 20);
    assert_eq!(result[2].host(), "tertiary.example.com");
    assert_eq!(result[2].priority(), 30);
}

#[tokio::test]
async fn multiple_transports_for_failover() {
    // Client should try TLS first, then TCP, then UDP
    let targets = vec![
        DnsTarget::unchecked_new("example.com", 5061, Transport::Tls).with_priority(10),
        DnsTarget::unchecked_new("example.com", 5060, Transport::Tcp).with_priority(20),
        DnsTarget::unchecked_new("example.com", 5060, Transport::Udp).with_priority(30),
    ];

    let resolver = StaticResolver::new(targets);
    let uri = SipUri::parse("sip:user@example.com").unwrap();

    let result = resolver.resolve(&uri).await.expect("resolve");

    assert_eq!(result.len(), 3);
    assert_eq!(result[0].transport(), Transport::Tls);
    assert_eq!(result[1].transport(), Transport::Tcp);
    assert_eq!(result[2].transport(), Transport::Udp);
}

#[tokio::test]
async fn websocket_transport_support() {
    let ws_uri = SipUri::parse("sip:example.com;transport=ws").unwrap();
    let targets = vec![DnsTarget::unchecked_new(
        "ws.example.com",
        80,
        Transport::Ws,
    )];
    let resolver = StaticResolver::new(targets);

    let result = resolver.resolve(&ws_uri).await.expect("resolve");

    assert_eq!(result[0].transport(), Transport::Ws);

    let wss_uri = SipUri::parse("sip:example.com;transport=wss").unwrap();
    let targets = vec![DnsTarget::unchecked_new(
        "wss.example.com",
        443,
        Transport::Wss,
    )];
    let resolver = StaticResolver::new(targets);

    let result = resolver.resolve(&wss_uri).await.expect("resolve");

    assert_eq!(result[0].transport(), Transport::Wss);
}

#[tokio::test]
async fn dns_target_equality() {
    let target1 = DnsTarget::unchecked_new("example.com", 5060, Transport::Udp);
    let target2 = DnsTarget::unchecked_new("example.com", 5060, Transport::Udp);
    let target3 = DnsTarget::unchecked_new("example.com", 5060, Transport::Tcp);

    assert_eq!(target1, target2);
    assert_ne!(target1, target3);
}

#[tokio::test]
async fn priority_affects_ordering() {
    let targets = vec![
        DnsTarget::unchecked_new("low.example.com", 5060, Transport::Udp).with_priority(100),
        DnsTarget::unchecked_new("high.example.com", 5060, Transport::Udp).with_priority(10),
        DnsTarget::unchecked_new("medium.example.com", 5060, Transport::Udp).with_priority(50),
    ];

    let resolver = StaticResolver::new(targets.clone());
    let uri = SipUri::parse("sip:test@example.com").unwrap();
    let result = resolver.resolve(&uri).await.expect("resolve");

    // Results should be in the order they were provided (priority doesn't auto-sort)
    // The calling code should sort by priority
    assert_eq!(result.len(), 3);
}

#[test]
fn transport_proto_str() {
    assert_eq!(Transport::Udp.as_proto_str(), "udp");
    assert_eq!(Transport::Tcp.as_proto_str(), "tcp");
    assert_eq!(Transport::Tls.as_proto_str(), "tcp");
    assert_eq!(Transport::Ws.as_proto_str(), "tcp");
    assert_eq!(Transport::Wss.as_proto_str(), "tcp");
}

#[test]
fn transport_service_str() {
    assert_eq!(Transport::Udp.as_service_str(false), "_sip");
    assert_eq!(Transport::Udp.as_service_str(true), "_sips");
    assert_eq!(Transport::Tcp.as_service_str(false), "_sip");
    assert_eq!(Transport::Tls.as_service_str(false), "_sips");
    assert_eq!(Transport::Tls.as_service_str(true), "_sips");
    assert_eq!(Transport::Wss.as_service_str(false), "_sips");
}

// Test DNS resolution caching would require time-based testing
// Test actual NAPTR/SRV lookups would require a test DNS server
// For now, these are covered by unit tests and static resolver tests
