// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Example demonstrating SIP DNS resolution per RFC 3263
///
/// Run with: cargo run --example dns_resolution
use sip_core::SipUri;
use sip_dns::{DnsTarget, Resolver, SipResolver, StaticResolver, Transport};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== SIP DNS Resolution Examples (RFC 3263) ===\n");

    // Example 1: Numeric IP address (no DNS lookup)
    println!("1. Resolving numeric IP address:");
    let resolver = SipResolver::from_system()?;
    let uri = SipUri::parse("sip:192.168.1.100:5060").unwrap();
    let targets = resolver.resolve(&uri).await?;
    print_targets(&targets);

    // Example 2: SIPS (secure) URI uses TLS and port 5061
    println!("\n2. Resolving SIPS URI:");
    let uri = SipUri::parse("sips:secure.example.com").unwrap();
    let resolver = SipResolver::from_system()?.disable_naptr();
    let targets = resolver.resolve(&uri).await.unwrap_or_else(|e| {
        println!("   Note: DNS lookup failed (expected in example): {}", e);
        vec![DnsTarget::unchecked_new("secure.example.com", 5061, Transport::Tls)]
    });
    print_targets(&targets);

    // Example 3: Explicit transport parameter
    println!("\n3. URI with explicit transport parameter:");
    let uri = SipUri::parse("sip:server.example.com;transport=tcp").unwrap();
    let targets = resolver.resolve(&uri).await.unwrap_or_else(|e| {
        println!("   Note: DNS lookup failed (expected in example): {}", e);
        vec![DnsTarget::unchecked_new("server.example.com", 5060, Transport::Tcp)]
    });
    print_targets(&targets);

    // Example 4: Static resolver for testing/development
    println!("\n4. Using StaticResolver for testing:");
    let static_targets = vec![
        DnsTarget::unchecked_new("primary.example.com", 5060, Transport::Tcp).with_priority(10),
        DnsTarget::unchecked_new("backup.example.com", 5060, Transport::Tcp).with_priority(20),
    ];
    let static_resolver = StaticResolver::new(static_targets);
    let uri = SipUri::parse("sip:test@example.com").unwrap();
    let targets = static_resolver.resolve(&uri).await?;
    print_targets(&targets);

    // Example 5: Failover scenario
    println!("\n5. Failover scenario with multiple targets:");
    let failover_targets = vec![
        DnsTarget::unchecked_new("sip1.example.com", 5060, Transport::Tls).with_priority(10),
        DnsTarget::unchecked_new("sip2.example.com", 5060, Transport::Tcp).with_priority(20),
        DnsTarget::unchecked_new("sip3.example.com", 5060, Transport::Udp).with_priority(30),
    ];
    let failover_resolver = StaticResolver::new(failover_targets);
    let targets = failover_resolver.resolve(&uri).await?;
    print_targets(&targets);
    println!("   -> Try connecting to targets in priority order");
    println!("   -> On failure, move to next priority level");

    // Example 6: Localhost resolution
    println!("\n6. Resolving localhost:");
    let uri = SipUri::parse("sip:localhost").unwrap();
    let targets = resolver.resolve(&uri).await?;
    print_targets(&targets);

    println!("\n=== End of examples ===");
    Ok(())
}

fn print_targets(targets: &[DnsTarget]) {
    for (i, target) in targets.iter().enumerate() {
        println!(
            "   [{}] {}:{} ({:?}) priority={}",
            i + 1,
            target.host(),
            target.port(),
            target.transport(),
            target.priority()
        );
    }
}
