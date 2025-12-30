// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Proxy utility helpers for forwarding requests with strict transport selection.
use anyhow::{anyhow, Result};
use sip_core::{Headers, Request, SipUri};
use sip_parse::header;
use sip_proxy::ProxyHelpers;
use sip_transaction::TransportKind;
use smol_str::SmolStr;

use crate::services::ServiceRegistry;

pub struct ProxyForwardOptions {
    pub add_record_route: bool,
    pub rewrite_request_uri: bool,
}

fn extract_first_route(headers: &Headers) -> Option<String> {
    let route = header(headers, "Route")?;
    let raw = route.as_str().trim();
    let first = raw.split(',').next()?.trim();
    Some(first.to_string())
}

fn parse_route_uri(route_value: &str) -> Option<SipUri> {
    let trimmed = route_value.trim().trim_matches('<').trim_matches('>');
    SipUri::parse(trimmed).ok()
}

fn remove_top_route(headers: &mut Headers) {
    let mut new_headers = Headers::new();
    let mut removed = false;
    for header in headers.iter() {
        if !removed && header.name().eq_ignore_ascii_case("Route") {
            let value = header.value();
            let rest = value.split(',').skip(1).collect::<Vec<_>>().join(",");
            let rest_trimmed = rest.trim();
            if !rest_trimmed.is_empty() {
                let _ = new_headers.push(header.name(), rest_trimmed);
            }
            removed = true;
            continue;
        }
        let _ = new_headers.push(header.name(), header.value());
    }
    *headers = new_headers;
}

fn is_route_local(route_uri: &SipUri, local_uri: &SipUri) -> bool {
    let local_host = local_uri.host();
    let route_host = route_uri.host();
    let local_port = local_uri.port().unwrap_or(5060);
    let route_port = route_uri.port().unwrap_or(5060);
    local_host.eq_ignore_ascii_case(route_host) && local_port == route_port
}

fn select_transport(uri: &SipUri) -> TransportKind {
    let transport_param: Option<&SmolStr> = uri
        .params()
        .get(&SmolStr::new("transport"))
        .and_then(|v| v.as_ref());
    if let Some(transport) = transport_param.map(|v| v.to_ascii_lowercase()) {
        return match transport.as_str() {
            "udp" => TransportKind::Udp,
            "tcp" => TransportKind::Tcp,
            "tls" => TransportKind::Tls,
            "ws" => TransportKind::Ws,
            "wss" => TransportKind::Wss,
            _ => TransportKind::Udp,
        };
    }

    if uri.is_sips() {
        TransportKind::Tls
    } else {
        TransportKind::Udp
    }
}

pub fn next_hop_from_request(request: &Request, local_uri: &SipUri) -> (SipUri, bool) {
    if let Some(route_value) = extract_first_route(request.headers()) {
        if let Some(route_uri) = parse_route_uri(&route_value) {
            if is_route_local(&route_uri, local_uri) {
                return (request.uri().as_sip().cloned().unwrap_or(route_uri), true);
            }
            return (route_uri, false);
        }
    }

    (
        request
            .uri()
            .as_sip()
            .cloned()
            .unwrap_or_else(|| local_uri.clone()),
        false,
    )
}

pub async fn forward_request(
    request: &Request,
    services: &ServiceRegistry,
    ctx: &sip_transaction::TransportContext,
    call_id: &str,
    options: ProxyForwardOptions,
) -> Result<()> {
    let mut proxied_req = request.clone();

    ProxyHelpers::check_max_forwards(&mut proxied_req)?;

    let proxy_host = services
        .config
        .local_uri
        .split('@')
        .nth(1)
        .unwrap_or("localhost");
    let transport_name = match ctx.transport() {
        TransportKind::Udp => "UDP",
        TransportKind::Tcp => "TCP",
        TransportKind::Tls => "TLS",
        TransportKind::Ws => "WS",
        TransportKind::Wss => "WSS",
        TransportKind::Sctp => "SCTP",
        TransportKind::TlsSctp => "TLS-SCTP",
    };

    let branch = ProxyHelpers::add_via(&mut proxied_req, proxy_host, transport_name);
    services
        .proxy_state
        .store_transaction(crate::proxy_state::ProxyTransaction {
            branch: branch.clone(),
            sender_addr: ctx.peer(),
            sender_transport: ctx.transport(),
            sender_stream: ctx.stream().cloned(),
            sender_ws_uri: ctx.ws_uri().map(String::from),
            call_id: call_id.to_string(),
            created_at: std::time::Instant::now(),
        });

    if options.add_record_route {
        if let Ok(proxy_uri) = sip_core::SipUri::parse(&services.config.local_uri) {
            ProxyHelpers::add_record_route(&mut proxied_req, &proxy_uri);
        }
    }

    let local_uri = sip_core::SipUri::parse(&services.config.local_uri)
        .map_err(|_| anyhow!("Invalid local_uri"))?;

    let (target_uri, remove_route) = next_hop_from_request(&proxied_req, &local_uri);
    if remove_route {
        remove_top_route(proxied_req.headers_mut());
    }

    if options.rewrite_request_uri {
        ProxyHelpers::set_request_uri(&mut proxied_req, target_uri.clone());
    }

    let target_addr = format!(
        "{}:{}",
        target_uri.host(),
        target_uri.port().unwrap_or(5060)
    )
    .parse::<std::net::SocketAddr>()?;

    let transport = select_transport(&target_uri);
    let payload = sip_parse::serialize_request(&proxied_req);

    match transport {
        TransportKind::Udp => {
            let socket = services
                .udp_socket
                .get()
                .ok_or_else(|| anyhow!("UDP socket not available for proxy forwarding"))?;
            sip_transport::send_udp(socket.as_ref(), &target_addr, &payload).await?;
        }
        TransportKind::Tcp => {
            sip_transport::send_tcp(&target_addr, &payload).await?;
        }
        TransportKind::Tls => {
            #[cfg(feature = "tls")]
            {
                let config = services
                    .tls_client_config
                    .get()
                    .ok_or_else(|| anyhow!("TLS client config not available"))?;
                let tls = sip_transport::TlsConfig {
                    server_name: target_uri.host().to_string(),
                    client_config: config.clone(),
                };
                sip_transport::send_tls(&target_addr, &payload, &tls).await?;
            }
            #[cfg(not(feature = "tls"))]
            {
                return Err(anyhow!("TLS support not enabled"));
            }
        }
        TransportKind::Ws | TransportKind::Wss => {
            #[cfg(feature = "ws")]
            {
                let scheme = if transport == TransportKind::Wss {
                    "wss"
                } else {
                    "ws"
                };
                let ws_url = format!("{}://{}:{}", scheme, target_uri.host(), target_addr.port());
                let data = bytes::Bytes::from(payload.to_vec());
                if transport == TransportKind::Wss {
                    sip_transport::send_wss(&ws_url, data).await?;
                } else {
                    sip_transport::send_ws(&ws_url, data).await?;
                }
            }
            #[cfg(not(feature = "ws"))]
            {
                return Err(anyhow!("WS/WSS proxy forwarding not enabled"));
            }
        }
        TransportKind::Sctp | TransportKind::TlsSctp => {
            return Err(anyhow!("SCTP proxy forwarding not implemented"));
        }
    }

    Ok(())
}
