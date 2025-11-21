use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use sip_core::{decrement_max_forwards, Header, Headers, Request, SipUri};
use sip_dns::{DnsEndpoint, Resolver, Transport as DnsTransport};
use sip_parse::{parse_route_headers, serialize_request};
use sip_transaction::{generate_branch_id, TransportContext, TransportDispatcher, TransportKind};
use sip_transport::{send_udp, DefaultTransportPolicy, TransportPolicy};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::info_span;

/// Configuration for a simple stateless proxy hop.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub next_hop: SocketAddr,
}

#[derive(Clone)]
pub struct StatelessProxy {
    socket: Arc<UdpSocket>,
    config: ProxyConfig,
}

impl StatelessProxy {
    /// Creates a new proxy using the provided socket and configuration.
    pub fn new(socket: Arc<UdpSocket>, config: ProxyConfig) -> Self {
        Self { socket, config }
    }

    /// Forwards a SIP request to the configured next hop.
    pub async fn forward(&self, request: &Request) -> Result<()> {
        let bytes = serialize_request(request);
        send_udp(self.socket.as_ref(), &self.config.next_hop, &bytes).await?;
        Ok(())
    }
}

/// Stateful proxy that maintains branch stamps and rewrites Record-Route/Route.
pub struct StatefulProxy<R: Resolver> {
    dispatcher: Arc<dyn TransportDispatcher>,
    resolver: R,
    policy: Arc<dyn TransportPolicy>,
    proxy_uri: SipUri,
    via_host: String,
    record_route: bool,
    branch_map: DashMap<String, String>,
}

impl<R: Resolver> StatefulProxy<R> {
    pub fn new(
        dispatcher: Arc<dyn TransportDispatcher>,
        resolver: R,
        proxy_uri: SipUri,
        via_host: String,
        record_route: bool,
    ) -> Self {
        Self {
            dispatcher,
            resolver,
            policy: Arc::new(DefaultTransportPolicy::default()),
            proxy_uri,
            via_host,
            record_route,
            branch_map: DashMap::new(),
        }
    }

    /// Proxies a request, applying RFC 3263 selection and basic RFC 3261 rewriting.
    pub async fn proxy(&self, request: &Request, transport: TransportKind) -> Result<()> {
        let span = info_span!(
            "proxy_request",
            method = %request.start.method.as_str(),
            uri = %request.start.uri.as_str()
        );
        let _entered = span.enter();
        let mut req = request.clone();
        decrement_max_forwards(&mut req.headers).map_err(|_| anyhow!("Max-Forwards exhausted"))?;

        self.prepend_via(&mut req);
        if self.record_route {
            self.insert_record_route(&mut req);
        }

        let target_uri = next_hop_uri(&req);
        let endpoints = self.resolver.resolve(&target_uri)?;
        let payload = serialize_request(&req);

        for ep in endpoints {
            let target_transport = self.choose_transport(&ep, transport, &payload);
            let addr: SocketAddr = format!("{}:{}", ep.target, ep.port)
                .parse()
                .map_err(|e| anyhow!("invalid target addr: {e}"))?;
            let ctx = TransportContext::new(target_transport, addr, None);
            if let Err(_e) = self.dispatcher.dispatch(&ctx, Bytes::from(payload.clone())).await {
                continue;
            }
            return Ok(());
        }
        Err(anyhow!("no reachable endpoints"))
    }

    fn choose_transport(&self, ep: &DnsEndpoint, _incoming: TransportKind, payload: &Bytes) -> TransportKind {
        let requested = match ep.transport {
            DnsTransport::Udp => sip_transport::TransportKind::Udp,
            DnsTransport::Tcp => sip_transport::TransportKind::Tcp,
            DnsTransport::Tls => sip_transport::TransportKind::Tls,
        };
        let selected = self
            .policy
            .choose(requested, payload.len(), matches!(requested, sip_transport::TransportKind::Tls));
        match selected {
            sip_transport::TransportKind::Udp => TransportKind::Udp,
            sip_transport::TransportKind::Tcp => TransportKind::Tcp,
            sip_transport::TransportKind::Tls => TransportKind::Tls,
        }
    }

    fn prepend_via(&self, req: &mut Request) {
        let branch = generate_branch_id();
        self.branch_map
            .insert(branch.as_str().to_owned(), branch.as_str().to_owned());
        let via_value = format!(
            "SIP/2.0/UDP {};branch={};rport",
            self.via_host, branch
        );
        let mut vec = Vec::new();
        vec.push(Header {
            name: "Via".into(),
            value: via_value.into(),
        });
        vec.extend(req.headers.clone().into_iter());
        req.headers = Headers::from_vec(vec);
    }

    fn insert_record_route(&self, req: &mut Request) {
        let rr = format!("<{}>", self.proxy_uri.as_str());
        req.headers
            .push("Record-Route".into(), rr.into());
    }
}

fn next_hop_uri(req: &Request) -> SipUri {
    if let Some(route) = parse_route_headers(&req.headers, "Route").first() {
        return route.uri().clone();
    }
    // For proxies, Request-URI should be a SIP URI
    // tel URIs in Request-URI would typically be handled by gateways, not proxies
    req.start.uri.as_sip()
        .expect("Proxy requires SIP URI in Request-URI")
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sip_core::{RequestLine, Method};
    use sip_transaction::TransportContext;
    use tokio::sync::Mutex;

    struct StaticResolver {
        endpoint: DnsEndpoint,
    }

    impl Resolver for StaticResolver {
        fn resolve(&self, _uri: &SipUri) -> Result<Vec<DnsEndpoint>> {
            Ok(vec![self.endpoint.clone()])
        }
    }

    #[derive(Default)]
    struct TestDispatcher {
        sent: Mutex<Vec<Bytes>>,
    }

    #[async_trait]
    impl TransportDispatcher for TestDispatcher {
        async fn dispatch(&self, _ctx: &TransportContext, payload: Bytes) -> Result<()> {
            let mut guard = self.sent.lock().await;
            guard.push(payload);
            Ok(())
        }
    }

    #[tokio::test]
    async fn proxy_inserts_via_and_decrements_max_forwards() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let resolver = StaticResolver {
            endpoint: DnsEndpoint {
                target: "127.0.0.1".into(),
                port: 5060,
                transport: DnsTransport::Udp,
            },
        };
        let proxy = StatefulProxy::new(
            dispatcher.clone(),
            resolver,
            SipUri::parse("sip:proxy.example.com").unwrap(),
            "proxy.example.com".to_owned(),
            true,
        );

        let mut headers = Headers::new();
        headers.push("Max-Forwards".into(), "70".into());
        headers.push("Contact".into(), "<sip:alice@example.com>".into());
        let req = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        proxy.proxy(&req, TransportKind::Udp).await.expect("proxy");

        let sent = dispatcher.sent.lock().await;
        assert_eq!(sent.len(), 1);
        let text = std::str::from_utf8(&sent[0]).unwrap();
        assert!(text.contains("Via:"), "via missing");
        assert!(text.contains("Max-Forwards: 69"), "max forwards not decremented");
        assert!(text.contains("Record-Route"), "record route missing");
    }
}
