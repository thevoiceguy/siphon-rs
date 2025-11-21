use anyhow::{anyhow, Result};
use rand::Rng;
use sip_core::SipUri;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::net::IpAddr;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::RecordType,
    TokioAsyncResolver,
};

/// Transport protocol discovered via DNS resolution (RFC 3263).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Ws,
    Wss,
}

impl Transport {
    /// Returns the protocol string for SRV lookup.
    pub fn as_proto_str(&self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp | Transport::Tls => "tcp",
            Transport::Ws | Transport::Wss => "tcp", // WebSocket uses TCP
        }
    }

    /// Returns the service prefix for SRV lookup.
    pub fn as_service_str(&self, sips: bool) -> &'static str {
        match self {
            Transport::Tls | Transport::Wss => "_sips",
            _ if sips => "_sips",
            _ => "_sip",
        }
    }
}

/// Target endpoint returned by DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTarget {
    pub host: SmolStr,
    pub port: u16,
    pub transport: Transport,
    pub priority: u16,
}

impl DnsTarget {
    pub fn new(host: impl Into<SmolStr>, port: u16, transport: Transport) -> Self {
        Self {
            host: host.into(),
            port,
            transport,
            priority: 0,
        }
    }

    pub fn with_priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }
}

/// Result of NAPTR record parsing (RFC 3263 §4.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NaptrRecord {
    order: u16,
    preference: u16,
    transport: Transport,
    replacement: SmolStr,
}

/// Trait for DNS resolution backends.
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, uri: &SipUri) -> Result<Vec<DnsTarget>>;
}

/// DNS resolver implementing RFC 3263 resolution algorithm.
///
/// Resolution follows this priority order:
/// 1. If numeric IP in URI: use directly
/// 2. If explicit port in URI: skip SRV, do A/AAAA
/// 3. NAPTR lookup for transport discovery
/// 4. SRV lookup with priority/weight handling
/// 5. Fallback to A/AAAA with default port
#[derive(Clone)]
pub struct SipResolver {
    resolver: TokioAsyncResolver,
    enable_naptr: bool,
}

impl SipResolver {
    /// Creates a resolver using system DNS configuration.
    pub fn from_system() -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self {
            resolver,
            enable_naptr: true,
        })
    }

    /// Creates a resolver with custom configuration.
    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(config, opts);
        Ok(Self {
            resolver,
            enable_naptr: true,
        })
    }

    /// Disables NAPTR lookups (useful for testing or non-compliant networks).
    pub fn disable_naptr(mut self) -> Self {
        self.enable_naptr = false;
        self
    }

    /// Determines the default transport for a URI.
    fn default_transport(uri: &SipUri) -> Transport {
        if uri.sips {
            Transport::Tls
        } else {
            // Check for explicit transport parameter
            if let Some(transport_param) = uri.params.get(&SmolStr::new("transport".to_owned())) {
                if let Some(t) = transport_param {
                    return match t.as_str().to_ascii_lowercase().as_str() {
                        "tcp" => Transport::Tcp,
                        "tls" => Transport::Tls,
                        "ws" => Transport::Ws,
                        "wss" => Transport::Wss,
                        _ => Transport::Udp,
                    };
                }
            }
            Transport::Udp
        }
    }

    /// Checks if the host is a numeric IP address.
    fn is_numeric_ip(host: &str) -> bool {
        host.parse::<IpAddr>().is_ok()
    }

    /// Performs complete RFC 3263 resolution.
    async fn resolve_internal(&self, uri: &SipUri) -> Result<Vec<DnsTarget>> {
        let host = uri.host.as_str();

        // RFC 3263 §4: If numeric IP, use directly
        if Self::is_numeric_ip(host) {
            let port = uri.port.unwrap_or(if uri.sips { 5061 } else { 5060 });
            return Ok(vec![DnsTarget::new(
                host,
                port,
                Self::default_transport(uri),
            )]);
        }

        // RFC 3263 §4: If explicit port, skip SRV, do A/AAAA
        if let Some(port) = uri.port {
            let ips = self.lookup_a_aaaa(host).await?;
            return Ok(ips
                .into_iter()
                .map(|ip| DnsTarget::new(ip.to_string(), port, Self::default_transport(uri)))
                .collect());
        }

        // RFC 3263 §4.1: Perform NAPTR lookup
        let transports = if self.enable_naptr {
            self.lookup_naptr(uri).await.unwrap_or_else(|_| {
                // NAPTR failed, use default transport ordering
                self.default_transport_order(uri)
            })
        } else {
            self.default_transport_order(uri)
        };

        // RFC 3263 §4.2: Perform SRV lookups for each transport
        let mut all_targets = Vec::new();
        for transport in transports {
            if let Ok(targets) = self.lookup_srv(host, transport, uri.sips).await {
                all_targets.extend(targets);
            }
        }

        // RFC 3263 §4.3: Fallback to A/AAAA if no SRV records
        if all_targets.is_empty() {
            let default_port = if uri.sips { 5061 } else { 5060 };
            let ips = self.lookup_a_aaaa(host).await?;
            for ip in ips {
                all_targets.push(DnsTarget::new(
                    ip.to_string(),
                    default_port,
                    Self::default_transport(uri),
                ));
            }
        }

        if all_targets.is_empty() {
            Err(anyhow!("No DNS targets found for {}", host))
        } else {
            Ok(all_targets)
        }
    }

    /// Returns default transport ordering when NAPTR is unavailable.
    fn default_transport_order(&self, uri: &SipUri) -> Vec<Transport> {
        if uri.sips {
            // SIPS requires TLS
            vec![Transport::Tls]
        } else {
            // Check for explicit transport parameter
            if let Some(transport_param) = uri.params.get(&SmolStr::new("transport".to_owned())) {
                if let Some(t) = transport_param {
                    let transport = match t.as_str().to_ascii_lowercase().as_str() {
                        "tcp" => Transport::Tcp,
                        "tls" => Transport::Tls,
                        "ws" => Transport::Ws,
                        "wss" => Transport::Wss,
                        _ => Transport::Udp,
                    };
                    return vec![transport];
                }
            }
            // RFC 3263 default: try TCP first, then UDP
            vec![Transport::Tcp, Transport::Udp]
        }
    }

    /// Performs NAPTR lookup per RFC 3263 §4.1.
    async fn lookup_naptr(&self, uri: &SipUri) -> Result<Vec<Transport>> {
        let host = uri.host.as_str();
        let lookup = self
            .resolver
            .lookup(format!("{}.", host), RecordType::NAPTR)
            .await?;

        let mut records = Vec::new();
        for rec in lookup.iter() {
            if let Some(rdata) = rec.as_naptr() {
                let service = String::from_utf8_lossy(rdata.services()).to_ascii_uppercase();
                let replacement = rdata.replacement().to_utf8();

                // Parse SIP service strings (RFC 3263 §4.1)
                let transport = if service.contains("SIPS+D2T") {
                    Some(Transport::Tls)
                } else if service.contains("SIP+D2T") {
                    Some(Transport::Tcp)
                } else if service.contains("SIP+D2U") {
                    Some(Transport::Udp)
                } else if service.contains("SIPS+D2W") {
                    Some(Transport::Wss)
                } else if service.contains("SIP+D2W") {
                    Some(Transport::Ws)
                } else {
                    None
                };

                if let Some(transport) = transport {
                    records.push(NaptrRecord {
                        order: rdata.order(),
                        preference: rdata.preference(),
                        transport,
                        replacement: SmolStr::new(replacement.trim_end_matches('.').to_owned()),
                    });
                }
            }
        }

        if records.is_empty() {
            return Err(anyhow!("No valid NAPTR records found"));
        }

        // Sort by order, then preference (RFC 3263 §4.1)
        records.sort();

        // Extract transports in priority order
        Ok(records.into_iter().map(|r| r.transport).collect())
    }

    /// Performs SRV lookup per RFC 3263 §4.2.
    async fn lookup_srv(
        &self,
        host: &str,
        transport: Transport,
        sips: bool,
    ) -> Result<Vec<DnsTarget>> {
        let service = transport.as_service_str(sips);
        let proto = transport.as_proto_str();
        let srv_name = format!("{}._{}.{}", service, proto, host);

        let lookup = self.resolver.srv_lookup(srv_name).await?;

        // Group by priority (RFC 2782 §3)
        let mut priority_groups: BTreeMap<u16, Vec<(u16, SmolStr, u16)>> = BTreeMap::new();
        for rec in lookup.iter() {
            let target = rec.target().to_utf8();
            priority_groups
                .entry(rec.priority())
                .or_default()
                .push((
                    rec.weight(),
                    SmolStr::new(target.trim_end_matches('.').to_owned()),
                    rec.port(),
                ));
        }

        // Process priority groups in order
        let mut targets = Vec::new();
        for (priority, records) in priority_groups {
            let weighted = select_by_weight(records);
            for (host, port) in weighted {
                targets.push(DnsTarget::new(host, port, transport).with_priority(priority));
            }
        }

        if targets.is_empty() {
            Err(anyhow!("No SRV records found"))
        } else {
            Ok(targets)
        }
    }

    /// Performs A and AAAA lookup with Happy Eyeballs preference.
    async fn lookup_a_aaaa(&self, host: &str) -> Result<Vec<IpAddr>> {
        let lookup = self.resolver.lookup_ip(host).await?;

        let mut ipv6_addrs = Vec::new();
        let mut ipv4_addrs = Vec::new();

        for ip in lookup.iter() {
            match ip {
                IpAddr::V6(addr) => ipv6_addrs.push(IpAddr::V6(addr)),
                IpAddr::V4(addr) => ipv4_addrs.push(IpAddr::V4(addr)),
            }
        }

        // Happy Eyeballs (RFC 8305): prefer IPv6 but interleave with IPv4
        let mut result = Vec::new();
        let max_len = ipv6_addrs.len().max(ipv4_addrs.len());
        for i in 0..max_len {
            if i < ipv6_addrs.len() {
                result.push(ipv6_addrs[i]);
            }
            if i < ipv4_addrs.len() {
                result.push(ipv4_addrs[i]);
            }
        }

        if result.is_empty() {
            Err(anyhow!("No A/AAAA records found for {}", host))
        } else {
            Ok(result)
        }
    }
}

#[async_trait::async_trait]
impl Resolver for SipResolver {
    async fn resolve(&self, uri: &SipUri) -> Result<Vec<DnsTarget>> {
        self.resolve_internal(uri).await
    }
}

/// Selects SRV targets by weight per RFC 2782.
///
/// Algorithm:
/// 1. Sum all weights
/// 2. Pick random number in range
/// 3. Select target where cumulative weight >= random
/// 4. Remove selected target and repeat
fn select_by_weight(mut records: Vec<(u16, SmolStr, u16)>) -> Vec<(SmolStr, u16)> {
    if records.is_empty() {
        return Vec::new();
    }

    let mut rng = rand::thread_rng();
    let mut result = Vec::new();

    while !records.is_empty() {
        let total_weight: u32 = records.iter().map(|(w, _, _)| *w as u32).sum();

        let idx = if total_weight == 0 {
            // All weights are 0, pick randomly
            rng.gen_range(0..records.len())
        } else {
            // Pick based on weight (RFC 2782 algorithm)
            let pick = rng.gen_range(0..total_weight);
            let mut cumulative = 0u32;
            records
                .iter()
                .position(|(w, _, _)| {
                    cumulative += *w as u32;
                    cumulative > pick
                })
                .unwrap_or(0)
        };

        let (_, host, port) = records.remove(idx);
        result.push((host, port));
    }

    result
}

/// Static resolver for testing that returns pre-configured endpoints.
#[derive(Clone)]
pub struct StaticResolver {
    targets: Vec<DnsTarget>,
}

impl StaticResolver {
    pub fn new(targets: Vec<DnsTarget>) -> Self {
        Self { targets }
    }

    pub fn single(host: impl Into<SmolStr>, port: u16, transport: Transport) -> Self {
        Self {
            targets: vec![DnsTarget::new(host, port, transport)],
        }
    }
}

#[async_trait::async_trait]
impl Resolver for StaticResolver {
    async fn resolve(&self, _uri: &SipUri) -> Result<Vec<DnsTarget>> {
        Ok(self.targets.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_resolver_returns_configured_targets() {
        let targets = vec![
            DnsTarget::new("server1.example.com", 5060, Transport::Udp),
            DnsTarget::new("server2.example.com", 5060, Transport::Tcp),
        ];
        let resolver = StaticResolver::new(targets.clone());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:test@example.com").unwrap();
        let result = rt.block_on(resolver.resolve(&uri)).expect("resolve");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].host.as_str(), "server1.example.com");
        assert_eq!(result[1].host.as_str(), "server2.example.com");
    }

    #[test]
    fn single_static_resolver() {
        let resolver = StaticResolver::single("example.com", 5060, Transport::Udp);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:test@example.com").unwrap();
        let result = rt.block_on(resolver.resolve(&uri)).expect("resolve");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host.as_str(), "example.com");
        assert_eq!(result[0].port, 5060);
        assert_eq!(result[0].transport, Transport::Udp);
    }

    #[test]
    fn numeric_ip_returns_directly() {
        let uri = SipUri::parse("sip:192.168.1.1").unwrap();
        assert!(SipResolver::is_numeric_ip("192.168.1.1"));
        assert!(!SipResolver::is_numeric_ip("example.com"));
    }

    #[test]
    fn sips_uses_tls_transport() {
        let uri = SipUri::parse("sips:example.com").unwrap();
        assert_eq!(SipResolver::default_transport(&uri), Transport::Tls);
    }

    #[test]
    fn sip_uses_udp_transport_by_default() {
        let uri = SipUri::parse("sip:example.com").unwrap();
        assert_eq!(SipResolver::default_transport(&uri), Transport::Udp);
    }

    #[test]
    fn explicit_transport_parameter_honored() {
        let uri = SipUri::parse("sip:example.com;transport=tcp").unwrap();
        assert_eq!(SipResolver::default_transport(&uri), Transport::Tcp);

        let uri = SipUri::parse("sip:example.com;transport=tls").unwrap();
        assert_eq!(SipResolver::default_transport(&uri), Transport::Tls);
    }

    #[test]
    fn weight_selection_handles_zero_weights() {
        let records = vec![
            (0, SmolStr::new("host1".to_owned()), 5060),
            (0, SmolStr::new("host2".to_owned()), 5060),
        ];
        let result = select_by_weight(records);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn weight_selection_prefers_higher_weights() {
        // Run multiple times to verify statistical distribution
        let mut selections = std::collections::HashMap::new();
        for _ in 0..1000 {
            let records = vec![
                (100, SmolStr::new("high".to_owned()), 5060),
                (1, SmolStr::new("low".to_owned()), 5060),
            ];
            let result = select_by_weight(records);
            *selections.entry(result[0].0.clone()).or_insert(0) += 1;
        }

        // "high" should be selected much more often than "low"
        let high_count = selections.get(&SmolStr::new("high".to_owned())).unwrap_or(&0);
        let low_count = selections.get(&SmolStr::new("low".to_owned())).unwrap_or(&0);
        assert!(*high_count > *low_count * 50); // Should be ~100x more
    }

    #[test]
    fn naptr_record_ordering() {
        let mut records = vec![
            NaptrRecord {
                order: 10,
                preference: 20,
                transport: Transport::Tcp,
                replacement: SmolStr::new("tcp.example.com".to_owned()),
            },
            NaptrRecord {
                order: 10,
                preference: 10,
                transport: Transport::Udp,
                replacement: SmolStr::new("udp.example.com".to_owned()),
            },
            NaptrRecord {
                order: 5,
                preference: 50,
                transport: Transport::Tls,
                replacement: SmolStr::new("tls.example.com".to_owned()),
            },
        ];

        records.sort();

        // Order 5 should come first
        assert_eq!(records[0].order, 5);
        // Within order 10, preference 10 should come before 20
        assert_eq!(records[1].preference, 10);
        assert_eq!(records[2].preference, 20);
    }
}
