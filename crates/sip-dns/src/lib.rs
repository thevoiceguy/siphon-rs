pub mod enum_lookup;

pub use enum_lookup::{
    enum_to_domain, filter_sip_records, select_best_sip_record, sort_enum_records,
    tel_uri_to_enum_domain, EnumNaptrRecord,
};

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

/// Transport protocol discovered via DNS resolution (RFC 3263, RFC 4168).
///
/// # SCTP Support (RFC 4168)
///
/// SCTP and TLS-SCTP are included for DNS resolution and transport discovery.
/// Actual SCTP socket implementations are platform-specific and not included
/// in the core DNS resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    /// WebSocket transport
    Ws,
    /// Secure WebSocket transport
    Wss,
    /// SCTP transport (RFC 4168)
    Sctp,
    /// TLS over SCTP transport (RFC 4168)
    TlsSctp,
}

impl Transport {
    /// Returns the protocol string for SRV lookup.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_dns::Transport;
    ///
    /// assert_eq!(Transport::Udp.as_proto_str(), "udp");
    /// assert_eq!(Transport::Tcp.as_proto_str(), "tcp");
    /// assert_eq!(Transport::Sctp.as_proto_str(), "sctp");
    /// ```
    pub fn as_proto_str(&self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp | Transport::Tls => "tcp",
            Transport::Ws | Transport::Wss => "tcp", // WebSocket uses TCP
            Transport::Sctp | Transport::TlsSctp => "sctp",
        }
    }

    /// Returns the service prefix for SRV lookup.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_dns::Transport;
    ///
    /// assert_eq!(Transport::Udp.as_service_str(false), "_sip");
    /// assert_eq!(Transport::Tls.as_service_str(false), "_sips");
    /// assert_eq!(Transport::TlsSctp.as_service_str(false), "_sips");
    /// ```
    pub fn as_service_str(&self, sips: bool) -> &'static str {
        match self {
            Transport::Tls | Transport::Wss | Transport::TlsSctp => "_sips",
            _ if sips => "_sips",
            _ => "_sip",
        }
    }

    /// Returns the Via header transport parameter value.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_dns::Transport;
    ///
    /// assert_eq!(Transport::Udp.as_via_str(), "UDP");
    /// assert_eq!(Transport::Tcp.as_via_str(), "TCP");
    /// assert_eq!(Transport::Tls.as_via_str(), "TLS");
    /// assert_eq!(Transport::Sctp.as_via_str(), "SCTP");
    /// assert_eq!(Transport::TlsSctp.as_via_str(), "TLS-SCTP");
    /// ```
    pub fn as_via_str(&self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
            Transport::Tls => "TLS",
            Transport::Ws => "WS",
            Transport::Wss => "WSS",
            Transport::Sctp => "SCTP",
            Transport::TlsSctp => "TLS-SCTP",
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
                        "sctp" => Transport::Sctp,
                        "tls-sctp" => Transport::TlsSctp,
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
                        "sctp" => Transport::Sctp,
                        "tls-sctp" => Transport::TlsSctp,
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

                // Parse SIP service strings (RFC 3263 §4.1, RFC 4168)
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
                } else if service.contains("SIPS+D2S") {
                    // RFC 4168: TLS over SCTP
                    Some(Transport::TlsSctp)
                } else if service.contains("SIP+D2S") {
                    // RFC 4168: Plain SCTP
                    Some(Transport::Sctp)
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

// ============================================================================
// DHCP Options Support: RFC 3361 (Option 120), RFC 2132 (Option 66), RFC 5859 (Option 150)
// ============================================================================

/// DHCP Option 66 TFTP server name (RFC 2132).
///
/// Contains a single TFTP server identifier (hostname, domain, or IP as string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TftpServerName(pub SmolStr);

impl TftpServerName {
    /// Returns the server name as a string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Parses DHCP Option 66 data per RFC 2132.
///
/// Option 66 contains a string identifying a TFTP server (hostname, domain, or IP).
///
/// # Example
///
/// ```
/// use sip_dns::parse_dhcp_option_66;
///
/// let data = b"tftp.example.com";
/// let server = parse_dhcp_option_66(data).unwrap();
/// assert_eq!(server.as_str(), "tftp.example.com");
/// ```
pub fn parse_dhcp_option_66(data: &[u8]) -> Result<TftpServerName> {
    if data.is_empty() {
        return Err(anyhow!("Empty DHCP Option 66 data"));
    }

    // Option 66 is a simple string
    let server_name = String::from_utf8_lossy(data).to_string();
    Ok(TftpServerName(SmolStr::new(server_name)))
}

/// Parses DHCP Option 150 data per RFC 5859.
///
/// Option 150 contains a list of IPv4 addresses for TFTP servers.
///
/// # Format
///
/// Multiple 4-byte IPv4 addresses in network byte order.
/// Length must be a multiple of 4 bytes.
///
/// # Example
///
/// ```
/// use sip_dns::parse_dhcp_option_150;
///
/// // Two TFTP server addresses
/// let data = vec![192, 168, 1, 1, 10, 0, 0, 1];
/// let servers = parse_dhcp_option_150(&data).unwrap();
/// assert_eq!(servers.len(), 2);
/// assert_eq!(servers[0].to_string(), "192.168.1.1");
/// assert_eq!(servers[1].to_string(), "10.0.0.1");
/// ```
pub fn parse_dhcp_option_150(data: &[u8]) -> Result<Vec<std::net::Ipv4Addr>> {
    if data.is_empty() {
        return Err(anyhow!("Empty DHCP Option 150 data"));
    }

    if data.len() % 4 != 0 {
        return Err(anyhow!(
            "Invalid DHCP Option 150 data length: {} (must be multiple of 4)",
            data.len()
        ));
    }

    let mut servers = Vec::new();
    for chunk in data.chunks_exact(4) {
        let addr = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        servers.push(addr);
    }

    if servers.is_empty() {
        Err(anyhow!("No TFTP servers found in DHCP Option 150"))
    } else {
        Ok(servers)
    }
}

/// DHCP Option 120 SIP server entry (RFC 3361).
///
/// Option 120 can contain either domain names or IPv4 addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpSipServer {
    /// Domain name that should be resolved via DNS (encoding 0)
    Domain(SmolStr),
    /// IPv4 address to use directly (encoding 1)
    Ipv4(std::net::Ipv4Addr),
}

impl DhcpSipServer {
    /// Returns the server as a string suitable for DNS resolution or direct use.
    pub fn as_str(&self) -> String {
        match self {
            DhcpSipServer::Domain(name) => name.to_string(),
            DhcpSipServer::Ipv4(addr) => addr.to_string(),
        }
    }
}

/// Trait for DHCP providers that can query DHCP options.
///
/// This trait allows platform-specific DHCP implementations to be plugged in.
/// Implement this trait to integrate with system DHCP or use [`StaticDhcpProvider`]
/// for testing.
#[async_trait::async_trait]
pub trait DhcpProvider: Send + Sync {
    /// Queries DHCP for Option 120 (SIP servers).
    ///
    /// Returns a list of SIP servers in preference order, or None if
    /// Option 120 is not available from DHCP.
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>>;

    /// Queries DHCP for Option 66 (TFTP server name).
    ///
    /// Returns the TFTP server name, or None if Option 66 is not available.
    async fn query_tftp_server_name(&self) -> Result<Option<TftpServerName>> {
        Ok(None)
    }

    /// Queries DHCP for Option 150 (TFTP server addresses).
    ///
    /// Returns a list of TFTP server addresses in preference order, or None if
    /// Option 150 is not available from DHCP.
    async fn query_tftp_server_addresses(&self) -> Result<Option<Vec<std::net::Ipv4Addr>>> {
        Ok(None)
    }
}

/// Parses DHCP Option 120 data per RFC 3361.
///
/// # Encoding
///
/// - **Encoding 0**: Domain names in RFC 1035 format (length-prefixed labels)
/// - **Encoding 1**: IPv4 addresses (4 bytes each)
///
/// # Example
///
/// ```
/// use sip_dns::parse_dhcp_option_120;
///
/// // Encoding 1: Two IPv4 addresses
/// let data = vec![1, 192, 168, 1, 1, 10, 0, 0, 1];
/// let servers = parse_dhcp_option_120(&data).unwrap();
/// assert_eq!(servers.len(), 2);
///
/// // Encoding 0: Domain name "example.com"
/// let data = vec![0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
/// let servers = parse_dhcp_option_120(&data).unwrap();
/// assert_eq!(servers.len(), 1);
/// ```
pub fn parse_dhcp_option_120(data: &[u8]) -> Result<Vec<DhcpSipServer>> {
    if data.is_empty() {
        return Err(anyhow!("Empty DHCP Option 120 data"));
    }

    let encoding = data[0];
    let payload = &data[1..];

    match encoding {
        0 => parse_dhcp_domain_names(payload),
        1 => parse_dhcp_ipv4_addresses(payload),
        _ => Err(anyhow!("Invalid DHCP Option 120 encoding: {}", encoding)),
    }
}

/// Parses domain names from DHCP Option 120 (encoding 0).
///
/// Domain names are encoded using RFC 1035 format:
/// - Each label is prefixed with a length byte
/// - Labels are concatenated
/// - Terminated with a zero-length label
fn parse_dhcp_domain_names(data: &[u8]) -> Result<Vec<DhcpSipServer>> {
    let mut servers = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let mut labels = Vec::new();

        // Parse labels until we hit a zero-length label or end of data
        loop {
            if pos >= data.len() {
                break;
            }

            let len = data[pos] as usize;
            pos += 1;

            if len == 0 {
                // End of this domain name
                break;
            }

            if pos + len > data.len() {
                return Err(anyhow!("Invalid domain name label length"));
            }

            let label = &data[pos..pos + len];
            labels.push(String::from_utf8_lossy(label).to_string());
            pos += len;
        }

        if !labels.is_empty() {
            let domain = labels.join(".");
            servers.push(DhcpSipServer::Domain(SmolStr::new(domain)));
        }
    }

    if servers.is_empty() {
        Err(anyhow!("No domain names found in DHCP Option 120"))
    } else {
        Ok(servers)
    }
}

/// Parses IPv4 addresses from DHCP Option 120 (encoding 1).
///
/// Each address is 4 bytes in network byte order.
fn parse_dhcp_ipv4_addresses(data: &[u8]) -> Result<Vec<DhcpSipServer>> {
    if data.len() % 4 != 0 {
        return Err(anyhow!(
            "Invalid DHCP Option 120 IPv4 data length: {}",
            data.len()
        ));
    }

    let mut servers = Vec::new();
    for chunk in data.chunks_exact(4) {
        let addr = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        servers.push(DhcpSipServer::Ipv4(addr));
    }

    if servers.is_empty() {
        Err(anyhow!("No IPv4 addresses found in DHCP Option 120"))
    } else {
        Ok(servers)
    }
}

/// Static DHCP provider for testing and manual configuration.
///
/// Returns pre-configured SIP and TFTP servers without querying actual DHCP.
///
/// # Example
///
/// ```
/// use sip_dns::{StaticDhcpProvider, DhcpSipServer, TftpServerName};
/// use smol_str::SmolStr;
///
/// let provider = StaticDhcpProvider::new(vec![
///     DhcpSipServer::Domain(SmolStr::new("sip.example.com".to_owned())),
///     DhcpSipServer::Ipv4("192.168.1.1".parse().unwrap()),
/// ]);
/// ```
#[derive(Clone)]
pub struct StaticDhcpProvider {
    sip_servers: Option<Vec<DhcpSipServer>>,
    tftp_server_name: Option<TftpServerName>,
    tftp_server_addresses: Option<Vec<std::net::Ipv4Addr>>,
}

impl StaticDhcpProvider {
    /// Creates a provider that returns the given SIP servers (Option 120).
    pub fn new(servers: Vec<DhcpSipServer>) -> Self {
        Self {
            sip_servers: Some(servers),
            tftp_server_name: None,
            tftp_server_addresses: None,
        }
    }

    /// Creates a provider that returns no servers (simulates DHCP without any options).
    pub fn empty() -> Self {
        Self {
            sip_servers: None,
            tftp_server_name: None,
            tftp_server_addresses: None,
        }
    }

    /// Sets the TFTP server name (Option 66).
    pub fn with_tftp_name(mut self, name: TftpServerName) -> Self {
        self.tftp_server_name = Some(name);
        self
    }

    /// Sets the TFTP server addresses (Option 150).
    pub fn with_tftp_addresses(mut self, addresses: Vec<std::net::Ipv4Addr>) -> Self {
        self.tftp_server_addresses = Some(addresses);
        self
    }
}

#[async_trait::async_trait]
impl DhcpProvider for StaticDhcpProvider {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        Ok(self.sip_servers.clone())
    }

    async fn query_tftp_server_name(&self) -> Result<Option<TftpServerName>> {
        Ok(self.tftp_server_name.clone())
    }

    async fn query_tftp_server_addresses(&self) -> Result<Option<Vec<std::net::Ipv4Addr>>> {
        Ok(self.tftp_server_addresses.clone())
    }
}

/// DHCP-based SIP server resolver (RFC 3361).
///
/// Queries DHCP Option 120 to discover SIP servers. If DHCP provides domain names,
/// they are resolved via the provided DNS resolver.
///
/// # Example
///
/// ```no_run
/// use sip_dns::{DhcpResolver, StaticDhcpProvider, SipResolver, DhcpSipServer, Resolver};
/// use sip_core::SipUri;
/// use smol_str::SmolStr;
///
/// # async fn example() -> anyhow::Result<()> {
/// let dhcp = StaticDhcpProvider::new(vec![
///     DhcpSipServer::Domain(SmolStr::new("sip.example.com".to_owned())),
/// ]);
/// let dns = SipResolver::from_system().unwrap();
/// let resolver = DhcpResolver::new(dhcp, dns);
///
/// let uri = SipUri::parse("sip:user@example.com").unwrap();
/// let targets = resolver.resolve(&uri).await?;
/// # Ok(())
/// # }
/// ```
pub struct DhcpResolver<D: DhcpProvider, R: Resolver> {
    dhcp_provider: D,
    dns_resolver: R,
}

impl<D: DhcpProvider, R: Resolver> DhcpResolver<D, R> {
    /// Creates a new DHCP resolver with the given DHCP provider and DNS resolver.
    ///
    /// The DNS resolver is used to resolve domain names returned by DHCP.
    pub fn new(dhcp_provider: D, dns_resolver: R) -> Self {
        Self {
            dhcp_provider,
            dns_resolver,
        }
    }

    /// Resolves SIP servers from DHCP, falling back to DNS for domain names.
    async fn resolve_internal(&self, uri: &SipUri) -> Result<Vec<DnsTarget>> {
        // Query DHCP for SIP servers
        let servers = self.dhcp_provider.query_sip_servers().await?;

        let Some(servers) = servers else {
            return Err(anyhow!("No DHCP Option 120 available"));
        };

        if servers.is_empty() {
            return Err(anyhow!("DHCP Option 120 contains no servers"));
        }

        let mut all_targets = Vec::new();

        // Process each DHCP server in preference order
        for server in servers {
            match server {
                DhcpSipServer::Ipv4(addr) => {
                    // Use IPv4 address directly
                    let port = if uri.sips { 5061 } else { 5060 };
                    let transport = SipResolver::default_transport(uri);
                    all_targets.push(DnsTarget::new(addr.to_string(), port, transport));
                }
                DhcpSipServer::Domain(domain) => {
                    // Create a temporary URI with the DHCP domain for DNS resolution
                    let mut temp_uri = uri.clone();
                    temp_uri.host = domain.clone();
                    temp_uri.port = None; // Let DNS resolver determine the port

                    // Resolve the domain via DNS (RFC 3263)
                    if let Ok(targets) = self.dns_resolver.resolve(&temp_uri).await {
                        all_targets.extend(targets);
                    }
                }
            }
        }

        if all_targets.is_empty() {
            Err(anyhow!("No targets resolved from DHCP servers"))
        } else {
            Ok(all_targets)
        }
    }
}

#[async_trait::async_trait]
impl<D: DhcpProvider, R: Resolver> Resolver for DhcpResolver<D, R> {
    async fn resolve(&self, uri: &SipUri) -> Result<Vec<DnsTarget>> {
        self.resolve_internal(uri).await
    }
}

/// Hybrid resolver that tries DHCP first, then falls back to DNS (RFC 3263 + RFC 3361).
///
/// This is the recommended resolver for production use, as it implements the
/// complete SIP server discovery mechanism:
/// 1. Query DHCP Option 120
/// 2. If DHCP unavailable or fails, use DNS (NAPTR → SRV → A/AAAA)
///
/// # Example
///
/// ```no_run
/// use sip_dns::{HybridResolver, StaticDhcpProvider, SipResolver, Resolver};
/// use sip_core::SipUri;
///
/// # async fn example() -> anyhow::Result<()> {
/// let dhcp = StaticDhcpProvider::empty(); // No DHCP in this example
/// let dns = SipResolver::from_system().unwrap();
/// let resolver = HybridResolver::new(dhcp, dns);
///
/// let uri = SipUri::parse("sip:user@example.com").unwrap();
/// // Will try DHCP first, then fall back to DNS
/// let targets = resolver.resolve(&uri).await?;
/// # Ok(())
/// # }
/// ```
pub struct HybridResolver<D: DhcpProvider, R: Resolver> {
    dhcp_provider: D,
    dns_resolver: R,
}

impl<D: DhcpProvider, R: Resolver> HybridResolver<D, R> {
    /// Creates a new hybrid resolver.
    pub fn new(dhcp_provider: D, dns_resolver: R) -> Self {
        Self {
            dhcp_provider,
            dns_resolver,
        }
    }
}

#[async_trait::async_trait]
impl<D: DhcpProvider, R: Resolver> Resolver for HybridResolver<D, R> {
    async fn resolve(&self, uri: &SipUri) -> Result<Vec<DnsTarget>> {
        // Try DHCP first
        let dhcp_servers = self.dhcp_provider.query_sip_servers().await.ok().flatten();

        if let Some(servers) = dhcp_servers {
            if !servers.is_empty() {
                // Process DHCP servers
                let mut all_targets = Vec::new();

                for server in servers {
                    match server {
                        DhcpSipServer::Ipv4(addr) => {
                            let port = if uri.sips { 5061 } else { 5060 };
                            let transport = SipResolver::default_transport(uri);
                            all_targets.push(DnsTarget::new(addr.to_string(), port, transport));
                        }
                        DhcpSipServer::Domain(domain) => {
                            let mut temp_uri = uri.clone();
                            temp_uri.host = domain.clone();
                            temp_uri.port = None;

                            if let Ok(targets) = self.dns_resolver.resolve(&temp_uri).await {
                                all_targets.extend(targets);
                            }
                        }
                    }
                }

                if !all_targets.is_empty() {
                    return Ok(all_targets);
                }
            }
        }

        // Fallback to DNS (RFC 3263)
        self.dns_resolver.resolve(uri).await
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

    // ========================================================================
    // DHCP Options Tests: Option 66, Option 150, Option 120
    // ========================================================================

    // Option 66 Tests
    #[test]
    fn parse_dhcp_option_66_hostname() {
        let data = b"tftp.example.com";
        let server = parse_dhcp_option_66(data).unwrap();
        assert_eq!(server.as_str(), "tftp.example.com");
    }

    #[test]
    fn parse_dhcp_option_66_ip_address() {
        let data = b"192.168.1.1";
        let server = parse_dhcp_option_66(data).unwrap();
        assert_eq!(server.as_str(), "192.168.1.1");
    }

    #[test]
    fn parse_dhcp_option_66_fqdn() {
        let data = b"tftp-server.voice.example.com";
        let server = parse_dhcp_option_66(data).unwrap();
        assert_eq!(server.as_str(), "tftp-server.voice.example.com");
    }

    #[test]
    fn parse_dhcp_option_66_empty() {
        let data = b"";
        let result = parse_dhcp_option_66(data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_dhcp_option_66_with_whitespace() {
        let data = b"  tftp.example.com  ";
        let server = parse_dhcp_option_66(data).unwrap();
        assert_eq!(server.as_str(), "  tftp.example.com  ");
    }

    // Option 150 Tests
    #[test]
    fn parse_dhcp_option_150_single_address() {
        let data = vec![192, 168, 1, 1];
        let servers = parse_dhcp_option_150(&data).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn parse_dhcp_option_150_multiple_addresses() {
        let data = vec![192, 168, 1, 1, 10, 0, 0, 1, 172, 16, 0, 1];
        let servers = parse_dhcp_option_150(&data).unwrap();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0].to_string(), "192.168.1.1");
        assert_eq!(servers[1].to_string(), "10.0.0.1");
        assert_eq!(servers[2].to_string(), "172.16.0.1");
    }

    #[test]
    fn parse_dhcp_option_150_invalid_length() {
        let data = vec![192, 168, 1]; // Only 3 bytes
        let result = parse_dhcp_option_150(&data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_dhcp_option_150_empty() {
        let data = vec![];
        let result = parse_dhcp_option_150(&data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_dhcp_option_150_eight_addresses() {
        let data = vec![
            192, 168, 1, 1, 192, 168, 1, 2, 192, 168, 1, 3, 192, 168, 1, 4, 10, 0, 0, 1, 10, 0,
            0, 2, 172, 16, 0, 1, 172, 16, 0, 2,
        ];
        let servers = parse_dhcp_option_150(&data).unwrap();
        assert_eq!(servers.len(), 8);
    }

    // Static DHCP Provider with TFTP options
    #[test]
    fn static_dhcp_provider_with_tftp_name() {
        let provider = StaticDhcpProvider::empty()
            .with_tftp_name(TftpServerName(SmolStr::new("tftp.example.com".to_owned())));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let tftp_name = rt.block_on(provider.query_tftp_server_name()).unwrap();

        assert!(tftp_name.is_some());
        assert_eq!(tftp_name.unwrap().as_str(), "tftp.example.com");
    }

    #[test]
    fn static_dhcp_provider_with_tftp_addresses() {
        let addresses = vec!["192.168.1.1".parse().unwrap(), "10.0.0.1".parse().unwrap()];
        let provider = StaticDhcpProvider::empty().with_tftp_addresses(addresses.clone());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let tftp_addrs = rt
            .block_on(provider.query_tftp_server_addresses())
            .unwrap();

        assert!(tftp_addrs.is_some());
        let addrs = tftp_addrs.unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].to_string(), "192.168.1.1");
        assert_eq!(addrs[1].to_string(), "10.0.0.1");
    }

    #[test]
    fn static_dhcp_provider_with_all_options() {
        let provider = StaticDhcpProvider::new(vec![DhcpSipServer::Ipv4(
            "192.168.1.100".parse().unwrap(),
        )])
        .with_tftp_name(TftpServerName(SmolStr::new("tftp.example.com".to_owned())))
        .with_tftp_addresses(vec!["10.0.0.1".parse().unwrap()]);

        let rt = tokio::runtime::Runtime::new().unwrap();

        let sip = rt.block_on(provider.query_sip_servers()).unwrap();
        assert!(sip.is_some());

        let tftp_name = rt.block_on(provider.query_tftp_server_name()).unwrap();
        assert!(tftp_name.is_some());

        let tftp_addrs = rt
            .block_on(provider.query_tftp_server_addresses())
            .unwrap();
        assert!(tftp_addrs.is_some());
    }

    // Option 120 Tests
    #[test]
    fn parse_dhcp_option_120_ipv4_single() {
        let data = vec![1, 192, 168, 1, 1];
        let servers = parse_dhcp_option_120(&data).unwrap();
        assert_eq!(servers.len(), 1);
        match &servers[0] {
            DhcpSipServer::Ipv4(addr) => assert_eq!(addr.to_string(), "192.168.1.1"),
            _ => panic!("Expected IPv4"),
        }
    }

    #[test]
    fn parse_dhcp_option_120_ipv4_multiple() {
        let data = vec![1, 192, 168, 1, 1, 10, 0, 0, 1, 172, 16, 0, 1];
        let servers = parse_dhcp_option_120(&data).unwrap();
        assert_eq!(servers.len(), 3);
        match &servers[0] {
            DhcpSipServer::Ipv4(addr) => assert_eq!(addr.to_string(), "192.168.1.1"),
            _ => panic!("Expected IPv4"),
        }
        match &servers[1] {
            DhcpSipServer::Ipv4(addr) => assert_eq!(addr.to_string(), "10.0.0.1"),
            _ => panic!("Expected IPv4"),
        }
        match &servers[2] {
            DhcpSipServer::Ipv4(addr) => assert_eq!(addr.to_string(), "172.16.0.1"),
            _ => panic!("Expected IPv4"),
        }
    }

    #[test]
    fn parse_dhcp_option_120_ipv4_invalid_length() {
        let data = vec![1, 192, 168, 1]; // Only 3 bytes instead of 4
        let result = parse_dhcp_option_120(&data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_dhcp_option_120_domain_single() {
        // "example.com" encoded: 7 "example" 3 "com" 0
        let data = vec![
            0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let servers = parse_dhcp_option_120(&data).unwrap();
        assert_eq!(servers.len(), 1);
        match &servers[0] {
            DhcpSipServer::Domain(name) => assert_eq!(name.as_str(), "example.com"),
            _ => panic!("Expected Domain"),
        }
    }

    #[test]
    fn parse_dhcp_option_120_domain_multiple() {
        // "sip.example.com" and "backup.example.net"
        let data = vec![
            0, 3, b's', b'i', b'p', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0, 6, b'b', b'a', b'c', b'k', b'u', b'p', 7, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 3, b'n', b'e', b't', 0,
        ];
        let servers = parse_dhcp_option_120(&data).unwrap();
        assert_eq!(servers.len(), 2);
        match &servers[0] {
            DhcpSipServer::Domain(name) => assert_eq!(name.as_str(), "sip.example.com"),
            _ => panic!("Expected Domain"),
        }
        match &servers[1] {
            DhcpSipServer::Domain(name) => assert_eq!(name.as_str(), "backup.example.net"),
            _ => panic!("Expected Domain"),
        }
    }

    #[test]
    fn parse_dhcp_option_120_domain_invalid_length() {
        // Label length exceeds available data
        let data = vec![0, 10, b'a', b'b', b'c']; // Says 10 bytes but only 3 available
        let result = parse_dhcp_option_120(&data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_dhcp_option_120_empty() {
        let data = vec![];
        let result = parse_dhcp_option_120(&data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_dhcp_option_120_invalid_encoding() {
        let data = vec![2, 192, 168, 1, 1]; // Encoding 2 is invalid
        let result = parse_dhcp_option_120(&data);
        assert!(result.is_err());
    }

    #[test]
    fn static_dhcp_provider_returns_servers() {
        let servers = vec![
            DhcpSipServer::Domain(SmolStr::new("sip.example.com".to_owned())),
            DhcpSipServer::Ipv4("192.168.1.1".parse().unwrap()),
        ];
        let provider = StaticDhcpProvider::new(servers.clone());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(provider.query_sip_servers()).unwrap();

        assert!(result.is_some());
        let returned = result.unwrap();
        assert_eq!(returned.len(), 2);
    }

    #[test]
    fn static_dhcp_provider_empty() {
        let provider = StaticDhcpProvider::empty();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(provider.query_sip_servers()).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn dhcp_resolver_with_ipv4() {
        let dhcp = StaticDhcpProvider::new(vec![DhcpSipServer::Ipv4(
            "192.168.1.100".parse().unwrap(),
        )]);
        let dns = StaticResolver::single("fallback.example.com", 5060, Transport::Udp);
        let resolver = DhcpResolver::new(dhcp, dns);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:user@example.com").unwrap();
        let targets = rt.block_on(resolver.resolve(&uri)).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host.as_str(), "192.168.1.100");
        assert_eq!(targets[0].port, 5060);
    }

    #[test]
    fn dhcp_resolver_with_domain() {
        let dhcp = StaticDhcpProvider::new(vec![DhcpSipServer::Domain(SmolStr::new(
            "dhcp-sip.example.com".to_owned(),
        ))]);
        let dns = StaticResolver::single("dhcp-sip.example.com", 5060, Transport::Tcp);
        let resolver = DhcpResolver::new(dhcp, dns);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:user@example.com").unwrap();
        let targets = rt.block_on(resolver.resolve(&uri)).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host.as_str(), "dhcp-sip.example.com");
        assert_eq!(targets[0].port, 5060);
        assert_eq!(targets[0].transport, Transport::Tcp);
    }

    #[test]
    fn dhcp_resolver_fails_when_no_option_120() {
        let dhcp = StaticDhcpProvider::empty();
        let dns = StaticResolver::single("fallback.example.com", 5060, Transport::Udp);
        let resolver = DhcpResolver::new(dhcp, dns);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:user@example.com").unwrap();
        let result = rt.block_on(resolver.resolve(&uri));

        assert!(result.is_err());
    }

    #[test]
    fn hybrid_resolver_uses_dhcp_when_available() {
        let dhcp = StaticDhcpProvider::new(vec![DhcpSipServer::Ipv4(
            "192.168.1.100".parse().unwrap(),
        )]);
        let dns = StaticResolver::single("dns-fallback.example.com", 5060, Transport::Udp);
        let resolver = HybridResolver::new(dhcp, dns);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:user@example.com").unwrap();
        let targets = rt.block_on(resolver.resolve(&uri)).unwrap();

        // Should use DHCP, not DNS fallback
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host.as_str(), "192.168.1.100");
    }

    #[test]
    fn hybrid_resolver_falls_back_to_dns() {
        let dhcp = StaticDhcpProvider::empty();
        let dns = StaticResolver::single("dns-fallback.example.com", 5060, Transport::Udp);
        let resolver = HybridResolver::new(dhcp, dns);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:user@example.com").unwrap();
        let targets = rt.block_on(resolver.resolve(&uri)).unwrap();

        // Should use DNS fallback
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host.as_str(), "dns-fallback.example.com");
    }

    #[test]
    fn hybrid_resolver_prefers_dhcp_over_dns() {
        let dhcp = StaticDhcpProvider::new(vec![
            DhcpSipServer::Ipv4("192.168.1.100".parse().unwrap()),
            DhcpSipServer::Domain(SmolStr::new("dhcp.example.com".to_owned())),
        ]);
        // StaticResolver returns all configured targets, so this simulates
        // DNS resolution returning both the DHCP domain and fallback
        let dns = StaticResolver::new(vec![
            DnsTarget::new("dhcp.example.com", 5060, Transport::Tcp),
            DnsTarget::new("dns-fallback.example.com", 5060, Transport::Udp),
        ]);
        let resolver = HybridResolver::new(dhcp, dns);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let uri = SipUri::parse("sip:user@example.com").unwrap();
        let targets = rt.block_on(resolver.resolve(&uri)).unwrap();

        // Should return DHCP IPv4 + resolved targets from DHCP domain
        // StaticResolver returns both configured targets
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].host.as_str(), "192.168.1.100");
        // Remaining targets come from DNS resolution
        assert!(targets.iter().any(|t| t.host.as_str() == "dhcp.example.com"));
        assert!(targets.iter().any(|t| t.host.as_str() == "dns-fallback.example.com"));
    }

    #[test]
    fn dhcp_sip_server_as_str() {
        let domain = DhcpSipServer::Domain(SmolStr::new("example.com".to_owned()));
        assert_eq!(domain.as_str(), "example.com");

        let ipv4 = DhcpSipServer::Ipv4("192.168.1.1".parse().unwrap());
        assert_eq!(ipv4.as_str(), "192.168.1.1");
    }
}
