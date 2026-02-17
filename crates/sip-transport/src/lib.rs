// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Async SIP transport layer for UDP, TCP, TLS, and WebSocket.
//!
//! Provides connection pooling, message framing, and automatic protocol handling
//! with observability integration.
//!
//! # Example
//! ```no_run
//! use sip_transport::{run_udp, InboundPacket};
//! use tokio::sync::mpsc;
//! use tokio::net::UdpSocket;
//! use std::sync::Arc;
//! # async fn example() -> anyhow::Result<()> {
//! let socket = Arc::new(UdpSocket::bind("0.0.0.0:5060").await?);
//! let (tx, mut rx) = mpsc::channel::<InboundPacket>(100);
//! tokio::spawn(run_udp(socket, tx));
//! while let Some(packet) = rx.recv().await {
//!     // Process inbound SIP messages
//! }
//! # Ok(())
//! # }
//! ```

use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use sip_observe::{span_with_transport, transport_metrics, OpLabel, StageLabel, TransportLabel};
pub mod pool;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
#[cfg(feature = "ws")]
use {
    futures_util::{SinkExt, StreamExt},
    tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::{self, handshake::server::Request},
    },
};

/// Maximum size of SIP headers before \r\n\r\n (64 KB).
/// Typical SIP messages have ~2-4 KB of headers. This limit protects against
/// unbounded header growth from malicious peers that never send \r\n\r\n.
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Maximum size of SIP message body based on Content-Length (10 MB).
/// Typical SIP bodies (SDP) are ~1-2 KB. Some scenarios (multipart MIME,
/// large presence documents) may need more, but 10 MB is a reasonable limit
/// to prevent memory exhaustion attacks via huge Content-Length values.
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Maximum total buffer size before we stop reading from peer (16 MB).
/// Protects against accumulation of multiple large messages in buffer.
pub(crate) const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of concurrent inbound sessions per listener.
const MAX_CONCURRENT_SESSIONS: usize = 1024;

/// Maximum idle time (no data received) before closing a TCP/TLS session.
/// Protects against Slowloris-style attacks where a client holds a session
/// slot by sending data very slowly or not at all.
const SESSION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Timeout for outbound TCP/TLS connection establishment.
/// Prevents indefinite blocking when a peer is unreachable or firewalled.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum number of concurrent sessions allowed from a single IP address.
/// Prevents a single source from exhausting the global session limit.
const MAX_SESSIONS_PER_IP: usize = 64;

/// Indicates which transport carried an inbound or outbound message.
///
/// # SCTP Support (RFC 4168)
///
/// SCTP and TLS-SCTP variants are included for protocol completeness per RFC 4168,
/// but actual SCTP socket implementations (run_sctp/send_sctp) are not provided.
/// SCTP requires kernel support and is not universally available across platforms.
///
/// Applications requiring SCTP transport should implement custom handlers using
/// crates like `sctp-rs` or `tokio-sctp` and integrate with the packet routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Udp,
    Tcp,
    Tls,
    /// SCTP transport (RFC 4168)
    Sctp,
    /// TLS over SCTP transport (RFC 4168)
    TlsSctp,
    /// WebSocket transport (RFC 7118)
    Ws,
    /// Secure WebSocket transport (RFC 7118)
    Wss,
}

impl TransportKind {
    /// Returns the lowercase transport string for metrics and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::Udp => "udp",
            TransportKind::Tcp => "tcp",
            TransportKind::Tls => "tls",
            TransportKind::Sctp => "sctp",
            TransportKind::TlsSctp => "tls-sctp",
            TransportKind::Ws => "ws",
            TransportKind::Wss => "wss",
        }
    }

    /// Returns the Via header transport parameter value per RFC 3261 and RFC 4168.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_transport::TransportKind;
    ///
    /// assert_eq!(TransportKind::Udp.via_transport(), "UDP");
    /// assert_eq!(TransportKind::Tcp.via_transport(), "TCP");
    /// assert_eq!(TransportKind::Tls.via_transport(), "TLS");
    /// assert_eq!(TransportKind::Sctp.via_transport(), "SCTP");
    /// assert_eq!(TransportKind::TlsSctp.via_transport(), "TLS-SCTP");
    /// ```
    pub fn via_transport(&self) -> &'static str {
        match self {
            TransportKind::Udp => "UDP",
            TransportKind::Tcp => "TCP",
            TransportKind::Tls => "TLS",
            TransportKind::Sctp => "SCTP",
            TransportKind::TlsSctp => "TLS-SCTP",
            TransportKind::Ws => "WS",
            TransportKind::Wss => "WSS",
        }
    }

    /// Parses a transport string (case-insensitive) into a TransportKind.
    ///
    /// Accepts strings from Via headers or URI transport parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_transport::TransportKind;
    ///
    /// assert_eq!(TransportKind::parse("UDP"), Some(TransportKind::Udp));
    /// assert_eq!(TransportKind::parse("tcp"), Some(TransportKind::Tcp));
    /// assert_eq!(TransportKind::parse("TLS"), Some(TransportKind::Tls));
    /// assert_eq!(TransportKind::parse("SCTP"), Some(TransportKind::Sctp));
    /// assert_eq!(TransportKind::parse("tls-sctp"), Some(TransportKind::TlsSctp));
    /// assert_eq!(TransportKind::parse("invalid"), None);
    /// ```
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" => Some(TransportKind::Udp),
            "tcp" => Some(TransportKind::Tcp),
            "tls" => Some(TransportKind::Tls),
            "sctp" => Some(TransportKind::Sctp),
            "tls-sctp" => Some(TransportKind::TlsSctp),
            "ws" => Some(TransportKind::Ws),
            "wss" => Some(TransportKind::Wss),
            _ => None,
        }
    }

    /// Returns true if this transport requires a persistent connection (TCP, TLS, SCTP, TLS-SCTP).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_transport::TransportKind;
    ///
    /// assert!(!TransportKind::Udp.is_stream_based());
    /// assert!(TransportKind::Tcp.is_stream_based());
    /// assert!(TransportKind::Tls.is_stream_based());
    /// assert!(TransportKind::Sctp.is_stream_based());
    /// assert!(TransportKind::TlsSctp.is_stream_based());
    /// ```
    pub fn is_stream_based(&self) -> bool {
        matches!(
            self,
            TransportKind::Tcp
                | TransportKind::Tls
                | TransportKind::Sctp
                | TransportKind::TlsSctp
                | TransportKind::Ws
                | TransportKind::Wss
        )
    }

    /// Returns true if this transport uses TLS encryption.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_transport::TransportKind;
    ///
    /// assert!(!TransportKind::Udp.is_secure());
    /// assert!(!TransportKind::Tcp.is_secure());
    /// assert!(TransportKind::Tls.is_secure());
    /// assert!(!TransportKind::Sctp.is_secure());
    /// assert!(TransportKind::TlsSctp.is_secure());
    /// ```
    pub fn is_secure(&self) -> bool {
        matches!(
            self,
            TransportKind::Tls | TransportKind::TlsSctp | TransportKind::Wss
        )
    }
}

impl From<TransportKind> for TransportLabel {
    fn from(value: TransportKind) -> Self {
        match value {
            TransportKind::Udp => Self::Udp,
            TransportKind::Tcp => Self::Tcp,
            TransportKind::Tls => Self::Tls,
            TransportKind::Sctp => Self::Sctp,
            TransportKind::TlsSctp => Self::TlsSctp,
            TransportKind::Ws => Self::Ws,
            TransportKind::Wss => Self::Wss,
        }
    }
}

/// Bundle representing a packet received by a transport listener.
/// Fields are private to protect transport metadata.
#[derive(Debug, Clone)]
pub struct InboundPacket {
    transport: TransportKind,
    peer: SocketAddr,
    payload: Bytes,
    stream: Option<mpsc::Sender<Bytes>>,
}

impl InboundPacket {
    /// Creates a new inbound packet.
    pub fn new(
        transport: TransportKind,
        peer: SocketAddr,
        payload: Bytes,
        stream: Option<mpsc::Sender<Bytes>>,
    ) -> Self {
        Self {
            transport,
            peer,
            payload,
            stream,
        }
    }

    /// Returns the transport kind.
    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    /// Returns the peer socket address.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the payload bytes.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Returns the stream sender if available.
    pub fn stream(&self) -> Option<&mpsc::Sender<Bytes>> {
        self.stream.as_ref()
    }

    /// Consumes the packet and returns the payload.
    pub fn into_payload(self) -> Bytes {
        self.payload
    }

    /// Consumes the packet and returns all components.
    pub fn into_parts(
        self,
    ) -> (
        TransportKind,
        SocketAddr,
        Bytes,
        Option<mpsc::Sender<Bytes>>,
    ) {
        (self.transport, self.peer, self.payload, self.stream)
    }
}

/// Runs a UDP receive loop and forwards packets to the provided channel.
pub async fn run_udp(socket: Arc<UdpSocket>, tx: mpsc::Sender<InboundPacket>) -> Result<()> {
    let bind = socket.local_addr()?;
    info!(%bind, "listening (udp)");
    transport_metrics().on_accept(TransportLabel::Udp);
    let mut buf = vec![0u8; 65_535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                transport_metrics().on_latency(TransportLabel::Udp, OpLabel::Recv, 0);
                let span = span_with_transport("udp_packet", TransportLabel::Udp);
                let _entered = span.enter();
                let payload = Bytes::copy_from_slice(&buf[..n]);
                if n == buf.len() {
                    transport_metrics().on_error(TransportLabel::Udp, StageLabel::Truncate);
                    error!(
                        %peer,
                        max = n,
                        "udp datagram likely truncated (buffer full); consider TCP"
                    );
                }
                transport_metrics().on_packet_received(TransportLabel::Udp);
                let packet = InboundPacket {
                    transport: TransportKind::Udp,
                    peer,
                    payload,
                    stream: None,
                };
                if tx.send(packet).await.is_err() {
                    error!("receiver dropped; shutting down udp loop");
                    transport_metrics().on_error(TransportLabel::Udp, StageLabel::Dispatch);
                    break;
                }
            }
            Err(e) => {
                error!(%e, "udp recv_from error");
                transport_metrics().on_error(TransportLabel::Udp, StageLabel::Recv);
            }
        }
    }
    Ok(())
}

/// Sends a UDP datagram using an existing bound socket.
pub async fn send_udp(socket: &UdpSocket, to: &std::net::SocketAddr, data: &[u8]) -> Result<()> {
    socket.send_to(data, to).await?;
    transport_metrics().on_packet_sent(TransportLabel::Udp);
    Ok(())
}

/// Accepts TCP connections, streaming frames to the supplied channel.
pub async fn run_tcp(bind: &str, tx: mpsc::Sender<InboundPacket>) -> Result<()> {
    let bind_addr: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow!("Invalid bind address: {}", e))?;

    let listener = {
        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(
            Domain::for_address(bind_addr),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        socket.listen(128)?;

        let std_listener: std::net::TcpListener = socket.into();
        TcpListener::from_std(std_listener)?
    };
    info!(%bind, "listening (tcp)");
    transport_metrics().on_accept(TransportLabel::Tcp);
    let limiter = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSIONS));
    let per_ip: Arc<dashmap::DashMap<std::net::IpAddr, usize>> = Arc::new(dashmap::DashMap::new());

    loop {
        let start = Instant::now();
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!(%e, "tcp accept error");
                transport_metrics().on_error(TransportLabel::Tcp, StageLabel::Accept);
                continue;
            }
        };
        transport_metrics().on_latency(
            TransportLabel::Tcp,
            OpLabel::Accept,
            start.elapsed().as_nanos() as u64,
        );

        // Per-IP session limit check
        let ip = peer.ip();
        {
            let mut ip_count = per_ip.entry(ip).or_insert(0);
            if *ip_count >= MAX_SESSIONS_PER_IP {
                warn!(%peer, count = *ip_count, "per-IP tcp session limit reached; dropping connection");
                transport_metrics().on_error(TransportLabel::Tcp, StageLabel::SessionLimit);
                continue;
            }
            *ip_count += 1;
        }

        let permit = match limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Undo per-IP increment
                if let Some(mut count) = per_ip.get_mut(&ip) {
                    *count = count.saturating_sub(1);
                }
                warn!(%peer, "tcp session limit reached; dropping connection");
                transport_metrics().on_error(TransportLabel::Tcp, StageLabel::SessionLimit);
                continue;
            }
        };
        let tx = tx.clone();
        let per_ip_clone = per_ip.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let span = span_with_transport("tcp_session", TransportLabel::Tcp);
            let _entered = span.enter();
            spawn_stream_session(
                peer,
                stream,
                TransportKind::Tcp,
                tx,
                "tcp read error",
                "tcp write error",
            )
            .await;
            // Decrement per-IP counter when session ends
            if let Some(mut count) = per_ip_clone.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    drop(count);
                    per_ip_clone.remove(&ip);
                }
            }
        });
    }
}

/// Connects to the destination and writes the bytes over TCP.
pub async fn send_tcp(to: &SocketAddr, data: &[u8]) -> Result<()> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(to))
        .await
        .map_err(|_| anyhow!("TCP connect timeout after {:?} to {}", CONNECT_TIMEOUT, to))?
        ?;
    transport_metrics().on_connect(TransportLabel::Tcp);
    stream.write_all(data).await?;
    transport_metrics().on_packet_sent(TransportLabel::Tcp);
    Ok(())
}

/// Sends buffered bytes via a per-connection writer channel.
pub async fn send_stream(
    transport: TransportKind,
    writer: &mpsc::Sender<Bytes>,
    data: Bytes,
) -> Result<()> {
    writer
        .send(data)
        .await
        .map_err(|_| anyhow!("connection writer dropped"))?;
    transport_metrics().on_packet_sent(transport.into());
    Ok(())
}

#[cfg(feature = "tls")]
/// TLS client configuration used for outbound SIPS traffic.
/// Fields are private to protect TLS configuration.
pub struct TlsConfig {
    server_name: String,
    client_config: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    /// Creates a new TLS configuration.
    pub fn new(
        server_name: String,
        client_config: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> Self {
        Self {
            server_name,
            client_config,
        }
    }

    /// Returns the server name.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns the client configuration.
    pub fn client_config(&self) -> &std::sync::Arc<tokio_rustls::rustls::ClientConfig> {
        &self.client_config
    }
}

#[cfg(feature = "ws")]
/// Sends bytes over a WebSocket (plaintext).
pub async fn send_ws(url: &str, data: Bytes) -> Result<()> {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::header::HeaderValue};

    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
    let (mut stream, response) = tokio_tungstenite::connect_async(request).await?;
    ensure_ws_subprotocol(&response)?;
    transport_metrics().on_connect(TransportLabel::Ws);
    stream
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            data.to_vec(),
        ))
        .await?;
    transport_metrics().on_packet_sent(TransportLabel::Ws);
    Ok(())
}

#[cfg(feature = "ws")]
/// Sends bytes over a secure WebSocket (WSS).
pub async fn send_wss(url: &str, data: Bytes) -> Result<()> {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::header::HeaderValue};

    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
    let (mut stream, response) = tokio_tungstenite::connect_async(request).await?;
    ensure_ws_subprotocol(&response)?;
    transport_metrics().on_connect(TransportLabel::Wss);
    stream
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            data.to_vec(),
        ))
        .await?;
    transport_metrics().on_packet_sent(TransportLabel::Wss);
    Ok(())
}

#[cfg(feature = "ws")]
async fn handle_ws_connection<S>(
    peer: SocketAddr,
    stream: S,
    transport: TransportKind,
    tx: mpsc::Sender<InboundPacket>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // RFC 7118 requires the "sip" subprotocol; reject peers that do not offer it.
    let mut selected_sip = false;
    let ws_stream = accept_hdr_async(
        stream,
        |req: &Request, mut resp: tungstenite::handshake::server::Response| {
            if let Some(value) = req.headers().get("Sec-WebSocket-Protocol") {
                if let Ok(proto_str) = value.to_str() {
                    if proto_str
                        .split(',')
                        .any(|p| p.trim().eq_ignore_ascii_case("sip"))
                    {
                        // Safety: "sip" is a valid HeaderValue
                        if let Ok(header_value) = "sip".parse() {
                            resp.headers_mut()
                                .append("Sec-WebSocket-Protocol", header_value);
                            selected_sip = true;
                        }
                    }
                }
            }
            if !selected_sip {
                return Err(ws_subprotocol_error_response());
            }
            Ok(resp)
        },
    )
    .await?;

    let (mut sink, mut stream) = ws_stream.split();
    let (writer_tx, mut writer_rx) = mpsc::channel::<Bytes>(64);

    loop {
        tokio::select! {
            outbound = writer_rx.recv() => {
                if let Some(data) = outbound {
                    if let Err(e) = sink.send(tungstenite::Message::Binary(data.to_vec())).await {
                        warn!(%peer, %e, "websocket send error");
                        break;
                    }
                    transport_metrics().on_packet_sent(transport.into());
                } else {
                    break;
                }
            }
            inbound = stream.next() => {
                match inbound {
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        transport_metrics().on_packet_received(transport.into());
                        let packet = InboundPacket {
                            transport,
                            peer,
                            payload: Bytes::from(data),
                            stream: Some(writer_tx.clone()),
                        };
                        if tx.send(packet).await.is_err() {
                            warn!(%peer, "websocket receiver dropped");
                            break;
                        }
                    }
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        transport_metrics().on_packet_received(transport.into());
                        let packet = InboundPacket {
                            transport,
                            peer,
                            payload: Bytes::from(text.into_bytes()),
                            stream: Some(writer_tx.clone()),
                        };
                        if tx.send(packet).await.is_err() {
                            warn!(%peer, "websocket receiver dropped");
                            break;
                        }
                    }
                    Some(Ok(tungstenite::Message::Ping(payload))) => {
                        if let Err(e) = sink.send(tungstenite::Message::Pong(payload)).await {
                            warn!(%peer, %e, "failed to send ws pong");
                            break;
                        }
                    }
                    Some(Ok(tungstenite::Message::Pong(_))) => {}
                    Some(Ok(tungstenite::Message::Close(_))) => break,
                    Some(Ok(tungstenite::Message::Frame(_))) => {}
                    Some(Err(e)) => {
                        warn!(%peer, %e, "websocket read error");
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "ws")]
/// Runs a WebSocket listener and forwards SIP-over-WS packets to the channel.
pub async fn run_ws(bind: &str, tx: mpsc::Sender<InboundPacket>) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "listening (ws)");
    transport_metrics().on_accept(TransportLabel::Ws);
    let limiter = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(%e, "ws accept error");
                continue;
            }
        };

        let permit = match limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(%peer, "ws session limit reached; dropping connection");
                transport_metrics().on_error(TransportLabel::Ws, StageLabel::SessionLimit);
                continue;
            }
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_ws_connection(peer, stream, TransportKind::Ws, tx).await {
                warn!(%peer, %e, "ws session ended with error");
            }
        });
    }
}

#[cfg(all(feature = "ws", feature = "tls"))]
/// Runs a secure WebSocket listener (WSS) and forwards SIP-over-WS packets.
pub async fn run_wss(
    bind: &str,
    config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    tx: mpsc::Sender<InboundPacket>,
) -> Result<()> {
    use tokio_rustls::TlsAcceptor;

    let listener = TcpListener::bind(bind).await?;
    let acceptor = TlsAcceptor::from(config);
    info!(%bind, "listening (wss)");
    transport_metrics().on_accept(TransportLabel::Wss);
    let limiter = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSIONS));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(%e, "wss accept error");
                continue;
            }
        };
        let permit = match limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(%peer, "wss session limit reached; dropping connection");
                transport_metrics().on_error(TransportLabel::Wss, StageLabel::SessionLimit);
                continue;
            }
        };
        let tx = tx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) =
                        handle_ws_connection(peer, tls_stream, TransportKind::Wss, tx).await
                    {
                        warn!(%peer, %e, "wss session ended with error");
                    }
                }
                Err(e) => warn!(%peer, %e, "wss tls accept failed"),
            }
        });
    }
}

#[cfg(feature = "tls")]
/// Sends bytes over a TLS connection using rustls.
pub async fn send_tls(to: &SocketAddr, data: &[u8], config: &TlsConfig) -> Result<()> {
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let connector = TlsConnector::from(config.client_config.clone());
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| anyhow!("invalid TLS server name"))?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(to))
        .await
        .map_err(|_| anyhow!("TLS connect timeout after {:?} to {}", CONNECT_TIMEOUT, to))?
        ?;
    let mut tls_stream = connector.connect(server_name, stream).await?;
    tls_stream.write_all(data).await?;
    transport_metrics().on_packet_sent(TransportLabel::Tls);
    Ok(())
}

#[cfg(feature = "tls")]
/// Runs a TLS listener, forwarding decrypted payloads to the supplied channel.
pub async fn run_tls(
    bind: &str,
    config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    tx: mpsc::Sender<InboundPacket>,
) -> Result<()> {
    use tokio_rustls::TlsAcceptor;

    let listener = TcpListener::bind(bind).await?;
    let acceptor = TlsAcceptor::from(config);
    info!(%bind, "listening (tls)");
    transport_metrics().on_accept(TransportLabel::Tls);
    let limiter = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSIONS));
    let per_ip: Arc<dashmap::DashMap<std::net::IpAddr, usize>> = Arc::new(dashmap::DashMap::new());

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!(%e, "tls accept error");
                transport_metrics().on_error(TransportLabel::Tls, StageLabel::Accept);
                continue;
            }
        };

        // Per-IP session limit check
        let ip = peer.ip();
        {
            let mut ip_count = per_ip.entry(ip).or_insert(0);
            if *ip_count >= MAX_SESSIONS_PER_IP {
                warn!(%peer, count = *ip_count, "per-IP tls session limit reached; dropping connection");
                transport_metrics().on_error(TransportLabel::Tls, StageLabel::SessionLimit);
                continue;
            }
            *ip_count += 1;
        }

        let permit = match limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Undo per-IP increment
                if let Some(mut count) = per_ip.get_mut(&ip) {
                    *count = count.saturating_sub(1);
                }
                warn!(%peer, "tls session limit reached; dropping connection");
                transport_metrics().on_error(TransportLabel::Tls, StageLabel::SessionLimit);
                continue;
            }
        };
        let tx = tx.clone();
        let acceptor = acceptor.clone();
        let per_ip_clone = per_ip.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let span = span_with_transport("tls_session", TransportLabel::Tls);
            let _entered = span.enter();
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!(%e, "tls handshake error");
                    transport_metrics().on_error(TransportLabel::Tls, StageLabel::Handshake);
                    // Decrement per-IP counter on early return
                    if let Some(mut count) = per_ip_clone.get_mut(&ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            drop(count);
                            per_ip_clone.remove(&ip);
                        }
                    }
                    return;
                }
            };
            transport_metrics().on_connect(TransportLabel::Tls);

            // Use TLS-specific session handler with proper shutdown support
            spawn_tls_session(peer, tls_stream, tx).await;
            // Decrement per-IP counter when session ends
            if let Some(mut count) = per_ip_clone.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    drop(count);
                    per_ip_clone.remove(&ip);
                }
            }
        });
    }
}

#[cfg(feature = "tls")]
/// Loads a rustls server config from PEM certificate and key files.
///
/// Uses `with_single_cert` which ignores SNI entirely. This is important for SIP
/// because clients often send IP addresses as SNI, which would be rejected by
/// SNI-aware configurations (per RFC 6066, SNI should be DNS names only).
pub fn load_rustls_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<std::sync::Arc<tokio_rustls::rustls::ServerConfig>> {
    use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer},
    };

    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs = certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| anyhow!("invalid certificate: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", cert_path));
    }

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let mut keys = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<PrivatePkcs8KeyDer<'static>>, _>>()
        .map_err(|e| anyhow!("invalid private key: {e}"))?
        .into_iter()
        .map(PrivateKeyDer::from)
        .collect::<Vec<_>>();
    if keys.is_empty() {
        let mut key_reader = BufReader::new(File::open(key_path)?);
        keys = rsa_private_keys(&mut key_reader)
            .collect::<Result<Vec<PrivatePkcs1KeyDer<'static>>, _>>()
            .map_err(|e| anyhow!("invalid private key: {e}"))?
            .into_iter()
            .map(PrivateKeyDer::from)
            .collect();
    }
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no private keys found in {}", key_path))?;

    let tls12_only = std::env::var("SIPHON_TLS12_ONLY")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
        .unwrap_or(false);

    let builder = if tls12_only {
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
    } else {
        rustls::ServerConfig::builder()
    };

    // Use with_single_cert which ignores SNI entirely (per rustls issue #130).
    // This is necessary for SIP clients that send IP addresses as SNI.
    let config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("failed to create TLS config: {e}"))?;

    Ok(std::sync::Arc::new(config))
}

/// Decides which transport to use for an outbound message.
pub trait TransportPolicy: Send + Sync {
    /// Returns the selected transport given a requested transport, payload size, and SIPS hint.
    fn choose(&self, requested: TransportKind, payload_len: usize, sips: bool) -> TransportKind;
}

/// Default policy that prefers TLS for SIPS and falls back to TCP when payloads exceed a UDP MTU.
/// Fields are private to protect transport policy configuration.
#[derive(Debug, Clone)]
pub struct DefaultTransportPolicy {
    udp_mtu: usize,
}

impl DefaultTransportPolicy {
    /// Creates a new transport policy with the specified UDP MTU.
    pub fn new(udp_mtu: usize) -> Self {
        Self { udp_mtu }
    }

    /// Returns the UDP MTU threshold.
    pub fn udp_mtu(&self) -> usize {
        self.udp_mtu
    }
}

impl Default for DefaultTransportPolicy {
    fn default() -> Self {
        Self { udp_mtu: 1300 }
    }
}

impl TransportPolicy for DefaultTransportPolicy {
    fn choose(&self, requested: TransportKind, payload_len: usize, sips: bool) -> TransportKind {
        if sips && !requested.is_secure() {
            return TransportKind::Tls;
        }
        if matches!(requested, TransportKind::Udp) && payload_len > self.udp_mtu {
            TransportKind::Tcp
        } else {
            requested
        }
    }
}

/// Handles a TLS session with proper shutdown support.
/// This function ensures TLS close_notify is sent when the connection closes.
#[cfg(feature = "tls")]
async fn spawn_tls_session(
    peer: SocketAddr,
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    tx: mpsc::Sender<InboundPacket>,
) {
    use tokio::io::AsyncWriteExt as _;

    // Split by ownership so we can reunite later for shutdown
    let (mut reader, writer) = tokio::io::split(tls_stream);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Bytes>(32);

    // Spawn writer task that returns the WriteHalf when done
    let writer_handle = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(buf) = writer_rx.recv().await {
            if let Err(e) = writer.write_all(&buf).await {
                error!(%e, "tls write error");
                transport_metrics().on_error(TransportLabel::Tls, StageLabel::Write);
                break;
            }
            transport_metrics().on_packet_sent(TransportLabel::Tls);
        }
        writer // Return the WriteHalf for reuniting
    });

    let mut buf = BytesMut::with_capacity(4096);
    loop {
        // Check if buffer has grown too large - protects against memory exhaustion
        if buf.len() >= MAX_BUFFER_SIZE {
            warn!(
                peer = %peer,
                buffer_size = buf.len(),
                "tls buffer exceeded MAX_BUFFER_SIZE, closing connection"
            );
            transport_metrics().on_error(TransportLabel::Tls, StageLabel::BufferOverflow);
            break;
        }

        // Apply idle timeout to prevent Slowloris-style DoS attacks.
        // If no data is received within SESSION_IDLE_TIMEOUT, close the connection.
        match tokio::time::timeout(SESSION_IDLE_TIMEOUT, reader.read_buf(&mut buf)).await {
            Ok(Ok(0)) => {
                info!(%peer, "tls connection closed by peer (EOF)");
                break;
            }
            Ok(Ok(n)) => {
                info!(%peer, bytes_read = n, buffer_len = buf.len(), "tls data received");
                transport_metrics().on_packet_received(TransportLabel::Tls);

                // Try to extract complete SIP messages
                match drain_sip_frames(&mut buf) {
                    Ok(frames) => {
                        for payload in frames {
                            let packet = InboundPacket {
                                transport: TransportKind::Tls,
                                peer,
                                payload,
                                stream: Some(writer_tx.clone()),
                            };
                            if tx.send(packet).await.is_err() {
                                error!("receiver dropped; shutting down tls session");
                                transport_metrics()
                                    .on_error(TransportLabel::Tls, StageLabel::Dispatch);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            peer = %peer,
                            error = %e,
                            "SIP framing error, closing tls connection"
                        );
                        transport_metrics().on_error(TransportLabel::Tls, StageLabel::FramingError);
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                error!(%e, "tls read error");
                transport_metrics().on_error(TransportLabel::Tls, StageLabel::Read);
                break;
            }
            Err(_) => {
                warn!(peer = %peer, timeout_secs = SESSION_IDLE_TIMEOUT.as_secs(),
                    "tls session idle timeout, closing connection");
                transport_metrics().on_error(TransportLabel::Tls, StageLabel::Read);
                break;
            }
        }
    }

    // Signal writer task to finish and get back the WriteHalf
    drop(writer_tx);
    match writer_handle.await {
        Ok(writer) => {
            // Reunite the stream halves
            let mut tls_stream = reader.unsplit(writer);

            // Perform proper TLS shutdown - send close_notify alert
            if let Err(e) = tls_stream.shutdown().await {
                // Don't log error if it's just "NotConnected" - peer may have already closed
                if e.kind() != std::io::ErrorKind::NotConnected {
                    warn!(%e, "tls shutdown error");
                }
            }
        }
        Err(e) => {
            error!(%e, "failed to join writer task, cannot perform tls shutdown");
        }
    }
}

async fn spawn_stream_session<S>(
    peer: SocketAddr,
    stream: S,
    transport: TransportKind,
    tx: mpsc::Sender<InboundPacket>,
    read_label: &'static str,
    write_label: &'static str,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Bytes>(32);

    let writer_handle = tokio::spawn(async move {
        while let Some(buf) = writer_rx.recv().await {
            if let Err(e) = writer.write_all(&buf).await {
                error!(%e, "{}", write_label);
                transport_metrics().on_error(transport.into(), StageLabel::Write);
                break;
            }
            transport_metrics().on_packet_sent(transport.into());
        }
    });

    let mut buf = BytesMut::with_capacity(4096);
    loop {
        // Check if buffer has grown too large - protects against memory exhaustion
        if buf.len() >= MAX_BUFFER_SIZE {
            warn!(
                peer = %peer,
                buffer_size = buf.len(),
                "stream buffer exceeded MAX_BUFFER_SIZE, closing connection"
            );
            transport_metrics().on_error(transport.into(), StageLabel::BufferOverflow);
            break;
        }

        // Apply idle timeout to prevent Slowloris-style DoS attacks.
        // If no data is received within SESSION_IDLE_TIMEOUT, close the connection.
        match tokio::time::timeout(SESSION_IDLE_TIMEOUT, reader.read_buf(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                transport_metrics().on_packet_received(transport.into());

                // Try to extract complete SIP messages
                match drain_sip_frames(&mut buf) {
                    Ok(frames) => {
                        for payload in frames {
                            let packet = InboundPacket {
                                transport,
                                peer,
                                payload,
                                stream: Some(writer_tx.clone()),
                            };
                            if tx.send(packet).await.is_err() {
                                error!("receiver dropped; shutting down {:?} session", transport);
                                transport_metrics()
                                    .on_error(transport.into(), StageLabel::Dispatch);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            peer = %peer,
                            error = %e,
                            "SIP framing error, closing connection"
                        );
                        transport_metrics().on_error(transport.into(), StageLabel::FramingError);
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                error!(%e, "{}", read_label);
                transport_metrics().on_error(transport.into(), StageLabel::Read);
                break;
            }
            Err(_) => {
                warn!(peer = %peer, timeout_secs = SESSION_IDLE_TIMEOUT.as_secs(),
                    "stream session idle timeout, closing connection");
                transport_metrics().on_error(transport.into(), StageLabel::Read);
                break;
            }
        }
    }

    drop(writer_tx);
    let _ = writer_handle.await;
}

/// Splits buffered TCP/TLS data into complete SIP messages using Content-Length or CRLFCRLF.
///
/// # Security
///
/// Enforces MAX_HEADER_SIZE and MAX_BODY_SIZE limits to prevent memory exhaustion attacks.
/// Returns an error if limits are exceeded, causing the connection to be closed.
pub(crate) fn drain_sip_frames(buf: &mut BytesMut) -> Result<Vec<Bytes>> {
    let mut frames = Vec::new();
    loop {
        // Handle CRLF keep-alive pings (RFC 5626)
        consume_leading_crlf(buf);
        if buf.is_empty() {
            break;
        }

        // Look for end of headers (\r\n\r\n)
        let head_end = match memchr::memmem::find(buf.as_ref(), b"\r\n\r\n") {
            Some(pos) => pos,
            None => {
                // No complete headers yet - check if buffer is growing too large
                if buf.len() > MAX_HEADER_SIZE {
                    return Err(anyhow!(
                        "SIP headers exceed MAX_HEADER_SIZE ({} bytes), possible attack",
                        MAX_HEADER_SIZE
                    ));
                }
                break;
            }
        };

        // Check header size limit
        if head_end > MAX_HEADER_SIZE {
            return Err(anyhow!(
                "SIP headers are {} bytes, exceeds MAX_HEADER_SIZE ({} bytes)",
                head_end,
                MAX_HEADER_SIZE
            ));
        }

        let header_bytes = &buf[..head_end];
        let content_length = parse_content_length(header_bytes)?;

        // Check body size limit
        if let Some(cl) = content_length {
            if cl > MAX_BODY_SIZE {
                return Err(anyhow!(
                    "Content-Length {} exceeds MAX_BODY_SIZE ({} bytes)",
                    cl,
                    MAX_BODY_SIZE
                ));
            }
        }

        // RFC 3261 §18.3: Content-Length is mandatory for stream transports.
        // If missing, assume zero-length body but log a warning since this may
        // indicate a smuggling attempt or a broken peer.
        let body_length = match content_length {
            Some(cl) => cl,
            None => {
                warn!(
                    "SIP message missing Content-Length header on stream transport; \
                     assuming zero-length body (RFC 3261 §18.3 violation)"
                );
                0
            }
        };

        let needed = head_end + 4 + body_length;
        if buf.len() < needed {
            // Don't have complete message yet
            break;
        }

        frames.push(buf.split_to(needed).freeze());
    }
    Ok(frames)
}

fn consume_leading_crlf(buf: &mut BytesMut) {
    loop {
        if buf.starts_with(b"\r\n") {
            buf.advance(2);
            continue;
        }
        if buf.starts_with(b"\n") {
            buf.advance(1);
            continue;
        }
        if buf.starts_with(b"\r") {
            buf.advance(1);
            continue;
        }
        break;
    }
}

fn parse_content_length(headers: &[u8]) -> Result<Option<usize>> {
    let mut found: Option<usize> = None;
    for line in headers.split(|b| *b == b'\n') {
        let line = if line.ends_with(b"\r") {
            &line[..line.len().saturating_sub(1)]
        } else {
            line
        };
        let Some(colon) = memchr::memchr(b':', line) else {
            continue;
        };
        let name = trim_ascii_whitespace(&line[..colon]);
        // RFC 3261 §7.3.3: "l" is the compact form of "Content-Length"
        if !ascii_eq_ignore_case(name, b"content-length") && !ascii_eq_ignore_case(name, b"l") {
            continue;
        }
        let value = trim_ascii_whitespace(&line[colon + 1..]);
        let parsed = parse_ascii_usize(value)?;
        if let Some(existing) = found {
            if existing != parsed {
                return Err(anyhow!(
                    "multiple Content-Length headers with different values"
                ));
            }
        } else {
            found = Some(parsed);
        }
    }
    Ok(found)
}

fn trim_ascii_whitespace(input: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = input.len();
    while start < end && input[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && input[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &input[start..end]
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn parse_ascii_usize(value: &[u8]) -> Result<usize> {
    if value.is_empty() {
        return Err(anyhow!("Content-Length header value is empty"));
    }
    let mut acc: usize = 0;
    for &b in value {
        if !b.is_ascii_digit() {
            return Err(anyhow!("Content-Length contains non-digit characters"));
        }
        let digit = (b - b'0') as usize;
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| anyhow!("Content-Length value overflows usize"))?;
    }
    Ok(acc)
}

#[cfg(feature = "ws")]
fn ensure_ws_subprotocol(
    response: &tokio_tungstenite::tungstenite::handshake::client::Response,
) -> Result<()> {
    match response.headers().get("Sec-WebSocket-Protocol") {
        Some(value) => {
            let proto = value
                .to_str()
                .map_err(|_| anyhow!("invalid Sec-WebSocket-Protocol header"))?;
            if proto.eq_ignore_ascii_case("sip") {
                Ok(())
            } else {
                Err(anyhow!("server did not accept Sec-WebSocket-Protocol: sip"))
            }
        }
        None => Err(anyhow!(
            "server did not negotiate Sec-WebSocket-Protocol: sip"
        )),
    }
}

#[cfg(feature = "ws")]
fn ws_subprotocol_error_response() -> tungstenite::handshake::server::ErrorResponse {
    use tokio_tungstenite::tungstenite::http::{Response, StatusCode};
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Some("Missing Sec-WebSocket-Protocol: sip".to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(None)
                .unwrap()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drains_multiple_frames_and_bodies() {
        let msg1 = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 4\r\n\r\nbody";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let payload = [msg1.as_slice(), msg2.as_slice()].concat();
        let mut buf = BytesMut::from(&payload[..]);
        let frames = drain_sip_frames(&mut buf).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(buf.is_empty());
        assert_eq!(frames[0].as_ref(), msg1);
        assert_eq!(frames[1].as_ref(), msg2);
    }

    #[test]
    fn leaves_partial_body_in_buffer() {
        let payload = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhi";
        let mut buf = BytesMut::from(&payload[..]);
        let frames = drain_sip_frames(&mut buf).unwrap();
        assert!(frames.is_empty(), "should not emit incomplete frame");
        assert_eq!(buf.len(), payload.len());
    }

    #[test]
    fn discards_crlf_keepalive() {
        let mut buf = BytesMut::from(&b"\r\n"[..]);
        let frames = drain_sip_frames(&mut buf).unwrap();
        assert!(frames.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn strips_multiple_crlf_keepalives() {
        let msg = b"\r\n\r\nOPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut buf = BytesMut::from(&msg[..]);
        let frames = drain_sip_frames(&mut buf).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(buf.is_empty());
        assert_eq!(frames[0].as_ref(), &msg[4..]);
    }

    // Security tests - memory exhaustion protections

    #[test]
    fn rejects_headers_exceeding_max_size() {
        // Create a SIP message with headers larger than MAX_HEADER_SIZE (64 KB)
        let mut headers = String::from("OPTIONS sip:a SIP/2.0\r\n");
        // Add a very long header value to exceed 64 KB
        headers.push_str("X-Large-Header: ");
        headers.push_str(&"A".repeat(70 * 1024)); // 70 KB header value
        headers.push_str("\r\n\r\n");

        let mut buf = BytesMut::from(headers.as_bytes());
        let result = drain_sip_frames(&mut buf);

        assert!(result.is_err(), "should reject oversized headers");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("MAX_HEADER_SIZE"));
    }

    #[test]
    fn rejects_partial_headers_exceeding_max_size() {
        // Create partial headers (no \r\n\r\n yet) larger than MAX_HEADER_SIZE
        let mut headers = String::from("OPTIONS sip:a SIP/2.0\r\n");
        headers.push_str("X-Large-Header: ");
        headers.push_str(&"B".repeat(70 * 1024)); // 70 KB, no terminator

        let mut buf = BytesMut::from(headers.as_bytes());
        let result = drain_sip_frames(&mut buf);

        assert!(
            result.is_err(),
            "should reject incomplete headers exceeding limit"
        );
        let err = result.unwrap_err();
        assert!(err.to_string().contains("MAX_HEADER_SIZE"));
    }

    #[test]
    fn rejects_content_length_exceeding_max_body_size() {
        // Create a SIP message with Content-Length larger than MAX_BODY_SIZE (10 MB)
        let oversized_cl = (11 * 1024 * 1024).to_string(); // 11 MB
        let msg = format!(
            "OPTIONS sip:a SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            oversized_cl
        );

        let mut buf = BytesMut::from(msg.as_bytes());
        let result = drain_sip_frames(&mut buf);

        assert!(result.is_err(), "should reject oversized Content-Length");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("MAX_BODY_SIZE"));
    }

    #[test]
    fn rejects_multiple_content_length_mismatch() {
        let msg = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nbody";
        let mut buf = BytesMut::from(&msg[..]);
        let result = drain_sip_frames(&mut buf);
        assert!(result.is_err(), "should reject mismatched Content-Length");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Content-Length"));
    }

    #[test]
    fn accepts_multiple_content_length_same_value() {
        let msg = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbody";
        let mut buf = BytesMut::from(&msg[..]);
        let result = drain_sip_frames(&mut buf);
        assert!(result.is_ok(), "should accept repeated Content-Length");
        let frames = result.unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn handles_invalid_utf8_headers() {
        let mut msg = b"OPTIONS sip:a SIP/2.0\r\nX-Bad: ".to_vec();
        msg.extend_from_slice(&[0xff, 0xfe]);
        msg.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let mut buf = BytesMut::from(&msg[..]);
        let result = drain_sip_frames(&mut buf);
        assert!(
            result.is_ok(),
            "should parse Content-Length with invalid UTF-8 elsewhere"
        );
        let frames = result.unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn accepts_headers_just_under_max_size() {
        // Create a SIP message with headers just under MAX_HEADER_SIZE (64 KB)
        let mut headers = String::from("OPTIONS sip:a SIP/2.0\r\n");
        // Add a header that brings us close to but under 64 KB
        headers.push_str("X-Large-Header: ");
        headers.push_str(&"C".repeat(60 * 1024)); // 60 KB header value
        headers.push_str("\r\nContent-Length: 0\r\n\r\n");

        let mut buf = BytesMut::from(headers.as_bytes());
        let result = drain_sip_frames(&mut buf);

        assert!(result.is_ok(), "should accept headers under limit");
        let frames = result.unwrap();
        assert_eq!(frames.len(), 1);
    }

    // TransportKind tests

    #[test]
    fn transport_kind_as_str() {
        assert_eq!(TransportKind::Udp.as_str(), "udp");
        assert_eq!(TransportKind::Tcp.as_str(), "tcp");
        assert_eq!(TransportKind::Tls.as_str(), "tls");
        assert_eq!(TransportKind::Sctp.as_str(), "sctp");
        assert_eq!(TransportKind::TlsSctp.as_str(), "tls-sctp");
    }

    #[test]
    fn transport_kind_via_transport() {
        assert_eq!(TransportKind::Udp.via_transport(), "UDP");
        assert_eq!(TransportKind::Tcp.via_transport(), "TCP");
        assert_eq!(TransportKind::Tls.via_transport(), "TLS");
        assert_eq!(TransportKind::Sctp.via_transport(), "SCTP");
        assert_eq!(TransportKind::TlsSctp.via_transport(), "TLS-SCTP");
    }

    #[test]
    fn transport_kind_parse() {
        assert_eq!(TransportKind::parse("UDP"), Some(TransportKind::Udp));
        assert_eq!(TransportKind::parse("tcp"), Some(TransportKind::Tcp));
        assert_eq!(TransportKind::parse("TLS"), Some(TransportKind::Tls));
        assert_eq!(TransportKind::parse("SCTP"), Some(TransportKind::Sctp));
        assert_eq!(
            TransportKind::parse("TLS-SCTP"),
            Some(TransportKind::TlsSctp)
        );
        assert_eq!(
            TransportKind::parse("tls-sctp"),
            Some(TransportKind::TlsSctp)
        );
    }

    #[test]
    fn transport_kind_parse_case_insensitive() {
        assert_eq!(TransportKind::parse("udp"), Some(TransportKind::Udp));
        assert_eq!(TransportKind::parse("UDP"), Some(TransportKind::Udp));
        assert_eq!(TransportKind::parse("Udp"), Some(TransportKind::Udp));
        assert_eq!(TransportKind::parse("sctp"), Some(TransportKind::Sctp));
        assert_eq!(TransportKind::parse("SCTP"), Some(TransportKind::Sctp));
        assert_eq!(TransportKind::parse("Sctp"), Some(TransportKind::Sctp));
    }

    #[test]
    fn transport_kind_parse_with_whitespace() {
        assert_eq!(TransportKind::parse("  UDP  "), Some(TransportKind::Udp));
        assert_eq!(TransportKind::parse("  sctp  "), Some(TransportKind::Sctp));
        assert_eq!(
            TransportKind::parse("  tls-sctp  "),
            Some(TransportKind::TlsSctp)
        );
    }

    #[test]
    fn transport_kind_parse_invalid() {
        assert_eq!(TransportKind::parse("invalid"), None);
        assert_eq!(TransportKind::parse(""), None);
    }

    #[test]
    fn transport_kind_is_stream_based() {
        assert!(!TransportKind::Udp.is_stream_based());
        assert!(TransportKind::Tcp.is_stream_based());
        assert!(TransportKind::Tls.is_stream_based());
        assert!(TransportKind::Sctp.is_stream_based());
        assert!(TransportKind::TlsSctp.is_stream_based());
    }

    #[test]
    fn transport_kind_is_secure() {
        assert!(!TransportKind::Udp.is_secure());
        assert!(!TransportKind::Tcp.is_secure());
        assert!(TransportKind::Tls.is_secure());
        assert!(!TransportKind::Sctp.is_secure());
        assert!(TransportKind::TlsSctp.is_secure());
    }

    #[test]
    fn transport_kind_round_trip() {
        let transports = vec![
            TransportKind::Udp,
            TransportKind::Tcp,
            TransportKind::Tls,
            TransportKind::Sctp,
            TransportKind::TlsSctp,
        ];

        for transport in transports {
            let via_str = transport.via_transport();
            let parsed = TransportKind::parse(via_str).unwrap();
            assert_eq!(parsed, transport);
        }
    }

    #[test]
    fn parses_compact_content_length_header() {
        // RFC 3261 §7.3.3: "l" is the compact form of "Content-Length"
        let msg = b"OPTIONS sip:a SIP/2.0\r\nl: 4\r\n\r\nbody";
        let mut buf = BytesMut::from(&msg[..]);
        let frames = drain_sip_frames(&mut buf).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_ref(), msg.as_slice());
    }

    #[test]
    fn parses_compact_content_length_case_insensitive() {
        let msg = b"OPTIONS sip:a SIP/2.0\r\nL: 3\r\n\r\nabc";
        let mut buf = BytesMut::from(&msg[..]);
        let frames = drain_sip_frames(&mut buf).unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn missing_content_length_assumes_zero_body() {
        // Missing Content-Length on stream transport should assume zero body
        let msg = b"OPTIONS sip:a SIP/2.0\r\nVia: SIP/2.0/TCP host\r\n\r\n";
        let mut buf = BytesMut::from(&msg[..]);
        let frames = drain_sip_frames(&mut buf).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_ref(), msg.as_slice());
    }
}
