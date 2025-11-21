use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use sip_observe::{span_with_transport, transport_metrics};
pub mod pool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{error, info};

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
            TransportKind::Tcp | TransportKind::Tls | TransportKind::Sctp | TransportKind::TlsSctp
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
        matches!(self, TransportKind::Tls | TransportKind::TlsSctp)
    }
}

/// Bundle representing a packet received by a transport listener.
#[derive(Debug, Clone)]
pub struct InboundPacket {
    pub transport: TransportKind,
    pub peer: SocketAddr,
    pub payload: Bytes,
    pub stream: Option<mpsc::Sender<Bytes>>,
}

/// Runs a UDP receive loop and forwards packets to the provided channel.
pub async fn run_udp(socket: Arc<UdpSocket>, tx: mpsc::Sender<InboundPacket>) -> Result<()> {
    let bind = socket.local_addr()?;
    info!(%bind, "listening (udp)");
    let mut buf = vec![0u8; 65_535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                let span = span_with_transport("udp_packet", TransportKind::Udp.as_str());
                let _entered = span.enter();
                let payload = Bytes::copy_from_slice(&buf[..n]);
                if n == buf.len() {
                    transport_metrics().on_error(TransportKind::Udp.as_str(), "truncate");
                    error!(
                        %peer,
                        max = n,
                        "udp datagram likely truncated (buffer full); consider TCP"
                    );
                }
                transport_metrics().on_packet_received(TransportKind::Udp.as_str());
                let packet = InboundPacket {
                    transport: TransportKind::Udp,
                    peer,
                    payload,
                    stream: None,
                };
                if tx.send(packet).await.is_err() {
                    error!("receiver dropped; shutting down udp loop");
                    transport_metrics().on_error(TransportKind::Udp.as_str(), "dispatch");
                    break;
                }
            }
            Err(e) => {
                error!(%e, "udp recv_from error");
                transport_metrics().on_error(TransportKind::Udp.as_str(), "recv");
            }
        }
    }
    Ok(())
}

/// Sends a UDP datagram using an existing bound socket.
pub async fn send_udp(socket: &UdpSocket, to: &std::net::SocketAddr, data: &[u8]) -> Result<()> {
    socket.send_to(data, to).await?;
    transport_metrics().on_packet_sent(TransportKind::Udp.as_str());
    Ok(())
}

/// Accepts TCP connections, streaming frames to the supplied channel.
pub async fn run_tcp(bind: &str, tx: mpsc::Sender<InboundPacket>) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "listening (tcp)");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!(%e, "tcp accept error");
                transport_metrics().on_error(TransportKind::Tcp.as_str(), "accept");
                continue;
            }
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let span = span_with_transport("tcp_session", TransportKind::Tcp.as_str());
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
        });
    }
}

/// Connects to the destination and writes the bytes over TCP.
pub async fn send_tcp(to: &SocketAddr, data: &[u8]) -> Result<()> {
    let mut stream = TcpStream::connect(to).await?;
    stream.write_all(data).await?;
    transport_metrics().on_packet_sent(TransportKind::Tcp.as_str());
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
    transport_metrics().on_packet_sent(transport.as_str());
    Ok(())
}

#[cfg(feature = "tls")]
/// TLS client configuration used for outbound SIPS traffic.
pub struct TlsConfig {
    pub server_name: String,
    pub client_config: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
}

#[cfg(feature = "tls")]
/// Sends bytes over a TLS connection using rustls.
pub async fn send_tls(to: &SocketAddr, data: &[u8], config: &TlsConfig) -> Result<()> {
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let connector = TlsConnector::from(config.client_config.clone());
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| anyhow!("invalid TLS server name"))?;
    let stream = TcpStream::connect(to).await?;
    let mut tls_stream = connector.connect(server_name, stream).await?;
    tls_stream.write_all(data).await?;
    transport_metrics().on_packet_sent(TransportKind::Tls.as_str());
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

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!(%e, "tls accept error");
                transport_metrics().on_error(TransportKind::Tls.as_str(), "accept");
                continue;
            }
        };
        let tx = tx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let span = span_with_transport("tls_session", TransportKind::Tls.as_str());
            let _entered = span.enter();
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!(%e, "tls handshake error");
                    transport_metrics().on_error(TransportKind::Tls.as_str(), "handshake");
                    return;
                }
            };

            spawn_stream_session(
                peer,
                tls_stream,
                TransportKind::Tls,
                tx,
                "tls read error",
                "tls write error",
            )
            .await;
        });
    }
}

#[cfg(feature = "tls")]
/// Loads a rustls server config from PEM certificate and key files.
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

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("failed to build tls config: {e}"))?;
    Ok(std::sync::Arc::new(config))
}

/// Decides which transport to use for an outbound message.
pub trait TransportPolicy: Send + Sync {
    /// Returns the selected transport given a requested transport, payload size, and SIPS hint.
    fn choose(&self, requested: TransportKind, payload_len: usize, sips: bool) -> TransportKind;
}

/// Default policy that prefers TLS for SIPS and falls back to TCP when payloads exceed a UDP MTU.
#[derive(Debug, Clone)]
pub struct DefaultTransportPolicy {
    pub udp_mtu: usize,
}

impl Default for DefaultTransportPolicy {
    fn default() -> Self {
        Self { udp_mtu: 1300 }
    }
}

impl TransportPolicy for DefaultTransportPolicy {
    fn choose(&self, requested: TransportKind, payload_len: usize, sips: bool) -> TransportKind {
        if sips {
            return TransportKind::Tls;
        }
        if matches!(requested, TransportKind::Udp) && payload_len > self.udp_mtu {
            TransportKind::Tcp
        } else {
            requested
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
                transport_metrics().on_error(transport.as_str(), "write");
                break;
            }
            transport_metrics().on_packet_sent(transport.as_str());
        }
    });

    let mut buf = BytesMut::with_capacity(4096);
    loop {
        match reader.read_buf(&mut buf).await {
            Ok(0) => break,
            Ok(_) => {
                transport_metrics().on_packet_received(transport.as_str());
                for payload in drain_sip_frames(&mut buf) {
                    let packet = InboundPacket {
                        transport,
                        peer,
                        payload,
                        stream: Some(writer_tx.clone()),
                    };
                    if tx.send(packet).await.is_err() {
                        error!("receiver dropped; shutting down {:?} session", transport);
                        transport_metrics().on_error(transport.as_str(), "dispatch");
                        break;
                    }
                }
            }
            Err(e) => {
                error!(%e, "{}", read_label);
                transport_metrics().on_error(transport.as_str(), "read");
                break;
            }
        }
    }

    drop(writer_tx);
    let _ = writer_handle.await;
}

/// Splits buffered TCP/TLS data into complete SIP messages using Content-Length or CRLFCRLF.
fn drain_sip_frames(buf: &mut BytesMut) -> Vec<Bytes> {
    let mut frames = Vec::new();
    loop {
        // Handle CRLF keep-alive pings
        if buf.len() <= 2 && buf.iter().all(|b| *b == b'\r' || *b == b'\n') {
            buf.clear();
            break;
        }

        let head_end = match memchr::memmem::find(buf.as_ref(), b"\r\n\r\n") {
            Some(pos) => pos,
            None => break,
        };

        let header_bytes = &buf[..head_end];
        let content_length = parse_content_length(header_bytes);
        let needed = head_end + 4 + content_length.unwrap_or(0);
        if buf.len() < needed {
            break;
        }

        frames.push(buf.split_to(needed).freeze());
    }
    frames
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drains_multiple_frames_and_bodies() {
        let msg1 =
            b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 4\r\n\r\nbody";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let payload = [msg1.as_slice(), msg2.as_slice()].concat();
        let mut buf = BytesMut::from(&payload[..]);
        let frames = drain_sip_frames(&mut buf);
        assert_eq!(frames.len(), 2);
        assert!(buf.is_empty());
        assert_eq!(frames[0].as_ref(), msg1);
        assert_eq!(frames[1].as_ref(), msg2);
    }

    #[test]
    fn leaves_partial_body_in_buffer() {
        let payload = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhi";
        let mut buf = BytesMut::from(&payload[..]);
        let frames = drain_sip_frames(&mut buf);
        assert!(frames.is_empty(), "should not emit incomplete frame");
        assert_eq!(buf.len(), payload.len());
    }

    #[test]
    fn discards_crlf_keepalive() {
        let mut buf = BytesMut::from(&b"\r\n"[..]);
        let frames = drain_sip_frames(&mut buf);
        assert!(frames.is_empty());
        assert!(buf.is_empty());
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
        assert_eq!(TransportKind::parse("ws"), None);
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
}
