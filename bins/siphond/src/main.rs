use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use clap::Parser;
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri, StatusLine};
use sip_observe::{set_transport_metrics, TracingTransportMetrics};
use sip_parse::{header, parse_request, parse_response, serialize_request};
use sip_transaction::{
    generate_branch_id, request_branch_id, ClientTransactionUser, TransactionKey,
    TransactionManager, TransportContext, TransportDispatcher, TransportKind,
};
use sip_transport::{
    load_rustls_server_config, run_tcp, run_tls, run_udp, send_stream, send_udp, InboundPacket,
    DefaultTransportPolicy, TransportPolicy, pool::{ConnectionPool, TlsPool, TlsClientConfig},
};
use smol_str::SmolStr;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    fs,
    net::UdpSocket,
    sync::{mpsc, watch},
    time::{self, Duration},
};
use tracing::{info, instrument, warn};

const USER_AGENT: &str = "siphond/0.1";
const DEFAULT_MAX_FORWARDS: &str = "70";

/// Simple SIP UDP daemon that answers OPTIONS with 200 OK
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Bind address (UDP)
    #[arg(long, default_value = "0.0.0.0:5060")]
    udp_bind: String,
    /// Bind address (TCP)
    #[arg(long, default_value = "0.0.0.0:5060")]
    tcp_bind: String,
    /// Bind address (TLS/SIPS)
    #[arg(long, default_value = "0.0.0.0:5061")]
    sips_bind: String,
    /// TLS certificate path (PEM)
    #[arg(long)]
    tls_cert: Option<String>,
    /// TLS private key path (PEM)
    #[arg(long)]
    tls_key: Option<String>,
    /// Remote socket to send an outbound OPTIONS request to (ip:port)
    #[arg(long)]
    uac_peer: Option<String>,
    /// SIP URI used as the Request-URI for outbound OPTIONS
    #[arg(long)]
    uac_target: Option<String>,
    /// SIP URI placed in From/Contact headers for outbound requests
    #[arg(long, default_value = "sip:siphond@localhost")]
    uac_from: String,
    /// Overrides the Via host:port value for outbound requests (defaults to udp_bind)
    #[arg(long)]
    uac_via: Option<String>,
    /// Interval (seconds) between outbound OPTIONS; if omitted only one request is sent at startup
    #[arg(long)]
    uac_interval_secs: Option<u64>,
    /// Method to send for outbound requests (OPTIONS, REGISTER, INVITE)
    #[arg(long)]
    uac_method: Option<String>,
    /// Path to a JSON config file watched for outbound overrides
    #[arg(long)]
    uac_config: Option<PathBuf>,
}

#[tokio::main]
/// Entry point for the SIP UDP/TCP demo daemon.
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    set_transport_metrics(Arc::new(TracingTransportMetrics::default()));
    let Args {
        udp_bind,
        tcp_bind,
        sips_bind,
        tls_cert,
        tls_key,
        uac_peer,
        uac_target,
        uac_from,
        uac_via,
        uac_interval_secs,
        uac_method,
        uac_config,
    } = Args::parse();

    let socket = Arc::new(UdpSocket::bind(&udp_bind).await?);
    let recv_socket = Arc::clone(&socket);

    let transport = Arc::new(SiphonTransportDispatcher::new(
        Arc::clone(&socket),
        Arc::new(DefaultTransportPolicy::default()),
        Arc::new(ConnectionPool::new()),
        Arc::new(TlsPool::new()),
        None,
    ));
    let dispatcher: Arc<dyn TransportDispatcher> = transport.clone();
    let manager = TransactionManager::new(dispatcher.clone());
    let client_tu = Arc::new(SiphonClientTransactionUser::new(dispatcher.clone()));

    let from_uri = SipUri::parse(&uac_from)
        .ok_or_else(|| anyhow::anyhow!("invalid --uac-from URI: {}", uac_from))?;
    let default_method = uac_method
        .as_deref()
        .and_then(parse_method_name)
        .unwrap_or(Method::Options);

    let (config_tx, config_rx) = watch::channel::<Option<OutboundConfig>>(None);
    if let Some(config) = build_outbound_config(
        uac_peer.as_deref(),
        uac_target.as_deref(),
        uac_via.as_deref(),
        uac_interval_secs,
        default_method,
        &from_uri,
        &udp_bind,
    ) {
        let _ = config_tx.send(Some(config));
    }
    if let Some(path) = uac_config.clone() {
        spawn_config_watcher(
            path,
            OutboundDefaults {
                via: udp_bind.clone(),
                from_uri: from_uri.clone(),
                method: default_method,
            },
            config_tx.clone(),
        );
    }
    spawn_outbound_manager(manager.clone(), client_tu.clone(), config_rx);

    let (tx, mut rx) = mpsc::channel::<InboundPacket>(1024);
    tokio::spawn({
        let bind = udp_bind.clone();
        let tx = tx.clone();
        async move {
            if let Err(e) = run_udp(recv_socket, tx).await {
                tracing::error!(%e, bind = %bind, "udp listener exited");
            }
        }
    });

    tokio::spawn({
        let bind = tcp_bind.clone();
        let tx = tx.clone();
        async move {
            if let Err(e) = run_tcp(&bind, tx).await {
                tracing::error!(%e, bind = %bind, "tcp listener exited");
            }
        }
    });

    if let (Some(cert), Some(key)) = (tls_cert.as_deref(), tls_key.as_deref()) {
        match load_rustls_server_config(cert, key) {
            Ok(config) => {
                let bind = sips_bind.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_tls(&bind, config, tx).await {
                        tracing::error!(%e, bind = %bind, "tls listener exited");
                    }
                });
            }
            Err(err) => {
                warn!(%err, "failed to build TLS config; TLS listener disabled");
            }
        }
    } else if tls_cert.is_some() || tls_key.is_some() {
        warn!("both --tls-cert and --tls-key must be provided to enable TLS");
    }

    info!(
        "siphond started on udp {}, tcp {}, tls {}",
        udp_bind, tcp_bind, sips_bind
    );
    while let Some(packet) = rx.recv().await {
        handle_packet(&manager, packet).await;
    }
    Ok(())
}

#[instrument(name = "handle_packet", skip(manager, packet), fields(transport = ?packet.transport, peer = %packet.peer))]
/// Processes a single inbound packet and emits responses via the transaction manager.
async fn handle_packet(manager: &TransactionManager, packet: InboundPacket) {
    if let Some(req) = parse_request(&packet.payload) {
        if req.start.method == Method::Ack {
            if let Some(branch) = request_branch_id(&req) {
                let key = TransactionKey {
                    branch,
                    method: Method::Invite,
                    is_server: true,
                };
                manager.ack_received(&key).await;
            }
            return;
        }

        let ctx = TransportContext::new(
            map_transport(packet.transport),
            packet.peer,
            packet.stream.clone(),
        );
        let handle = manager.receive_request(req.clone(), ctx).await;
        match req.start.method {
            Method::Options => {
                // Essential headers to echo
                let via = header(&req.headers, "Via").cloned().unwrap_or_default();
                let to = header(&req.headers, "To").cloned().unwrap_or_default();
                let from = header(&req.headers, "From").cloned().unwrap_or_default();
                let call_id = header(&req.headers, "Call-ID").cloned().unwrap_or_default();
                let cseq = header(&req.headers, "CSeq").cloned().unwrap_or_default();
                let max_forwards = header(&req.headers, "Max-Forwards").cloned();

                // Add a to-tag if missing (naive for demo)
                let to_with_tag = if to.is_empty() || to.contains(";tag=") {
                    to
                } else {
                    format!("{};tag=sr", to).into()
                };

                let mut headers = Headers::new();
                headers.push("Via".into(), via);
                headers.push("To".into(), to_with_tag);
                headers.push("From".into(), from);
                headers.push("Call-ID".into(), call_id);
                headers.push("CSeq".into(), cseq);
                if let Some(mf) = max_forwards {
                    headers.push("Max-Forwards".into(), mf);
                }

                let response =
                    Response::new(StatusLine::new(200, "OK".into()), headers, Bytes::new());
                handle.send_final(response).await;
            }
            other => {
                warn!("Unhandled method {:?} from {}", other, packet.peer);
            }
        }
        return;
    }

    if let Some(response) = parse_response(&packet.payload) {
        manager.receive_response(response).await;
        return;
    }

    warn!(
        "Non-UTF8 or unparsable packet from {} via {:?}",
        packet.peer, packet.transport
    );
}

async fn start_outbound_request(
    manager: TransactionManager,
    tu: Arc<SiphonClientTransactionUser>,
    config: &OutboundConfig,
    cseq: u32,
) -> Result<()> {
    let branch = generate_branch_id();
    let from_tag = random_token(8);
    let call_id = format!("{}@{}", random_token(10), config.via_host);

    let method = config.method;

    let mut headers = Headers::new();
    headers.push(
        "Via".into(),
        SmolStr::new(format!(
            "SIP/2.0/UDP {};branch={}",
            config.via_host,
            branch.as_str()
        )),
    );
    headers.push(
        "Max-Forwards".into(),
        SmolStr::new(DEFAULT_MAX_FORWARDS.to_owned()),
    );
    headers.push(
        "From".into(),
        SmolStr::new(format!("<{}>;tag={}", config.from_uri.as_str(), from_tag)),
    );
    headers.push(
        "To".into(),
        SmolStr::new(format!("<{}>", config.target_uri.as_str())),
    );
    headers.push("Call-ID".into(), SmolStr::new(call_id));
    headers.push(
        "CSeq".into(),
        SmolStr::new(format!("{} {}", cseq, method.as_str())),
    );
    headers.push(
        "Contact".into(),
        SmolStr::new(format!("<{}>", config.from_uri.as_str())),
    );
    headers.push("User-Agent".into(), SmolStr::new(USER_AGENT.to_owned()));

    let request = Request::new(
        RequestLine::new(method, config.target_uri.clone()),
        headers,
        Bytes::new(),
    );
    let ctx = TransportContext::new(TransportKind::Udp, config.peer, None);
    let stored = request.clone();
    let tu_handle: Arc<dyn ClientTransactionUser> = tu.clone();
    let key = manager
        .start_client_transaction(request, ctx.clone(), tu_handle)
        .await?;
    tu.register_request(key, stored, ctx);
    info!(
        method = ?method,
        target = %config.target_uri.as_str(),
        peer = %config.peer,
        "started outbound client transaction"
    );
    Ok(())
}

#[derive(Clone)]
struct OutboundConfig {
    peer: SocketAddr,
    target_uri: SipUri,
    from_uri: SipUri,
    via_host: String,
    interval: Option<Duration>,
    method: Method,
}

#[derive(Clone)]
struct OutboundDefaults {
    via: String,
    from_uri: SipUri,
    method: Method,
}

#[derive(Debug, Deserialize)]
struct FileOutboundConfig {
    peer: String,
    target: String,
    from: Option<String>,
    via: Option<String>,
    method: Option<String>,
    interval_secs: Option<u64>,
}

fn build_outbound_config(
    peer: Option<&str>,
    target: Option<&str>,
    via_override: Option<&str>,
    interval_secs: Option<u64>,
    method: Method,
    from_uri: &SipUri,
    default_via: &str,
) -> Option<OutboundConfig> {
    match (peer, target) {
        (Some(peer_str), Some(target_uri)) => {
            let peer_addr = match peer_str.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(%err, "invalid --uac-peer value");
                    return None;
                }
            };
            let target_uri = match SipUri::parse(target_uri) {
                Some(uri) => uri,
                None => {
                    warn!("invalid --uac-target URI; outbound requests disabled");
                    return None;
                }
            };
            Some(OutboundConfig {
                peer: peer_addr,
                target_uri,
                from_uri: from_uri.clone(),
                via_host: via_override.unwrap_or(default_via).to_owned(),
                interval: interval_secs.map(Duration::from_secs),
                method,
            })
        }
        (None, None) => None,
        _ => {
            warn!("both --uac-peer and --uac-target must be set to send outbound requests");
            None
        }
    }
}

fn spawn_config_watcher(
    path: PathBuf,
    defaults: OutboundDefaults,
    tx: watch::Sender<Option<OutboundConfig>>,
) {
    tokio::spawn(async move {
        let mut last_modified: Option<SystemTime> = None;
        loop {
            match fs::metadata(&path).await {
                Ok(metadata) => {
                    let modified = metadata.modified().ok();
                    let should_reload = last_modified != modified;
                    if should_reload {
                        last_modified = modified;
                        match fs::read_to_string(&path).await {
                            Ok(contents) => {
                                match serde_json::from_str::<FileOutboundConfig>(&contents) {
                                    Ok(raw) => {
                                        if let Some(config) = convert_file_config(raw, &defaults) {
                                            if tx.send(Some(config)).is_err() {
                                                break;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        warn!(%err, path = %path.display(), "failed to parse outbound config")
                                    }
                                }
                            }
                            Err(err) => {
                                warn!(%err, path = %path.display(), "failed to read outbound config")
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(%err, path = %path.display(), "unable to read outbound config metadata");
                }
            }
            time::sleep(Duration::from_secs(3)).await;
        }
    });
}

fn convert_file_config(
    raw: FileOutboundConfig,
    defaults: &OutboundDefaults,
) -> Option<OutboundConfig> {
    let method = raw
        .method
        .as_deref()
        .and_then(parse_method_name)
        .unwrap_or(defaults.method);
    let peer = raw.peer.parse::<SocketAddr>().ok()?;
    let target_uri = SipUri::parse(&raw.target)?;
    let from_uri = raw
        .from
        .as_deref()
        .and_then(SipUri::parse)
        .unwrap_or_else(|| defaults.from_uri.clone());
    let via = raw.via.unwrap_or_else(|| defaults.via.clone());
    Some(OutboundConfig {
        peer,
        target_uri,
        from_uri,
        via_host: via,
        interval: raw.interval_secs.map(Duration::from_secs),
        method,
    })
}

fn spawn_outbound_manager(
    manager: TransactionManager,
    tu: Arc<SiphonClientTransactionUser>,
    mut rx: watch::Receiver<Option<OutboundConfig>>,
) {
    tokio::spawn(async move {
        let mut current = start_outbound_task(manager.clone(), tu.clone(), rx.borrow().clone());
        loop {
            if rx.changed().await.is_err() {
                if let Some(handle) = current.take() {
                    handle.abort();
                }
                break;
            }
            if let Some(handle) = current.take() {
                handle.abort();
            }
            current = start_outbound_task(manager.clone(), tu.clone(), rx.borrow().clone());
        }
    });
}

fn start_outbound_task(
    manager: TransactionManager,
    tu: Arc<SiphonClientTransactionUser>,
    config: Option<OutboundConfig>,
) -> Option<tokio::task::JoinHandle<()>> {
    let config = config?;
    Some(tokio::spawn(async move {
        let mut cseq: u32 = 1;
        let mut ticker = config.interval.map(time::interval);
        loop {
            if let Err(err) =
                start_outbound_request(manager.clone(), tu.clone(), &config, cseq).await
            {
                warn!(%err, "failed to start outbound transaction");
            }
            cseq = cseq.saturating_add(1);
            match &mut ticker {
                Some(interval) => {
                    interval.tick().await;
                }
                None => break,
            }
        }
    }))
}

fn map_transport(kind: sip_transport::TransportKind) -> TransportKind {
    match kind {
        sip_transport::TransportKind::Udp => TransportKind::Udp,
        sip_transport::TransportKind::Tcp => TransportKind::Tcp,
        sip_transport::TransportKind::Tls => TransportKind::Tls,
    }
}

fn to_sip_transport(kind: TransportKind) -> sip_transport::TransportKind {
    match kind {
        TransportKind::Udp => sip_transport::TransportKind::Udp,
        TransportKind::Tcp => sip_transport::TransportKind::Tcp,
        TransportKind::Tls => sip_transport::TransportKind::Tls,
    }
}

fn parse_method_name(name: &str) -> Option<Method> {
    match name.to_ascii_uppercase().as_str() {
        "OPTIONS" => Some(Method::Options),
        "REGISTER" => Some(Method::Register),
        "INVITE" => Some(Method::Invite),
        "MESSAGE" => Some(Method::Message),
        "BYE" => Some(Method::Bye),
        "CANCEL" => Some(Method::Cancel),
        _ => None,
    }
}

#[derive(Clone)]
struct SiphonTransportDispatcher {
    udp_socket: Arc<UdpSocket>,
    policy: Arc<dyn TransportPolicy>,
    pool: Arc<ConnectionPool>,
    tls_pool: Arc<TlsPool>,
    tls_config: Option<std::sync::Arc<TlsClientConfig>>,
}

impl SiphonTransportDispatcher {
    fn new(
        udp_socket: Arc<UdpSocket>,
        policy: Arc<dyn TransportPolicy>,
        pool: Arc<ConnectionPool>,
        tls_pool: Arc<TlsPool>,
        tls_config: Option<std::sync::Arc<TlsClientConfig>>,
    ) -> Self {
        Self {
            udp_socket,
            policy,
            pool,
            tls_pool,
            tls_config,
        }
    }
}

#[async_trait]
impl TransportDispatcher for SiphonTransportDispatcher {
    async fn dispatch(&self, ctx: &TransportContext, payload: Bytes) -> Result<()> {
        let desired = to_sip_transport(ctx.transport);
        let selected = self
            .policy
            .choose(desired, payload.len(), matches!(ctx.transport, TransportKind::Tls));
        let target = match selected {
            sip_transport::TransportKind::Tcp | sip_transport::TransportKind::Tls
                if ctx.stream.is_none() =>
            {
                warn!(
                    ?selected,
                    ?desired,
                    peer = %ctx.peer,
                    "policy requested stream transport but no stream available; falling back"
                );
                desired
            }
            other => other,
        };

        match target {
            sip_transport::TransportKind::Udp => {
                send_udp(self.udp_socket.as_ref(), &ctx.peer, &payload).await?;
            }
            sip_transport::TransportKind::Tcp => {
                if let Some(writer) = &ctx.stream {
                    send_stream(target, writer, payload).await?;
                } else {
                    self.pool.send_tcp(ctx.peer, payload).await?;
                }
            }
            sip_transport::TransportKind::Tls => {
                if let Some(writer) = &ctx.stream {
                    send_stream(target, writer, payload).await?;
                } else {
                    let cfg = self
                        .tls_config
                        .clone()
                        .ok_or_else(|| anyhow!("tls client config missing"))?;
                    let server_name = ctx.peer.ip().to_string();
                    self.tls_pool
                        .send_tls(ctx.peer, server_name, cfg, payload)
                        .await?;
                }
            }
        }
        Ok(())
    }
}

struct ClientDialogState {
    request: Request,
    invite_cseq: u32,
    next_cseq: u32,
    route_set: Vec<SmolStr>,
    remote_target: SipUri,
    transport: TransportContext,
}

impl ClientDialogState {
    fn new(request: Request, invite_cseq: u32, transport: TransportContext) -> Self {
        let route_set = request
            .headers
            .get_all("Route")
            .map(|h| h.clone())
            .collect::<Vec<_>>();
        Self {
            next_cseq: invite_cseq.saturating_add(1),
            invite_cseq,
            route_set,
            // For SIP dialogs, remote target should be a SIP URI
            remote_target: request.start.uri.as_sip()
                .expect("Dialog requires SIP URI")
                .clone(),
            transport,
            request,
        }
    }
}

struct SiphonClientTransactionUser {
    dispatcher: Arc<dyn TransportDispatcher>,
    dialogs: DashMap<TransactionKey, ClientDialogState>,
}

impl SiphonClientTransactionUser {
    fn new(dispatcher: Arc<dyn TransportDispatcher>) -> Self {
        Self {
            dispatcher,
            dialogs: DashMap::new(),
        }
    }

    fn register_request(&self, key: TransactionKey, request: Request, ctx: TransportContext) {
        let invite_cseq = parse_cseq_number(&request.headers).unwrap_or(1);
        self.dialogs
            .insert(key, ClientDialogState::new(request, invite_cseq, ctx));
    }

    fn remove_request(&self, key: &TransactionKey) {
        self.dialogs.remove(key);
    }

    async fn transmit(&self, ctx: &TransportContext, request: Request) {
        let payload = serialize_request(&request);
        if let Err(e) = self.dispatcher.dispatch(ctx, payload).await {
            warn!(error = %e, peer = %ctx.peer, "failed to transmit client request");
        }
    }
}

#[async_trait]
impl ClientTransactionUser for SiphonClientTransactionUser {
    async fn on_provisional(&self, key: &TransactionKey, response: &Response) {
        info!(
            branch = %key.branch,
            code = response.start.code,
            reason = %response.start.reason,
            "client transaction provisional response"
        );
    }

    async fn on_final(&self, key: &TransactionKey, response: &Response) {
        info!(
            branch = %key.branch,
            code = response.start.code,
            reason = %response.start.reason,
            "client transaction final response"
        );
    }

    async fn on_terminated(&self, key: &TransactionKey, reason: &str) {
        self.remove_request(key);
        info!(
            branch = %key.branch,
            method = ?key.method,
            reason,
            "client transaction terminated"
        );
    }

    async fn send_ack(
        &self,
        key: &TransactionKey,
        response: Response,
        ctx: &TransportContext,
        is_2xx: bool,
    ) {
        if let Some(mut entry) = self.dialogs.get_mut(key) {
            if let Some((request, target_uri)) =
                build_ack_from_state(entry.value_mut(), &response, is_2xx)
            {
                let ctx_override = build_transport_context(entry.value(), ctx, &target_uri);
                entry.value_mut().transport.peer = ctx_override.peer;
                entry.value_mut().transport.stream = ctx_override.stream.clone();
                drop(entry);
                info!(
                    branch = %key.branch,
                    code = response.start.code,
                    peer = %ctx_override.peer,
                    "sending ACK (is_2xx={})",
                    is_2xx
                );
                self.transmit(&ctx_override, request).await;
            } else {
                warn!(
                    branch = %key.branch,
                    "missing dialog state; unable to build ACK"
                );
            }
        } else {
            warn!(
                branch = %key.branch,
                "client transaction not found while sending ACK"
            );
        }
    }

    async fn send_prack(&self, key: &TransactionKey, response: Response, ctx: &TransportContext) {
        if let Some(mut entry) = self.dialogs.get_mut(key) {
            if let Some((request, target_uri)) =
                build_prack_from_state(entry.value_mut(), &response)
            {
                let ctx_override = build_transport_context(entry.value(), ctx, &target_uri);
                entry.value_mut().transport.peer = ctx_override.peer;
                entry.value_mut().transport.stream = ctx_override.stream.clone();
                drop(entry);
                info!(
                    branch = %key.branch,
                    code = response.start.code,
                    peer = %ctx_override.peer,
                    "sending PRACK"
                );
                self.transmit(&ctx_override, request).await;
            } else {
                warn!(
                    branch = %key.branch,
                    "missing dialog state; unable to build PRACK"
                );
            }
        } else {
            warn!(
                branch = %key.branch,
                "client transaction not found while sending PRACK"
            );
        }
    }

    async fn on_transport_error(&self, key: &TransactionKey) {
        self.remove_request(key);
        warn!(
            branch = %key.branch,
            method = ?key.method,
            "client transaction transport error signalled"
        );
    }
}

fn parse_cseq_number(headers: &Headers) -> Option<u32> {
    let value = header(headers, "CSeq")?;
    let number = value.split_whitespace().next()?;
    number.parse().ok()
}

fn build_ack_from_state(
    state: &mut ClientDialogState,
    response: &Response,
    is_2xx: bool,
) -> Option<(Request, SipUri)> {
    let via = header(&state.request.headers, "Via")?.clone();
    let via_value = if is_2xx {
        let new_branch = generate_branch_id();
        rewrite_branch(via.as_str(), new_branch.as_str())
    } else {
        via.as_str().to_owned()
    };
    let from = header(&state.request.headers, "From")?.clone();
    let to = header(&response.headers, "To")
        .or_else(|| header(&state.request.headers, "To"))
        .cloned()?;
    let call_id = header(&state.request.headers, "Call-ID")?.clone();
    let max_forwards = header(&state.request.headers, "Max-Forwards")
        .cloned()
        .unwrap_or_else(|| SmolStr::new(DEFAULT_MAX_FORWARDS.to_owned()));
    let contact = header(&state.request.headers, "Contact").cloned();

    let mut headers = Headers::new();
    headers.push("Via".into(), SmolStr::new(via_value));
    headers.push("Max-Forwards".into(), max_forwards);
    headers.push("From".into(), from);
    headers.push("To".into(), to);
    headers.push("Call-ID".into(), call_id);
    headers.push(
        "CSeq".into(),
        SmolStr::new(format!("{} ACK", state.invite_cseq)),
    );
    for route in route_headers_for_response(state, response) {
        headers.push("Route".into(), route);
    }
    if let Some(contact) = contact {
        headers.push("Contact".into(), contact);
    }
    headers.push("User-Agent".into(), SmolStr::new(USER_AGENT.to_owned()));

    let target_uri = target_uri_for_response(state, response, is_2xx);

    Some((
        Request::new(
            RequestLine::new(Method::Ack, target_uri.clone()),
            headers,
            Bytes::new(),
        ),
        target_uri,
    ))
}

fn build_prack_from_state(
    state: &mut ClientDialogState,
    response: &Response,
) -> Option<(Request, SipUri)> {
    let rseq = header(&response.headers, "RSeq")?.parse::<u32>().ok()?;
    let via = header(&state.request.headers, "Via")?.clone();
    let from = header(&state.request.headers, "From")?.clone();
    let to = header(&response.headers, "To")
        .or_else(|| header(&state.request.headers, "To"))
        .cloned()?;
    let call_id = header(&state.request.headers, "Call-ID")?.clone();
    let max_forwards = header(&state.request.headers, "Max-Forwards")
        .cloned()
        .unwrap_or_else(|| SmolStr::new(DEFAULT_MAX_FORWARDS.to_owned()));
    let contact = header(&state.request.headers, "Contact").cloned();

    let cseq = state.next_cseq;
    state.next_cseq = state.next_cseq.saturating_add(1);

    let mut headers = Headers::new();
    headers.push("Via".into(), via);
    headers.push("Max-Forwards".into(), max_forwards);
    headers.push("From".into(), from);
    headers.push("To".into(), to);
    headers.push("Call-ID".into(), call_id);
    headers.push("CSeq".into(), SmolStr::new(format!("{} PRACK", cseq)));
    for route in route_headers_for_response(state, response) {
        headers.push("Route".into(), route);
    }
    headers.push(
        "RAck".into(),
        SmolStr::new(format!(
            "{} {} {}",
            rseq,
            state.invite_cseq,
            state.request.start.method.as_str()
        )),
    );
    if let Some(contact) = contact {
        headers.push("Contact".into(), contact);
    }
    headers.push("User-Agent".into(), SmolStr::new(USER_AGENT.to_owned()));

    let target_uri = target_uri_for_response(state, response, false);

    Some((
        Request::new(
            RequestLine::new(Method::Prack, target_uri.clone()),
            headers,
            Bytes::new(),
        ),
        target_uri,
    ))
}

fn route_headers_for_response(state: &mut ClientDialogState, response: &Response) -> Vec<SmolStr> {
    let mut record_routes = response
        .headers
        .get_all("Record-Route")
        .map(|h| h.clone())
        .collect::<Vec<_>>();
    if !record_routes.is_empty() {
        record_routes.reverse();
        state.route_set = record_routes.clone();
        return record_routes;
    }
    state.route_set.clone()
}

fn target_uri_for_response(
    state: &mut ClientDialogState,
    response: &Response,
    prefer_contact: bool,
) -> SipUri {
    if prefer_contact {
        if let Some(uri) = extract_contact_uri(&response.headers) {
            state.remote_target = uri.clone();
            return uri;
        }
        if let Some(uri) = extract_contact_uri(&state.request.headers) {
            state.remote_target = uri.clone();
            return uri;
        }
    }
    state.remote_target.clone()
}

fn extract_contact_uri(headers: &Headers) -> Option<SipUri> {
    let value = header(headers, "Contact")?;
    parse_uri_from_header(value.as_str())
}

fn parse_uri_from_header(raw: &str) -> Option<SipUri> {
    let trimmed = raw.trim();
    let candidate = if let Some(start) = trimmed.find('<') {
        let end = trimmed[start + 1..].find('>')?;
        &trimmed[start + 1..start + 1 + end]
    } else {
        trimmed
    };
    SipUri::parse(candidate)
}

fn build_transport_context(
    state: &ClientDialogState,
    base_ctx: &TransportContext,
    target: &SipUri,
) -> TransportContext {
    let mut ctx = base_ctx.clone();
    if ctx.stream.is_none() && state.transport.stream.is_some() {
        ctx.stream = state.transport.stream.clone();
    }
    if let Some(addr) = uri_to_socket_addr(target) {
        ctx.peer = addr;
    }
    ctx
}

fn uri_to_socket_addr(uri: &SipUri) -> Option<SocketAddr> {
    let port = uri.port.unwrap_or(if uri.sips { 5061 } else { 5060 });
    match uri.host.as_str().parse::<IpAddr>() {
        Ok(addr) => Some(SocketAddr::new(addr, port)),
        Err(_) => None,
    }
}

fn rewrite_branch(via: &str, new_branch: &str) -> String {
    let mut segments = via.split(';');
    let mut rebuilt = String::new();
    if let Some(first) = segments.next() {
        rebuilt.push_str(first.trim());
    }
    let mut replaced = false;
    for part in segments {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        rebuilt.push(';');
        if trimmed.to_ascii_lowercase().starts_with("branch=") {
            rebuilt.push_str(&format!("branch={}", new_branch));
            replaced = true;
        } else {
            rebuilt.push_str(trimmed);
        }
    }
    if !replaced {
        rebuilt.push(';');
        rebuilt.push_str(&format!("branch={}", new_branch));
    }
    rebuilt
}

fn random_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
