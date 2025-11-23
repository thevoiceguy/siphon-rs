/// siphond - SIP testing daemon with multiple operational modes
///
/// A Swiss Army knife SIP server for testing and demonstration.

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

mod b2bua_state;
mod config;
mod dispatcher;
mod handlers;
mod proxy_state;
mod services;
mod transport;

use config::{AuthConfig, DaemonConfig, DaemonMode, FeatureFlags, RegistrarConfig, SdpProfile};
use dispatcher::RequestDispatcher;
use services::ServiceRegistry;
use sip_observe::{set_transport_metrics, TracingTransportMetrics};
use sip_transaction::TransactionManager;
use sip_transport::InboundPacket;
use transport::start_transports;

/// SIP testing daemon - Swiss Army knife for SIP protocol testing
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Operational mode
    #[arg(long, default_value = "minimal", value_parser = parse_mode)]
    mode: DaemonMode,

    /// UDP bind address
    #[arg(long, default_value = "0.0.0.0:5060")]
    udp_bind: String,

    /// TCP bind address
    #[arg(long, default_value = "0.0.0.0:5060")]
    tcp_bind: String,

    /// TLS/SIPS bind address
    #[arg(long, default_value = "0.0.0.0:5061")]
    sips_bind: String,

    /// TLS certificate path (PEM format)
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS private key path (PEM format)
    #[arg(long)]
    tls_key: Option<String>,

    /// Local SIP URI (used in From/Contact headers)
    #[arg(long, default_value = "sip:siphond@localhost")]
    local_uri: String,

    /// User-Agent header value
    #[arg(long, default_value = "siphond/0.2-refactored")]
    user_agent: String,

    // Feature flags
    /// Enable Digest authentication
    #[arg(long)]
    auth: bool,

    /// Authentication realm
    #[arg(long, default_value = "siphond.local")]
    auth_realm: String,

    /// Path to users file (JSON format: {"user": "password"})
    #[arg(long)]
    auth_users: Option<std::path::PathBuf>,

    /// Automatically accept incoming calls
    #[arg(long, default_value = "true", value_parser = clap::value_parser!(bool))]
    auto_accept_calls: bool,

    /// Automatically accept registrations
    #[arg(long, default_value = "true", value_parser = clap::value_parser!(bool))]
    auto_accept_registrations: bool,

    /// Automatically accept subscriptions
    #[arg(long, default_value = "true", value_parser = clap::value_parser!(bool))]
    auto_accept_subscriptions: bool,

    /// SDP profile for media handling
    #[arg(long, default_value = "audio-only", value_parser = parse_sdp_profile)]
    sdp_profile: SdpProfile,

    /// Enable PRACK (reliable provisional responses)
    #[arg(long, default_value = "true", value_parser = clap::value_parser!(bool))]
    enable_prack: bool,

    /// Enable REFER (call transfer)
    #[arg(long, default_value = "true", value_parser = clap::value_parser!(bool))]
    enable_refer: bool,

    // Registrar configuration
    /// Default registration expiry (seconds)
    #[arg(long, default_value = "3600")]
    reg_default_expiry: u32,

    /// Minimum registration expiry (seconds)
    #[arg(long, default_value = "60")]
    reg_min_expiry: u32,

    /// Maximum registration expiry (seconds)
    #[arg(long, default_value = "86400")]
    reg_max_expiry: u32,
}

fn parse_mode(s: &str) -> Result<DaemonMode, String> {
    match s.to_lowercase().as_str() {
        "minimal" => Ok(DaemonMode::Minimal),
        "full-uas" | "fulluas" | "full" => Ok(DaemonMode::FullUas),
        "registrar" => Ok(DaemonMode::Registrar),
        "proxy" => Ok(DaemonMode::Proxy),
        "b2bua" => Ok(DaemonMode::B2bua),
        "call-server" | "callserver" | "calls" => Ok(DaemonMode::CallServer),
        "subscription-server" | "subscriptionserver" | "subscriptions" => {
            Ok(DaemonMode::SubscriptionServer)
        }
        "interactive" => Ok(DaemonMode::Interactive),
        _ => Err(format!(
            "Invalid mode: {}. Valid options: minimal, full-uas, registrar, proxy, b2bua, call-server, subscription-server, interactive",
            s
        )),
    }
}

fn parse_sdp_profile(s: &str) -> Result<SdpProfile, String> {
    match s.to_lowercase().as_str() {
        "none" => Ok(SdpProfile::None),
        "audio-only" | "audio" => Ok(SdpProfile::AudioOnly),
        "audio-video" | "av" => Ok(SdpProfile::AudioVideo),
        path => Ok(SdpProfile::Custom(std::path::PathBuf::from(path))),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Set up observability
    set_transport_metrics(Arc::new(TracingTransportMetrics::default()));

    let args = Args::parse();

    // Build daemon configuration
    let config = DaemonConfig {
        mode: args.mode.clone(),
        features: FeatureFlags {
            authentication: args.auth,
            auto_accept_calls: args.auto_accept_calls,
            auto_accept_registrations: args.auto_accept_registrations,
            auto_accept_subscriptions: args.auto_accept_subscriptions,
            enable_prack: args.enable_prack,
            enable_refer: args.enable_refer,
            enable_session_timers: false,
        },
        sdp_profile: args.sdp_profile,
        auth: AuthConfig {
            realm: args.auth_realm,
            algorithm: "SHA-256".to_string(),
            qop: "auth".to_string(),
            nonce_ttl_secs: 3600,
            users_file: args.auth_users,
        },
        registrar: RegistrarConfig {
            default_expiry: args.reg_default_expiry,
            min_expiry: args.reg_min_expiry,
            max_expiry: args.reg_max_expiry,
        },
        local_uri: args.local_uri,
        user_agent: args.user_agent,
    };

    info!(
        mode = ?config.mode,
        udp = %args.udp_bind,
        tcp = %args.tcp_bind,
        tls = %args.sips_bind,
        "siphond starting"
    );

    print_mode_info(&config);

    // Create service registry
    let services = Arc::new(ServiceRegistry::new(config));

    // Create request dispatcher
    let dispatcher = Arc::new(RequestDispatcher::new(services.clone()));

    // Create transaction manager (note: we'll create transport dispatcher separately)
    let (tx, mut rx) = mpsc::channel::<InboundPacket>(1024);

    // Start transport layers
    let transport_dispatcher = start_transports(
        &args.udp_bind,
        &args.tcp_bind,
        &args.sips_bind,
        args.tls_cert.as_deref(),
        args.tls_key.as_deref(),
        tx.clone(),
    )
    .await?;

    let transaction_mgr = Arc::new(TransactionManager::new(transport_dispatcher));

    // Set transaction manager in service registry for sending requests
    if let Err(_) = services.set_transaction_manager(transaction_mgr.clone()) {
        panic!("Failed to set transaction manager - already initialized");
    }

    info!("siphond ready - listening for requests");

    // Set up graceful shutdown signal handling
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to register SIGTERM handler");

    // Main event loop with graceful shutdown
    loop {
        tokio::select! {
            Some(packet) = rx.recv() => {
                handle_packet(&transaction_mgr, &dispatcher, &services, packet).await;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                break;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown...");
                break;
            }
        }
    }

    info!("Shutdown complete");
    Ok(())
}

/// Create an ACK request for B2BUA callee leg
///
/// Constructs an ACK based on the stored outgoing INVITE, using the callee's To-tag
/// from the 200 OK response. Preserves any SDP body from caller's ACK (late offer).
async fn create_b2bua_ack(
    call_leg: &crate::b2bua_state::CallLegPair,
    caller_ack: &sip_core::Request,
) -> sip_core::Request {
    use sip_core::{Headers, Method, Request, RequestLine};
    use sip_transaction::generate_branch_id;
    use smol_str::SmolStr;

    let mut headers = Headers::new();

    // Via - new branch for this ACK
    let branch = generate_branch_id();
    headers.push(
        SmolStr::new("Via"),
        SmolStr::new(format!("SIP/2.0/TCP placeholder;branch={}", branch)),
    );

    // From - same as our outgoing INVITE
    if let Some(from) = call_leg.outgoing_invite.headers.get("From") {
        headers.push(SmolStr::new("From"), from.clone());
    }

    // To - with callee's tag from 200 OK
    if let Some(to_tag) = &call_leg.callee_to_tag {
        // Extract To header from outgoing INVITE and add tag
        if let Some(to) = call_leg.outgoing_invite.headers.get("To") {
            let to_with_tag = format!("{};tag={}", to.as_str(), to_tag);
            headers.push(SmolStr::new("To"), SmolStr::new(to_with_tag));
        }
    } else {
        // Shouldn't happen - we should have callee_to_tag after 200 OK
        if let Some(to) = call_leg.outgoing_invite.headers.get("To") {
            headers.push(SmolStr::new("To"), to.clone());
        }
    }

    // Call-ID - same as our outgoing INVITE
    headers.push(
        SmolStr::new("Call-ID"),
        SmolStr::new(&call_leg.outgoing_call_id),
    );

    // CSeq - same number as INVITE, but ACK method
    if let Some(cseq) = call_leg.outgoing_invite.headers.get("CSeq") {
        if let Some((num, _)) = cseq.split_once(' ') {
            headers.push(SmolStr::new("CSeq"), SmolStr::new(format!("{} ACK", num)));
        }
    }

    // Max-Forwards
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));

    // Copy SDP body from caller's ACK if present (late offer scenario)
    let body = if !caller_ack.body.is_empty() {
        if let Some(content_type) = caller_ack.headers.get("Content-Type") {
            headers.push(SmolStr::new("Content-Type"), content_type.clone());
        }
        let content_length = caller_ack.body.len().to_string();
        headers.push(SmolStr::new("Content-Length"), SmolStr::new(content_length));
        caller_ack.body.clone()
    } else {
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));
        bytes::Bytes::new()
    };

    // Request-URI should be callee's contact (from 200 OK Contact header)
    // For now, use the callee_contact from call leg
    Request::new(
        RequestLine::new(Method::Ack, call_leg.callee_contact.clone()),
        headers,
        body,
    )
}

/// Handle an incoming packet from the transport layer
async fn handle_packet(
    transaction_mgr: &Arc<TransactionManager>,
    dispatcher: &Arc<RequestDispatcher>,
    services: &Arc<ServiceRegistry>,
    packet: InboundPacket,
) {
    use sip_core::Method;
    use sip_parse::{parse_request, parse_response};
    use sip_transaction::{request_branch_id, TransactionKey, TransportContext};

    // Try parsing as a request
    if let Some(req) = parse_request(&packet.payload) {
        // Special handling for ACK (doesn't create a transaction)
        if req.start.method == Method::Ack {
            // B2BUA MODE: Bridge ACK from caller to callee
            if services.config.enable_b2bua() {
                if let Some(call_id_header) = req.headers.get("Call-ID") {
                    let incoming_call_id = call_id_header.to_string();

                    // Look up call leg by incoming Call-ID (caller's Call-ID)
                    if let Some(call_leg) = services.b2bua_state.find_call_leg_by_incoming(&incoming_call_id) {
                        tracing::info!(
                            incoming_call_id = %incoming_call_id,
                            outgoing_call_id = %call_leg.outgoing_call_id,
                            "B2BUA: Bridging ACK from caller to callee"
                        );

                        // Create ACK for callee using stored outgoing INVITE
                        let callee_ack = create_b2bua_ack(&call_leg, &req).await;

                        // Send ACK to callee
                        let callee_addr = format!(
                            "{}:{}",
                            call_leg.callee_contact.host,
                            call_leg.callee_contact.port.unwrap_or(5060)
                        );

                        if let Ok(addr) = callee_addr.parse::<std::net::SocketAddr>() {
                            let payload = sip_parse::serialize_request(&callee_ack);
                            if let Err(e) = sip_transport::send_tcp(&addr, &payload).await {
                                tracing::error!(
                                    error = %e,
                                    callee = %callee_addr,
                                    "B2BUA: Failed to send ACK to callee"
                                );
                            } else {
                                tracing::info!(
                                    callee = %callee_addr,
                                    "B2BUA: ACK sent to callee successfully"
                                );
                            }
                        } else {
                            tracing::error!(
                                callee = %callee_addr,
                                "B2BUA: Invalid callee address"
                            );
                        }
                    }
                }
            }

            // Always notify transaction manager about ACK
            if let Some(branch) = request_branch_id(&req) {
                let key = TransactionKey {
                    branch,
                    method: Method::Invite,
                    is_server: true,
                };
                transaction_mgr.ack_received(&key).await;
            }
            return;
        }

        let ctx = TransportContext::new(
            map_transport(packet.transport),
            packet.peer,
            packet.stream.clone(),
        );

        let handle = transaction_mgr.receive_request(req.clone(), ctx.clone()).await;

        // Dispatch to appropriate handler
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            dispatcher.dispatch(&req, handle, &ctx).await;
        });
        return;
    }

    // Try parsing as a response
    if let Some(response) = parse_response(&packet.payload) {
        // Check if this response belongs to a B2BUA call leg
        if services.config.enable_b2bua() {
            if let Some(call_id_header) = response.headers.get("Call-ID") {
                let call_id = call_id_header.to_string();

                // Look up B2BUA call leg by outgoing Call-ID
                if let Some(leg_pair) = services.b2bua_state.find_call_leg(&call_id) {
                    tracing::info!(
                        outgoing_call_id = %call_id,
                        incoming_call_id = %leg_pair.incoming_call_id,
                        status_code = response.start.code,
                        "B2BUA: Relaying response from callee to caller"
                    );

                    // Send response through channel to relay task
                    if let Err(e) = leg_pair.response_tx.send(response.clone()) {
                        tracing::error!(
                            outgoing_call_id = %call_id,
                            error = %e,
                            "B2BUA: Failed to send response through channel - receiver dropped"
                        );
                    } else {
                        tracing::debug!(
                            status_code = response.start.code,
                            "B2BUA: Response queued for relay to caller"
                        );
                    }

                    // Note: Call leg cleanup is handled by the spawned task after transformation
                    // to avoid race conditions

                    // Also pass to transaction manager for UAC transaction state management
                    transaction_mgr.receive_response(response).await;
                    return;
                }
            }
        }

        // Not a B2BUA response, handle normally
        transaction_mgr.receive_response(response).await;
        return;
    }

    // Check for SIP keep-alive packets (RFC 5626)
    // Keep-alives are CRLF sequences: single CRLF (2 bytes) or double CRLF (4 bytes)
    if is_keepalive(&packet.payload) {
        tracing::trace!(
            peer = %packet.peer,
            transport = ?packet.transport,
            "SIP keep-alive packet received (silently ignored per RFC 5626)"
        );
        return;
    }

    tracing::warn!(
        peer = %packet.peer,
        transport = ?packet.transport,
        len = packet.payload.len(),
        "Unparsable packet received"
    );
}

/// Check if packet is a SIP keep-alive (CRLF sequence per RFC 5626)
fn is_keepalive(payload: &[u8]) -> bool {
    // RFC 5626: Keep-alives are CRLF sequences
    // Single CRLF: 0x0D 0x0A (2 bytes)
    // Double CRLF: 0x0D 0x0A 0x0D 0x0A (4 bytes)
    matches!(
        payload,
        b"\r\n" | b"\r\n\r\n"
    )
}

fn map_transport(kind: sip_transport::TransportKind) -> sip_transaction::TransportKind {
    match kind {
        sip_transport::TransportKind::Udp => sip_transaction::TransportKind::Udp,
        sip_transport::TransportKind::Tcp => sip_transaction::TransportKind::Tcp,
        sip_transport::TransportKind::Tls => sip_transaction::TransportKind::Tls,
        sip_transport::TransportKind::Sctp => sip_transaction::TransportKind::Tcp,
        sip_transport::TransportKind::TlsSctp => sip_transaction::TransportKind::Tls,
    }
}

/// Print informational message about the current mode
fn print_mode_info(config: &DaemonConfig) {
    use DaemonMode::*;

    match config.mode {
        Minimal => {
            info!("Mode: MINIMAL - Only OPTIONS requests will be handled");
        }
        FullUas => {
            info!("Mode: FULL UAS - All SIP methods enabled");
            info!(
                "  ├─ INVITE: {}",
                if config.features.auto_accept_calls {
                    "Auto-accept"
                } else {
                    "Reject"
                }
            );
            info!(
                "  ├─ REGISTER: {}",
                if config.features.auto_accept_registrations {
                    "Auto-accept"
                } else {
                    "Reject"
                }
            );
            info!(
                "  ├─ SUBSCRIBE: {}",
                if config.features.auto_accept_subscriptions {
                    "Auto-accept"
                } else {
                    "Reject"
                }
            );
            info!("  ├─ REFER: {}", if config.features.enable_refer { "Enabled" } else { "Disabled" });
            info!("  └─ PRACK: {}", if config.features.enable_prack { "Enabled" } else { "Disabled" });
        }
        Registrar => {
            info!("Mode: REGISTRAR - Registration server");
            info!("  ├─ Default expiry: {}s", config.registrar.default_expiry);
            info!("  ├─ Min expiry: {}s", config.registrar.min_expiry);
            info!("  ├─ Max expiry: {}s", config.registrar.max_expiry);
            info!(
                "  └─ Authentication: {}",
                if config.features.authentication {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
        }
        Proxy => {
            info!("Mode: PROXY - Stateful proxy with location service");
            info!("  ├─ Registration: Enabled");
            info!("  ├─ Call forwarding: Enabled");
            info!("  ├─ Default expiry: {}s", config.registrar.default_expiry);
            info!(
                "  └─ Authentication: {}",
                if config.features.authentication {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
        }
        B2bua => {
            info!("Mode: B2BUA - Back-to-Back User Agent");
            info!("  ├─ Registration: Enabled");
            info!("  ├─ Call bridging: Enabled");
            info!("  ├─ Default expiry: {}s", config.registrar.default_expiry);
            info!(
                "  └─ Authentication: {}",
                if config.features.authentication {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
        }
        CallServer => {
            info!("Mode: CALL SERVER - INVITE/BYE only");
            info!(
                "  ├─ Auto-accept: {}",
                if config.features.auto_accept_calls {
                    "Yes"
                } else {
                    "No"
                }
            );
            info!("  └─ SDP: {:?}", config.sdp_profile);
        }
        SubscriptionServer => {
            info!("Mode: SUBSCRIPTION SERVER - SUBSCRIBE/NOTIFY");
            info!(
                "  └─ Auto-accept: {}",
                if config.features.auto_accept_subscriptions {
                    "Yes"
                } else {
                    "No"
                }
            );
        }
        Interactive => {
            info!("Mode: INTERACTIVE - Manual control");
            info!("  └─ (Interactive mode not yet implemented)");
        }
    }

    if config.requires_auth() {
        info!("Authentication realm: {}", config.auth.realm);
    }
}
