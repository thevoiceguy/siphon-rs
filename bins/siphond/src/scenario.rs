// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Scenario runner for scripted SIP flows.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sip_core::{Headers, Method, Request, RequestLine, SipUri};
use sip_transaction::{ClientTransactionUser, TransactionKey, TransportContext, TransportKind};
use sip_uac::UserAgentClient;
use smol_str::SmolStr;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::info;

use crate::services::ServiceRegistry;

#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub steps: Vec<ScenarioStep>,
    pub local_uri: Option<String>,
    pub contact_uri: Option<String>,
    pub default_transport: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScenarioStep {
    Sleep {
        ms: u64,
    },
    Send {
        method: String,
        uri: String,
        headers: Option<Vec<HeaderSpec>>,
        body: Option<String>,
        transport: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
pub struct HeaderSpec {
    pub name: String,
    pub value: String,
}

struct ScenarioTransactionUser {
    uac: UserAgentClient,
    request: Request,
}

#[async_trait]
impl ClientTransactionUser for ScenarioTransactionUser {
    async fn on_provisional(&self, _key: &TransactionKey, _response: &sip_core::Response) {}

    async fn on_final(&self, _key: &TransactionKey, _response: &sip_core::Response) {}

    async fn on_terminated(&self, _key: &TransactionKey, _reason: &str) {}

    async fn send_ack(
        &self,
        _key: &TransactionKey,
        response: sip_core::Response,
        ctx: &TransportContext,
        is_2xx: bool,
    ) {
        if !is_2xx {
            return;
        }
        let ack = self.uac.create_ack(&self.request, &response, None);
        let payload = sip_parse::serialize_request(&ack);

        match ctx.transport {
            TransportKind::Tcp => {
                let _ = sip_transport::send_tcp(&ctx.peer, &payload).await;
            }
            TransportKind::Udp => {
                if let Some(socket) = &ctx.udp_socket {
                    let _ = sip_transport::send_udp(socket.as_ref(), &ctx.peer, &payload).await;
                }
            }
            TransportKind::Ws | TransportKind::Wss => {
                #[cfg(feature = "ws")]
                {
                    if let Some(ws_uri) = ctx.ws_uri.as_deref() {
                        let data = bytes::Bytes::from(payload.to_vec());
                        if ctx.transport == TransportKind::Wss {
                            let _ = sip_transport::send_wss(ws_uri, data).await;
                        } else {
                            let _ = sip_transport::send_ws(ws_uri, data).await;
                        }
                    }
                }
            }
            TransportKind::Tls => {}
            _ => {}
        }
    }

    async fn send_prack(
        &self,
        _key: &TransactionKey,
        _response: sip_core::Response,
        _ctx: &TransportContext,
    ) {
    }

    async fn on_transport_error(&self, _key: &TransactionKey) {}
}

fn parse_transport(value: Option<&str>) -> TransportKind {
    match value.unwrap_or("udp").to_ascii_lowercase().as_str() {
        "tcp" => TransportKind::Tcp,
        "tls" => TransportKind::Tls,
        "ws" => TransportKind::Ws,
        "wss" => TransportKind::Wss,
        "udp" => TransportKind::Udp,
        _ => TransportKind::Udp,
    }
}

fn build_request(
    method: Method,
    uri: SipUri,
    local_uri: &SipUri,
    contact_uri: &SipUri,
    body: Option<&str>,
    headers: &[HeaderSpec],
    cseq: u32,
) -> Request {
    let mut hdrs = Headers::new();
    let _ = hdrs.push(
        SmolStr::new("Via"),
        SmolStr::new("SIP/2.0/UDP scenario;branch=z9hG4bKscenario"),
    );
    let _ = hdrs.push(
        SmolStr::new("From"),
        SmolStr::new(format!("<{}>;tag=scenario", local_uri.as_str())),
    );
    let _ = hdrs.push(
        SmolStr::new("To"),
        SmolStr::new(format!("<{}>", uri.as_str())),
    );
    let _ = hdrs.push(SmolStr::new("Call-ID"), SmolStr::new("scenario-call"));
    let _ = hdrs.push(
        SmolStr::new("CSeq"),
        SmolStr::new(format!("{} {}", cseq, method.as_str())),
    );
    let _ = hdrs.push(
        SmolStr::new("Contact"),
        SmolStr::new(format!("<{}>", contact_uri.as_str())),
    );
    let _ = hdrs.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));

    for header in headers {
        let _ = hdrs.push(&header.name, &header.value);
    }

    let request_body = if let Some(content) = body {
        let _ = hdrs.push(
            SmolStr::new("Content-Length"),
            SmolStr::new(content.len().to_string()),
        );
        bytes::Bytes::from(content.as_bytes().to_vec())
    } else {
        let _ = hdrs.push(SmolStr::new("Content-Length"), SmolStr::new("0"));
        bytes::Bytes::new()
    };

    Request::new(RequestLine::new(method, uri), hdrs, request_body).expect("valid scenario request")
}

pub async fn run_scenario(path: &Path, services: &ServiceRegistry) -> Result<()> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .map(|e| e == "yaml" || e == "yml")
        .unwrap_or(false)
    {
        return Err(anyhow!("YAML scenarios are not supported in this build"));
    }

    let scenario: Scenario = serde_json::from_str(&contents)?;

    let local_uri = scenario
        .local_uri
        .as_deref()
        .unwrap_or(&services.config.local_uri);
    let contact_uri = scenario
        .contact_uri
        .as_deref()
        .unwrap_or(&services.config.local_uri);

    let local_uri = SipUri::parse(local_uri).map_err(|_| anyhow!("Invalid local_uri"))?;
    let contact_uri = SipUri::parse(contact_uri).map_err(|_| anyhow!("Invalid contact_uri"))?;

    let Some(transaction_mgr) = services.transaction_mgr.get() else {
        return Err(anyhow!("Transaction manager not available for scenario"));
    };

    let default_transport = scenario.default_transport.clone();
    let mut cseq = 1;
    for step in scenario.steps {
        match step {
            ScenarioStep::Sleep { ms } => {
                sleep(Duration::from_millis(ms)).await;
            }
            ScenarioStep::Send {
                method,
                uri,
                headers,
                body,
                transport,
            } => {
                let method =
                    Method::from_token(&method).map_err(|err| anyhow!("Invalid method: {err}"))?;
                let uri = SipUri::parse(&uri).map_err(|_| anyhow!("Invalid URI: {}", uri))?;
                let request = build_request(
                    method.clone(),
                    uri.clone(),
                    &local_uri,
                    &contact_uri,
                    body.as_deref(),
                    &headers.unwrap_or_default(),
                    cseq,
                );

                let transport =
                    parse_transport(transport.as_deref().or(default_transport.as_deref()));
                let target_addr = format!("{}:{}", uri.host(), uri.port().unwrap_or(5060))
                    .parse::<std::net::SocketAddr>()?;
                let ws_uri = match transport {
                    TransportKind::Ws => {
                        Some(format!("ws://{}:{}", uri.host(), target_addr.port()))
                    }
                    TransportKind::Wss => {
                        Some(format!("wss://{}:{}", uri.host(), target_addr.port()))
                    }
                    _ => None,
                };
                let ctx = TransportContext::new(transport, target_addr, None)
                    .with_ws_uri(ws_uri)
                    .with_udp_socket(services.udp_socket.get().cloned());

                info!(
                    method = method.as_str(),
                    target = %uri.as_str(),
                    "Scenario sending request"
                );

                let uac = UserAgentClient::new(local_uri.clone(), contact_uri.clone());
                let tu = Arc::new(ScenarioTransactionUser {
                    uac,
                    request: request.clone(),
                });

                transaction_mgr
                    .start_client_transaction(request, ctx, tu)
                    .await?;

                cseq = cseq.saturating_add(1);
            }
        }
    }

    Ok(())
}
