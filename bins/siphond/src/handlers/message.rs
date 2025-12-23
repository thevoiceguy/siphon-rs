/// MESSAGE request handler.
///
/// Accepts MESSAGE requests for mid-dialog or out-of-dialog testing.
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::info;

use super::RequestHandler;
use crate::{proxy_utils, services::ServiceRegistry};

pub struct MessageHandler;

impl MessageHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequestHandler for MessageHandler {
    async fn handle(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        services: &ServiceRegistry,
    ) -> Result<()> {
        let call_id = header(&request.headers, "Call-ID")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        if services.config.enable_proxy() {
            proxy_utils::forward_request(
                request,
                services,
                ctx,
                call_id,
                proxy_utils::ProxyForwardOptions {
                    add_record_route: false,
                    rewrite_request_uri: false,
                },
            )
            .await?;
            return Ok(());
        }

        info!(
            call_id,
            len = request.body.len(),
            "Received MESSAGE"
        );

        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    fn method(&self) -> &str {
        "MESSAGE"
    }
}
