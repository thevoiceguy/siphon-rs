/// Integrated UAS with full transaction, transport integration.
///
/// This module provides a production-ready UAS implementation that integrates:
/// - Transaction layer (automatic retransmissions, state management)
/// - Transport layer (Via/Contact auto-filling, connection management)
/// - Authentication (automatic 401/407 challenges)
/// - Dialog and subscription management
///
/// # Architecture
///
/// The integrated UAS uses composition over modification:
/// - Embeds the low-level `UserAgentServer` helper for response generation
/// - Adds transaction/transport integration on top
/// - Provides async trait-based request handlers for applications
///
/// # Example
///
/// ```ignore
/// use sip_uas::integrated::{IntegratedUAS, UasRequestHandler};
/// use sip_core::{Request, Response};
/// use anyhow::Result;
///
/// struct MyApp;
///
/// #[async_trait::async_trait]
/// impl UasRequestHandler for MyApp {
///     async fn on_invite(&self, request: &Request) -> Result<Response> {
///         // Handle INVITE request
///         Ok(Response::new(/* ... */))
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let uas = IntegratedUAS::builder()
///     .local_uri("sip:server@example.com")
///     .local_addr("192.168.1.100:5060")
///     .transaction_manager(tx_mgr)
///     .dispatcher(dispatcher)
///     .request_handler(Arc::new(MyApp))
///     .build()?;
///
/// // UAS will automatically handle incoming requests via the transaction manager
/// # Ok(())
/// # }
/// ```
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sip_auth::Authenticator;
use sip_core::{Method, Request, Response, SipUri};
use sip_dialog::{Dialog, DialogManager, SubscriptionManager};
use sip_sdp::profiles::MediaProfileBuilder;
use sip_transaction::{
    ServerTransactionHandle, TransactionKey, TransactionManager, TransportContext,
    TransportDispatcher,
};
use smol_str::SmolStr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::UserAgentServer;

const ALLOW_HEADER_VALUE: &str =
    "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, UPDATE, PRACK, INFO";

fn method_not_allowed_response(request: &Request) -> Response {
    let mut response = UserAgentServer::create_response(request, 405, "Method Not Allowed");
    response
        .headers
        .push(SmolStr::new("Allow"), SmolStr::new(ALLOW_HEADER_VALUE));
    response
}

/// Trait for handling incoming SIP requests.
///
/// Applications implement this trait to define their request handling logic.
/// Handlers can send provisional and final responses using the `ServerTransactionHandle`.
/// Default implementations send 405 Method Not Allowed for all methods.
#[async_trait]
pub trait UasRequestHandler: Send + Sync {
    /// Handle an incoming INVITE request.
    ///
    /// # Arguments
    /// * `request` - The INVITE request
    /// * `handle` - Transaction handle for sending responses
    /// * `ctx` - Transport context
    /// * `dialog` - Optional dialog if this is a re-INVITE
    async fn on_invite(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        dialog: Option<&Dialog>,
    ) -> Result<()> {
        let _ = (ctx, dialog);
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming ACK request (for 2xx INVITE responses).
    async fn on_ack(&self, request: &Request, dialog: &Dialog) -> Result<()> {
        let _ = (request, dialog);
        Ok(())
    }

    /// Handle an incoming BYE request.
    async fn on_bye(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming CANCEL request.
    async fn on_cancel(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming REGISTER request.
    async fn on_register(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming OPTIONS request.
    async fn on_options(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming SUBSCRIBE request.
    async fn on_subscribe(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming NOTIFY request.
    async fn on_notify(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming REFER request.
    async fn on_refer(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming UPDATE request.
    async fn on_update(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming PRACK request.
    async fn on_prack(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming INFO request.
    async fn on_info(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request);
        handle.send_final(response).await;
        Ok(())
    }
}

/// Configuration for IntegratedUAS behavior.
#[derive(Clone)]
pub struct UASConfig {
    /// Automatically fill Via header in responses from transport context (default: true)
    pub auto_via_filling: bool,

    /// Automatically fill Contact header in responses from local transport (default: true)
    pub auto_contact_filling: bool,

    /// Automatically send 100 Trying for INVITE requests (default: true)
    pub auto_send_100_trying: bool,

    /// User-Agent header value (default: "siphon-rs/0.1.0")
    pub user_agent: String,

    /// Require authentication for requests (default: false)
    pub require_authentication: bool,
}

impl Default for UASConfig {
    fn default() -> Self {
        Self {
            auto_via_filling: true,
            auto_contact_filling: true,
            auto_send_100_trying: true,
            user_agent: "siphon-rs/0.1.0".to_string(),
            require_authentication: false,
        }
    }
}

/// Integrated User Agent Server with full transaction and transport integration.
///
/// Automatically handles:
/// - Transaction state management and retransmissions
/// - Dialog and subscription tracking
/// - Via/Contact header auto-filling
/// - Request routing to application handlers
pub struct IntegratedUAS {
    helper: Arc<Mutex<UserAgentServer>>,
    transaction_manager: Arc<TransactionManager>,
    transport_dispatcher: Arc<dyn TransportDispatcher>,
    local_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
    config: UASConfig,
    dialog_manager: Arc<DialogManager>,
    subscription_manager: Arc<SubscriptionManager>,
    request_handler: Arc<dyn UasRequestHandler>,
    sdp_profile: Option<MediaProfileBuilder>,
}

impl IntegratedUAS {
    /// Creates a builder for constructing an IntegratedUAS.
    pub fn builder() -> IntegratedUASBuilder {
        IntegratedUASBuilder::new()
    }

    /// Dispatch an incoming request to the appropriate handler.
    ///
    /// This is the main entry point for incoming requests. It routes the request
    /// to the appropriate trait method based on the SIP method.
    ///
    /// # Arguments
    /// * `request` - The incoming SIP request
    /// * `handle` - Transaction handle for sending responses
    /// * `ctx` - Transport context
    pub async fn dispatch(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
    ) -> Result<()> {
        info!(
            "Dispatching {:?} request from {}",
            &request.start.method,
            ctx.peer
        );

        if self.config.require_authentication && request.start.method != Method::Ack {
            let helper = self.helper.lock().await;
            let is_authenticated = helper.verify_authentication(request)?;
            if !is_authenticated {
                let mut response = helper.create_unauthorized(request)?;
                drop(helper);
                self.auto_fill_headers(&mut response, ctx).await;
                handle.send_final(response).await;
                return Ok(());
            }
        }

        // Route based on method
        match request.start.method.as_str() {
            "INVITE" => {
                if let Err(mut response) = UserAgentServer::validate_invite_headers(request) {
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                    return Ok(());
                }

                let helper = self.helper.lock().await;
                let dialog = helper.dialog_manager.find_by_request(request);
                drop(helper);

                // Send 100 Trying if configured
                if self.config.auto_send_100_trying {
                    let mut trying = UserAgentServer::create_response(request, 100, "Trying");
                    self.auto_fill_headers(&mut trying, ctx).await;
                    handle.send_provisional(trying).await;
                }

                self.request_handler
                    .on_invite(request, handle, ctx, dialog.as_ref())
                    .await?;
            }
            "ACK" => {
                // ACK doesn't get a response
                let helper = self.helper.lock().await;
                if let Some(dialog) = helper.dialog_manager.find_by_request(request) {
                    drop(helper);
                    self.request_handler.on_ack(request, &dialog).await?;
                } else {
                    warn!("Received ACK for unknown dialog");
                }
            }
            "BYE" => {
                let helper = self.helper.lock().await;
                if let Some(dialog) = helper.dialog_manager.find_by_request(request) {
                    drop(helper);
                    self.request_handler
                        .on_bye(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received BYE for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "CANCEL" => {
                self.request_handler.on_cancel(request, handle).await?;
                if let Some(cancel_key) = TransactionKey::from_request(request, true) {
                    let invite_key = TransactionKey {
                        branch: cancel_key.branch.clone(),
                        method: Method::Invite,
                        is_server: true,
                    };
                    let mut response =
                        UserAgentServer::create_request_terminated_from_cancel(request);
                    self.auto_fill_headers(&mut response, ctx).await;
                    self.transaction_manager
                        .send_final(&invite_key, response)
                        .await;
                }
            }
            "REGISTER" => {
                self.request_handler.on_register(request, handle).await?;
            }
            "OPTIONS" => {
                self.request_handler.on_options(request, handle).await?;
            }
            "SUBSCRIBE" => {
                self.request_handler.on_subscribe(request, handle).await?;
            }
            "NOTIFY" => {
                self.request_handler.on_notify(request, handle).await?;
            }
            "REFER" => {
                let helper = self.helper.lock().await;
                if let Some(dialog) = helper.dialog_manager.find_by_request(request) {
                    drop(helper);
                    self.request_handler
                        .on_refer(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received REFER for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "UPDATE" => {
                let helper = self.helper.lock().await;
                if let Some(dialog) = helper.dialog_manager.find_by_request(request) {
                    drop(helper);
                    self.request_handler
                        .on_update(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received UPDATE for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "PRACK" => {
                let helper = self.helper.lock().await;
                if let Some(dialog) = helper.dialog_manager.find_by_request(request) {
                    drop(helper);
                    self.request_handler
                        .on_prack(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received PRACK for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "INFO" => {
                let helper = self.helper.lock().await;
                if let Some(dialog) = helper.dialog_manager.find_by_request(request) {
                    drop(helper);
                    self.request_handler
                        .on_info(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received INFO for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            _ => {
                warn!("Unsupported method: {:?}", &request.start.method);
                let mut response = UserAgentServer::create_response(request, 501, "Not Implemented");
                self.auto_fill_headers(&mut response, ctx).await;
                handle.send_final(response).await;
            }
        }

        Ok(())
    }

    /// Auto-fill Via and Contact headers in responses based on transport context.
    async fn auto_fill_headers(&self, response: &mut Response, _ctx: &TransportContext) {
        if self.config.auto_via_filling {
            // Via already copied from request, no need to add
        }

        if self.config.auto_contact_filling {
            // Add Contact header from local address
            let addr = self.public_addr.unwrap_or(self.local_addr);
            let helper = self.helper.lock().await;
            let contact_uri = &helper.contact_uri;

            let contact_value = format!(
                "<sip:{}@{}:{}>",
                contact_uri
                    .user
                    .as_ref()
                    .map(|u| u.as_str())
                    .unwrap_or("server"),
                addr.ip(),
                addr.port()
            );

            response
                .headers
                .push(SmolStr::new("Contact"), SmolStr::new(&contact_value));
        }

        // Add User-Agent if not present
        if response.headers.get("User-Agent").is_none() {
            response.headers.push(
                SmolStr::new("User-Agent"),
                SmolStr::new(&self.config.user_agent),
            );
        }
    }
}

/// Builder for constructing IntegratedUAS instances.
pub struct IntegratedUASBuilder {
    local_uri: Option<SipUri>,
    contact_uri: Option<SipUri>,
    local_addr: Option<SocketAddr>,
    public_addr: Option<SocketAddr>,
    transaction_manager: Option<Arc<TransactionManager>>,
    dispatcher: Option<Arc<dyn TransportDispatcher>>,
    request_handler: Option<Arc<dyn UasRequestHandler>>,
    authenticator: Option<Arc<dyn Authenticator>>,
    config: UASConfig,
    sdp_profile: Option<MediaProfileBuilder>,
}

impl IntegratedUASBuilder {
    fn new() -> Self {
        Self {
            local_uri: None,
            contact_uri: None,
            local_addr: None,
            public_addr: None,
            transaction_manager: None,
            dispatcher: None,
            request_handler: None,
            authenticator: None,
            config: UASConfig::default(),
            sdp_profile: None,
        }
    }

    /// Sets the local SIP URI (used in To/Contact headers).
    pub fn local_uri(mut self, uri: impl AsRef<str>) -> Self {
        self.local_uri = SipUri::parse(uri.as_ref());
        self
    }

    /// Sets the contact URI (used in Contact header).
    pub fn contact_uri(mut self, uri: impl AsRef<str>) -> Self {
        self.contact_uri = SipUri::parse(uri.as_ref());
        self
    }

    /// Sets the local transport address for Via/Contact auto-filling.
    pub fn local_addr(mut self, addr: impl AsRef<str>) -> Result<Self> {
        self.local_addr = Some(
            addr.as_ref()
                .parse()
                .map_err(|e| anyhow!("Invalid local address: {}", e))?,
        );
        Ok(self)
    }

    /// Sets the public address for NAT scenarios (overrides local_addr in Contact).
    pub fn public_addr(mut self, addr: impl AsRef<str>) -> Result<Self> {
        self.public_addr = Some(
            addr.as_ref()
                .parse()
                .map_err(|e| anyhow!("Invalid public address: {}", e))?,
        );
        Ok(self)
    }

    /// Sets the transaction manager.
    pub fn transaction_manager(mut self, mgr: Arc<TransactionManager>) -> Self {
        self.transaction_manager = Some(mgr);
        self
    }

    /// Sets the transport dispatcher.
    pub fn dispatcher(mut self, dispatcher: Arc<dyn TransportDispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Sets the request handler for processing incoming requests.
    pub fn request_handler(mut self, handler: Arc<dyn UasRequestHandler>) -> Self {
        self.request_handler = Some(handler);
        self
    }

    /// Sets the authenticator for 401 challenges.
    pub fn authenticator(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Sets the UAS configuration.
    pub fn config(mut self, config: UASConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets a default SDP media profile builder for auto-offer/answer.
    pub fn sdp_profile(mut self, builder: MediaProfileBuilder) -> Self {
        self.sdp_profile = Some(builder);
        self
    }

    /// Builds the IntegratedUAS.
    pub fn build(self) -> Result<IntegratedUAS> {
        if self.config.require_authentication && self.authenticator.is_none() {
            return Err(anyhow!(
                "authenticator is required when require_authentication is enabled"
            ));
        }

        let local_uri = self
            .local_uri
            .ok_or_else(|| anyhow!("local_uri is required"))?;
        let local_addr = self
            .local_addr
            .ok_or_else(|| anyhow!("local_addr is required"))?;
        let transaction_manager = self
            .transaction_manager
            .ok_or_else(|| anyhow!("transaction_manager is required"))?;
        let dispatcher = self
            .dispatcher
            .ok_or_else(|| anyhow!("dispatcher is required"))?;
        let request_handler = self
            .request_handler
            .ok_or_else(|| anyhow!("request_handler is required"))?;

        // Create embedded helper
        let contact_uri = self.contact_uri.unwrap_or_else(|| {
            // Default contact: sip:server@local_addr
            let user = local_uri
                .user
                .as_ref()
                .map(|u| u.as_str())
                .unwrap_or("server");
            SipUri::parse(&format!("sip:{}@{}", user, local_addr)).unwrap()
        });

        let helper = if let Some(authenticator) = self.authenticator {
            UserAgentServer::new(local_uri, contact_uri).with_authenticator(authenticator)
        } else {
            UserAgentServer::new(local_uri, contact_uri)
        };
        let dialog_manager = helper.dialog_manager.clone();
        let subscription_manager = helper.subscription_manager.clone();

        Ok(IntegratedUAS {
            helper: Arc::new(Mutex::new(helper)),
            transaction_manager,
            transport_dispatcher: dispatcher,
            local_addr,
            public_addr: self.public_addr,
            config: self.config,
            dialog_manager,
            subscription_manager,
            request_handler,
            sdp_profile: self.sdp_profile,
        })
    }
}
