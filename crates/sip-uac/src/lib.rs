// Integrated UAC with full transaction/transport/DNS integration
pub mod auth_utils;
pub mod integrated;
pub use integrated::CredentialProvider;
pub use sip_sdp::profiles::{MediaProfileBuilder, SdpProfile};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sip_auth::{DigestAlgorithm, DigestClient, Qop};
use sip_core::{Headers, Method, Request, RequestLine, Response, ServiceRouteHeader, SipUri};
use sip_dialog::{Dialog, DialogManager, Subscription, SubscriptionManager, SubscriptionState};
use sip_parse::header;
use smol_str::SmolStr;
use std::sync::Arc;
use tracing::info;

/// UAC (User Agent Client) helper for sending SIP requests.
///
/// **Note**: This is the low-level helper for request generation. For production
/// use with automatic transaction management, DNS resolution, and authentication,
/// see [`integrated::IntegratedUAC`].
///
/// Provides high-level APIs for common UAC operations like REGISTER, INVITE, and BYE,
/// with automatic authentication handling and dialog management.
pub struct UserAgentClient {
    /// Local SIP URI (From)
    pub local_uri: SipUri,

    /// Local Contact URI
    pub contact_uri: SipUri,

    /// Display name for From header
    pub display_name: Option<String>,

    /// Dialog manager for call state
    pub dialog_manager: Arc<DialogManager>,

    /// Subscription manager for event subscriptions (RFC 3265)
    pub subscription_manager: Arc<SubscriptionManager>,

    /// Optional digest client for authentication
    digest_client: Option<DigestClient>,

    /// Local tag for From header (generated once)
    local_tag: SmolStr,

    /// Service-Route from REGISTER response (RFC 3608)
    /// Stored route set to be used as preloaded Route headers in subsequent requests
    service_route: Option<ServiceRouteHeader>,
}

impl UserAgentClient {
    /// Creates a new UAC with the given local URI and contact.
    pub fn new(local_uri: SipUri, contact_uri: SipUri) -> Self {
        let local_tag = generate_tag();

        Self {
            local_uri,
            contact_uri,
            display_name: None,
            dialog_manager: Arc::new(DialogManager::new()),
            subscription_manager: Arc::new(SubscriptionManager::new()),
            digest_client: None,
            local_tag,
            service_route: None,
        }
    }

    /// Sets display name for From header.
    pub fn with_display_name(mut self, name: String) -> Self {
        self.display_name = Some(name);
        self
    }

    /// Configures digest authentication credentials.
    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.digest_client = Some(DigestClient::new(username, password));
        self
    }

    /// Creates a minimal OPTIONS request for connectivity/keepalive.
    pub fn create_options(&self, target: &SipUri) -> Request {
        let mut headers = Headers::new();

        // Via (placeholder)
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From/To
        headers.push(
            SmolStr::new("From"),
            SmolStr::new(format!(
                "<{}>;tag={}",
                self.local_uri.as_str(),
                self.local_tag
            )),
        );
        headers.push(
            SmolStr::new("To"),
            SmolStr::new(format!("<{}>", target.as_str())),
        );

        // Call-ID
        let call_id = generate_call_id();
        headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id));

        // CSeq
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 OPTIONS".to_owned()));

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));

        // User-Agent
        headers.push(
            SmolStr::new("User-Agent"),
            SmolStr::new("siphon-rs/0.1.0".to_owned()),
        );

        // Content-Length
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        Request::new(
            RequestLine::new(Method::Options, target.clone()),
            headers,
            Bytes::new(),
        )
    }

    /// Creates a REGISTER request.
    ///
    /// # Arguments
    /// * `registrar_uri` - URI of the registrar (Request-URI)
    /// * `expires` - Registration expiration in seconds (0 to deregister)
    ///
    /// # Returns
    /// A REGISTER request ready to send
    pub fn create_register(&self, registrar_uri: &SipUri, expires: u32) -> Request {
        let mut headers = Headers::new();

        // Via header (will be filled by transport layer with actual address)
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From header
        let from = self.format_from_header();
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To header (same as From for REGISTER)
        headers.push(
            SmolStr::new("To"),
            SmolStr::new(format!("<{}>", self.local_uri.as_str())),
        );

        // Call-ID
        let call_id = generate_call_id();
        headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id));

        // CSeq
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 REGISTER".to_owned()));

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!(
                "<{}>;expires={}",
                self.contact_uri.as_str(),
                expires
            )),
        );

        // Expires header
        headers.push(SmolStr::new("Expires"), SmolStr::new(expires.to_string()));

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // User-Agent
        headers.push(
            SmolStr::new("User-Agent"),
            SmolStr::new("siphon-rs/0.1.0".to_owned()),
        );

        // Content-Length
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        Request::new(
            RequestLine::new(Method::Register, registrar_uri.clone()),
            headers,
            Bytes::new(),
        )
    }

    /// Processes a REGISTER response to extract and store Service-Route headers (RFC 3608).
    ///
    /// The Service-Route header field is returned by a registrar in a 200 OK response
    /// to REGISTER to inform the UA of a route set that should be used for subsequent
    /// requests.
    ///
    /// # Arguments
    /// * `register_response` - The 200 OK response to a REGISTER request
    ///
    /// # RFC 3608 Behavior
    /// - If Service-Route headers are present, they are stored for later use
    /// - If no Service-Route headers are present, any previously stored routes are cleared
    /// - The order of multiple Service-Route values is preserved
    /// - Stored routes are used as preloaded Route headers in subsequent requests
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sip_uac::UserAgentClient;
    /// use sip_core::{SipUri, Response, StatusLine, Headers};
    /// use bytes::Bytes;
    /// use smol_str::SmolStr;
    ///
    /// let mut uac = UserAgentClient::new(
    ///     SipUri::parse("sip:alice@example.com").unwrap(),
    ///     SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
    /// );
    ///
    /// // Simulate REGISTER response with Service-Route
    /// let mut headers = Headers::new();
    /// headers.push(
    ///     SmolStr::new("Service-Route"),
    ///     SmolStr::new("<sip:proxy.example.com;lr>")
    /// );
    ///
    /// let response = Response::new(
    ///     StatusLine::new(200, SmolStr::new("OK")),
    ///     headers,
    ///     Bytes::new()
    /// );
    ///
    /// uac.process_register_response(&response);
    ///
    /// // Now subsequent requests will include the service route
    /// ```
    pub fn process_register_response(&mut self, register_response: &Response) {
        use sip_parse::parse_service_route;

        // Only process 200 OK responses
        if register_response.start.code != 200 {
            return;
        }

        // Parse Service-Route headers from response
        let service_route = parse_service_route(&register_response.headers);

        // Per RFC 3608: If the response contains Service-Route header(s), store them.
        // If the response does not contain Service-Route header(s), clear any stored routes.
        if !service_route.is_empty() {
            info!(
                "Storing {} Service-Route entries from REGISTER response",
                service_route.len()
            );
            self.service_route = Some(service_route);
        } else {
            info!("No Service-Route in REGISTER response, clearing stored routes");
            self.service_route = None;
        }
    }

    /// Returns the currently stored Service-Route, if any.
    ///
    /// Service-Route is obtained from REGISTER responses per RFC 3608 and provides
    /// a route set for subsequent requests.
    pub fn get_service_route(&self) -> Option<&ServiceRouteHeader> {
        self.service_route.as_ref()
    }

    /// Applies the stored Service-Route as preloaded Route headers to a request.
    ///
    /// Per RFC 3608, the Service-Route learned during registration should be used
    /// as a preloaded route set for requests. This method adds Route headers to
    /// the request based on the stored Service-Route.
    ///
    /// # Arguments
    /// * `request` - The request to add Route headers to
    ///
    /// # RFC 3608 Behavior
    /// - Service-Route entries are added as Route headers in the same order
    /// - Route headers are added before any existing Route headers
    /// - If no Service-Route is stored, the request is not modified
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sip_uac::UserAgentClient;
    /// use sip_core::SipUri;
    ///
    /// let mut uac = UserAgentClient::new(
    ///     SipUri::parse("sip:alice@example.com").unwrap(),
    ///     SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
    /// );
    ///
    /// // After processing REGISTER response with Service-Route...
    /// // Create an outgoing request
    /// let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
    /// let mut invite = uac.create_invite(&target_uri, None);
    ///
    /// // Apply service route to the request
    /// uac.apply_service_route(&mut invite);
    ///
    /// // Now the INVITE will be routed through the service proxy
    /// ```
    pub fn apply_service_route(&self, request: &mut Request) {
        if let Some(ref service_route) = self.service_route {
            // Add each Service-Route entry as a Route header
            // Per RFC 3608, preserve the order
            for route in &service_route.routes {
                let route_value = format!("<{}>", route.uri.as_str());
                // Insert at the beginning to maintain order
                // (since we iterate forward but want them in order)
                request
                    .headers
                    .push(SmolStr::new("Route"), SmolStr::new(route_value));
            }

            info!(
                "Applied {} Service-Route entries as Route headers",
                service_route.len()
            );
        }
    }

    /// Handles a 401/407 challenge and creates an authenticated request.
    ///
    /// # Arguments
    /// * `original_request` - The request that received the challenge
    /// * `challenge_response` - The 401/407 response with WWW-Authenticate/Proxy-Authenticate
    ///
    /// # Returns
    /// A new request with Authorization/Proxy-Authorization header
    pub fn create_authenticated_request(
        &mut self,
        original_request: &Request,
        challenge_response: &Response,
    ) -> Result<Request> {
        self.create_authenticated_request_with(original_request, challenge_response, None)
    }

    /// Handles a 401/407 challenge using provided override credentials (if any) or the configured digest client.
    pub fn create_authenticated_request_with(
        &mut self,
        original_request: &Request,
        challenge_response: &Response,
        override_creds: Option<(String, String)>,
    ) -> Result<Request> {
        let mut owned_client;
        let digest_client = match override_creds {
            Some((user, pass)) => {
                owned_client = DigestClient::new(&user, &pass);
                &mut owned_client
            }
            None => self
                .digest_client
                .as_mut()
                .ok_or_else(|| anyhow!("No credentials configured for authentication"))?,
        };

        // Determine if it's proxy or www authentication
        let is_proxy = challenge_response.start.code == 407;
        let auth_header_name = if is_proxy {
            "Proxy-Authenticate"
        } else {
            "WWW-Authenticate"
        };

        // Parse challenge
        let auth_header = challenge_response
            .headers
            .get(auth_header_name)
            .ok_or_else(|| anyhow!("Missing {} header", auth_header_name))?;

        let challenge = parse_www_authenticate(auth_header)?;

        // Extract challenge parameters
        let realm = challenge
            .get("realm")
            .ok_or_else(|| anyhow!("Missing realm in challenge"))?;
        let nonce = challenge
            .get("nonce")
            .ok_or_else(|| anyhow!("Missing nonce in challenge"))?;

        let algorithm = challenge
            .get("algorithm")
            .and_then(|a| DigestAlgorithm::from_str(a))
            .unwrap_or(DigestAlgorithm::Md5);

        let qop = challenge.get("qop").and_then(|q| {
            // qop might be "auth,auth-int" - take the first supported one
            if q.contains("auth-int") {
                Some(Qop::AuthInt)
            } else if q.contains("auth") {
                Some(Qop::Auth)
            } else {
                None
            }
        });

        let opaque = challenge.get("opaque").map(|s| s.as_str());

        // Generate authorization
        let uri = original_request.start.uri.as_str();
        let auth_value = digest_client.generate_authorization(
            original_request.start.method,
            uri,
            realm,
            nonce,
            algorithm,
            qop,
            opaque,
            &original_request.body,
        );

        // Build new request with incremented CSeq and authorization header
        let mut new_headers = Headers::new();
        let response_header_name = if is_proxy {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };

        // Copy all headers from original request, incrementing CSeq
        let mut cseq_incremented = false;
        for header in original_request.headers.iter() {
            if header.name.as_str() == "CSeq" && !cseq_incremented {
                if let Some((num, method)) = header.value.split_once(' ') {
                    if let Ok(mut cseq_num) = num.parse::<u32>() {
                        cseq_num += 1;
                        new_headers.push(
                            SmolStr::new("CSeq"),
                            SmolStr::new(format!("{} {}", cseq_num, method)),
                        );
                        cseq_incremented = true;
                        continue;
                    }
                }
                // If parsing failed, just copy as-is
                new_headers.push(header.name.clone(), header.value.clone());
            } else {
                new_headers.push(header.name.clone(), header.value.clone());
            }
        }

        // Add authorization header
        new_headers.push(SmolStr::new(response_header_name), SmolStr::new(auth_value));

        let new_request = Request::new(
            original_request.start.clone(),
            new_headers,
            original_request.body.clone(),
        );

        Ok(new_request)
    }

    /// Creates an INVITE request to establish a call.
    ///
    /// # Arguments
    /// * `target_uri` - URI of the callee (Request-URI and To)
    /// * `sdp_body` - Optional SDP offer body
    ///
    /// # Returns
    /// An INVITE request ready to send
    pub fn create_invite(&self, target_uri: &SipUri, sdp_body: Option<&str>) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From
        let from = self.format_from_header();
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To
        headers.push(
            SmolStr::new("To"),
            SmolStr::new(format!("<{}>", target_uri.as_str())),
        );

        // Call-ID
        let call_id = generate_call_id();
        headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id));

        // CSeq
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE".to_owned()));

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // User-Agent
        headers.push(
            SmolStr::new("User-Agent"),
            SmolStr::new("siphon-rs/0.1.0".to_owned()),
        );

        let body = if let Some(sdp) = sdp_body {
            // Content-Type
            headers.push(
                SmolStr::new("Content-Type"),
                SmolStr::new("application/sdp".to_owned()),
            );

            // Content-Length
            headers.push(
                SmolStr::new("Content-Length"),
                SmolStr::new(sdp.len().to_string()),
            );

            Bytes::from(sdp.as_bytes().to_vec())
        } else {
            headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));
            Bytes::new()
        };

        Request::new(
            RequestLine::new(Method::Invite, target_uri.clone()),
            headers,
            body,
        )
    }

    /// Creates an ACK request for a 2xx response to INVITE.
    ///
    /// # Arguments
    /// * `invite_request` - The original INVITE request
    /// * `response` - The 2xx response to ACK
    /// * `_dialog` - The dialog created from the INVITE transaction
    /// * `sdp_body` - Optional SDP body for late offer (when 200 OK contained the offer)
    ///
    /// # Returns
    /// An ACK request
    ///
    /// # SDP Offer/Answer
    /// - Early offer: INVITE has SDP offer, 200 OK has answer, ACK is empty (pass None)
    /// - Late offer: INVITE is empty, 200 OK has SDP offer, ACK has answer (pass Some(sdp))
    pub fn create_ack(
        &self,
        invite_request: &Request,
        response: &Response,
        _dialog: &Dialog,
        sdp_body: Option<&str>,
    ) -> Request {
        let mut headers = Headers::new();

        // Via (same branch as INVITE for non-2xx, new branch for 2xx)
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (same as INVITE)
        if let Some(from) = invite_request.headers.get("From") {
            headers.push(SmolStr::new("From"), from.clone());
        }

        // To (with tag from response)
        if let Some(to) = response.headers.get("To") {
            headers.push(SmolStr::new("To"), to.clone());
        }

        // Call-ID (same as INVITE)
        if let Some(call_id) = invite_request.headers.get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id.clone());
        }

        // CSeq (same number as INVITE, but ACK method)
        if let Some(cseq) = invite_request.headers.get("CSeq") {
            if let Some((num, _)) = cseq.split_once(' ') {
                headers.push(SmolStr::new("CSeq"), SmolStr::new(format!("{} ACK", num)));
            }
        }

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Handle SDP body (for late offer scenario)
        let body = if let Some(sdp) = sdp_body {
            // Content-Type
            headers.push(
                SmolStr::new("Content-Type"),
                SmolStr::new("application/sdp".to_owned()),
            );

            // Content-Length
            headers.push(
                SmolStr::new("Content-Length"),
                SmolStr::new(sdp.len().to_string()),
            );

            Bytes::from(sdp.as_bytes().to_vec())
        } else {
            // Content-Length
            headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));
            Bytes::new()
        };

        Request::new(
            RequestLine::new(Method::Ack, invite_request.start.uri.clone()),
            headers,
            body,
        )
    }

    /// Creates a BYE request to terminate a call.
    ///
    /// # Arguments
    /// * `dialog` - The dialog to terminate
    ///
    /// # Returns
    /// A BYE request
    pub fn create_bye(&self, dialog: &Dialog) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (with local tag)
        let from = format!(
            "<{}>;tag={}",
            self.local_uri.as_str(),
            dialog.id.local_tag.as_str()
        );
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To (with remote tag)
        let to = format!(
            "<{}>;tag={}",
            dialog.remote_uri.as_str(),
            dialog.id.remote_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID
        headers.push(SmolStr::new("Call-ID"), dialog.id.call_id.clone());

        // CSeq (next local CSeq)
        let mut mutable_dialog = dialog.clone();
        let cseq = mutable_dialog.next_local_cseq();
        headers.push(SmolStr::new("CSeq"), SmolStr::new(format!("{} BYE", cseq)));

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Content-Length
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        // Request-URI is the remote target
        let request_uri = dialog.remote_target.clone();

        Request::new(
            RequestLine::new(Method::Bye, request_uri),
            headers,
            Bytes::new(),
        )
    }

    /// Creates a re-INVITE request to modify an existing session (RFC 3261 §14).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send re-INVITE within
    /// * `sdp_body` - Optional new SDP offer (None for session refresh without media change)
    ///
    /// # Returns
    /// A re-INVITE request ready to send
    pub fn create_reinvite(&self, dialog: &Dialog, sdp_body: Option<&str>) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (with local tag)
        let from = if let Some(ref display) = self.display_name {
            format!(
                "\"{}\" <{}>;tag={}",
                display,
                self.local_uri.as_str(),
                dialog.id.local_tag.as_str()
            )
        } else {
            format!(
                "<{}>;tag={}",
                self.local_uri.as_str(),
                dialog.id.local_tag.as_str()
            )
        };
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To (with remote tag)
        let to = format!(
            "<{}>;tag={}",
            dialog.remote_uri.as_str(),
            dialog.id.remote_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID
        headers.push(SmolStr::new("Call-ID"), dialog.id.call_id.clone());

        // CSeq (next local CSeq)
        let mut mutable_dialog = dialog.clone();
        let cseq = mutable_dialog.next_local_cseq();
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} INVITE", cseq)),
        );

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // User-Agent
        headers.push(
            SmolStr::new("User-Agent"),
            SmolStr::new("siphon-rs/0.1.0".to_owned()),
        );

        let body = if let Some(sdp) = sdp_body {
            // Content-Type
            headers.push(
                SmolStr::new("Content-Type"),
                SmolStr::new("application/sdp".to_owned()),
            );

            // Content-Length
            headers.push(
                SmolStr::new("Content-Length"),
                SmolStr::new(sdp.len().to_string()),
            );

            Bytes::from(sdp.as_bytes().to_vec())
        } else {
            headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));
            Bytes::new()
        };

        // Request-URI is the remote target
        let request_uri = dialog.remote_target.clone();

        Request::new(RequestLine::new(Method::Invite, request_uri), headers, body)
    }

    /// Creates an UPDATE request to modify session parameters (RFC 3311).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send UPDATE within
    /// * `sdp_body` - Optional SDP for session modification
    ///
    /// # Returns
    /// An UPDATE request ready to send
    pub fn create_update(&self, dialog: &Dialog, sdp_body: Option<&str>) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (with local tag)
        let from = if let Some(ref display) = self.display_name {
            format!(
                "\"{}\" <{}>;tag={}",
                display,
                self.local_uri.as_str(),
                dialog.id.local_tag.as_str()
            )
        } else {
            format!(
                "<{}>;tag={}",
                self.local_uri.as_str(),
                dialog.id.local_tag.as_str()
            )
        };
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To (with remote tag)
        let to = format!(
            "<{}>;tag={}",
            dialog.remote_uri.as_str(),
            dialog.id.remote_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID
        headers.push(SmolStr::new("Call-ID"), dialog.id.call_id.clone());

        // CSeq (next local CSeq)
        let mut mutable_dialog = dialog.clone();
        let cseq = mutable_dialog.next_local_cseq();
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} UPDATE", cseq)),
        );

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // User-Agent
        headers.push(
            SmolStr::new("User-Agent"),
            SmolStr::new("siphon-rs/0.1.0".to_owned()),
        );

        let body = if let Some(sdp) = sdp_body {
            // Content-Type
            headers.push(
                SmolStr::new("Content-Type"),
                SmolStr::new("application/sdp".to_owned()),
            );

            // Content-Length
            headers.push(
                SmolStr::new("Content-Length"),
                SmolStr::new(sdp.len().to_string()),
            );

            Bytes::from(sdp.as_bytes().to_vec())
        } else {
            headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));
            Bytes::new()
        };

        // Request-URI is the remote target
        let request_uri = dialog.remote_target.clone();

        Request::new(RequestLine::new(Method::Update, request_uri), headers, body)
    }

    /// Creates a PUBLISH request for event state publication (RFC 3903).
    pub fn create_publish(
        &self,
        target: &SipUri,
        event: &str,
        content_type: &str,
        body: &str,
    ) -> Request {
        let mut headers = Headers::new();

        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        let from = self.format_from_header();
        headers.push(SmolStr::new("From"), SmolStr::new(from.clone()));
        headers.push(
            SmolStr::new("To"),
            SmolStr::new(format!("<{}>", target.as_str())),
        );

        let call_id = generate_call_id();
        headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id));
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 PUBLISH".to_owned()));
        headers.push(SmolStr::new("Event"), SmolStr::new(event.to_owned()));
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));
        headers.push(
            SmolStr::new("User-Agent"),
            SmolStr::new("siphon-rs/0.1.0".to_owned()),
        );
        headers.push(
            SmolStr::new("Content-Type"),
            SmolStr::new(content_type.to_owned()),
        );

        let body_bytes = Bytes::from(body.as_bytes().to_vec());
        headers.push(
            SmolStr::new("Content-Length"),
            SmolStr::new(body_bytes.len().to_string()),
        );

        Request::new(
            RequestLine::new(Method::Publish, target.clone()),
            headers,
            body_bytes,
        )
    }

    /// Creates a session refresh request for RFC 4028 session timers.
    ///
    /// # Arguments
    /// * `dialog` - The dialog to refresh
    /// * `session_expires` - Session-Expires value in seconds
    /// * `refresher` - Refresher role ("uac" or "uas")
    /// * `use_update` - If true, use UPDATE; if false, use re-INVITE
    /// * `sdp_body` - Optional SDP body (required for re-INVITE if call has media)
    ///
    /// # Returns
    /// A session refresh request (re-INVITE or UPDATE) with Session-Expires header
    ///
    /// # RFC 4028 Session Timer Refresh
    ///
    /// Session timers prevent stuck dialogs by requiring periodic refresh.
    /// The refresher (UAC or UAS) must send a refresh before Session-Expires/2.
    ///
    /// Per RFC 4028 §7.4, refresh can be done with:
    /// - **re-INVITE**: Full session refresh with SDP renegotiation
    /// - **UPDATE**: Session refresh without changing media (RFC 3311)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use sip_dialog::session_timer_manager::SessionTimerEvent;
    ///
    /// // Listen for refresh events
    /// while let Some(event) = timer_events.recv().await {
    ///     match event {
    ///         SessionTimerEvent::RefreshNeeded(dialog_id) => {
    ///             let dialog = dialog_manager.get(&dialog_id).unwrap();
    ///
    ///             // Create refresh with UPDATE (no SDP renegotiation)
    ///             let refresh = uac.create_session_refresh(
    ///                 &dialog,
    ///                 1800,     // 30 minutes
    ///                 "uac",    // We are refresher
    ///                 true,     // Use UPDATE
    ///                 None      // No SDP needed for UPDATE
    ///             );
    ///
    ///             // Send refresh request
    ///             transport.send(refresh).await?;
    ///         }
    ///         SessionTimerEvent::SessionExpired(dialog_id) => {
    ///             // Session timed out - send BYE
    ///         }
    ///     }
    /// }
    /// ```
    pub fn create_session_refresh(
        &self,
        dialog: &Dialog,
        session_expires: u32,
        refresher: &str,
        use_update: bool,
        sdp_body: Option<&str>,
    ) -> Request {
        // Create base request (re-INVITE or UPDATE)
        let mut request = if use_update {
            self.create_update(dialog, sdp_body)
        } else {
            self.create_reinvite(dialog, sdp_body)
        };

        // Add Session-Expires header per RFC 4028 §7.4
        let session_expires_value = format!("{};refresher={}", session_expires, refresher);
        request.headers.push(
            SmolStr::new("Session-Expires"),
            SmolStr::new(session_expires_value),
        );

        // Add Supported: timer to indicate session timer support
        if !request.headers.get("Supported").is_some() {
            request
                .headers
                .push(SmolStr::new("Supported"), SmolStr::new("timer"));
        }

        request
    }

    /// Creates an INFO request to send mid-dialog information (RFC 2976).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send INFO within
    /// * `content_type` - MIME type of the body (e.g., "application/dtmf-relay", "application/json")
    /// * `body` - The information payload
    ///
    /// # Returns
    /// An INFO request ready to send
    ///
    /// # RFC 2976 INFO Method
    /// INFO is used to carry session-related control information generated during a session.
    /// Common use cases:
    /// - DTMF relay: Send DTMF digits within an established call
    /// - Custom application data: Exchange application-specific information
    /// - Mid-call signaling: Send non-SDP signaling data
    ///
    /// # Examples
    ///
    /// ## DTMF Relay
    /// ```ignore
    /// let dtmf_body = "Signal=1\r\nDuration=100\r\n";
    /// let info = uac.create_info(&dialog, "application/dtmf-relay", dtmf_body);
    /// ```
    ///
    /// ## Custom Application Data
    /// ```ignore
    /// let json_body = r#"{"action":"mute","value":true}"#;
    /// let info = uac.create_info(&dialog, "application/json", json_body);
    /// ```
    pub fn create_info(&self, dialog: &Dialog, content_type: &str, body: &str) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (with local tag)
        let from = format!(
            "<{}>;tag={}",
            self.local_uri.as_str(),
            dialog.id.local_tag.as_str()
        );
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To (with remote tag)
        let to = format!(
            "<{}>;tag={}",
            dialog.remote_uri.as_str(),
            dialog.id.remote_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID
        headers.push(SmolStr::new("Call-ID"), dialog.id.call_id.clone());

        // CSeq (next local CSeq)
        let mut mutable_dialog = dialog.clone();
        let cseq = mutable_dialog.next_local_cseq();
        headers.push(SmolStr::new("CSeq"), SmolStr::new(format!("{} INFO", cseq)));

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Content-Type
        headers.push(
            SmolStr::new("Content-Type"),
            SmolStr::new(content_type.to_owned()),
        );

        // Content-Length
        headers.push(
            SmolStr::new("Content-Length"),
            SmolStr::new(body.len().to_string()),
        );

        // Request-URI is the remote target
        let request_uri = dialog.remote_target.clone();

        Request::new(
            RequestLine::new(Method::Info, request_uri),
            headers,
            Bytes::from(body.as_bytes().to_vec()),
        )
    }

    /// Adds a Privacy header to a request (RFC 3323).
    ///
    /// # Arguments
    /// * `request` - The request to add the Privacy header to
    /// * `privacy_values` - The privacy values to include
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::PrivacyValue;
    /// use sip_uac::UserAgentClient;
    ///
    /// let uac = UserAgentClient::new(local_uri, contact_uri);
    /// let mut invite = uac.create_invite(&remote_uri, Some(sdp));
    ///
    /// // Add privacy for identity hiding
    /// UserAgentClient::add_privacy_header(&mut invite, vec![PrivacyValue::Id]);
    ///
    /// // Add critical privacy (must be honored or request fails)
    /// UserAgentClient::add_privacy_header(&mut invite, vec![
    ///     PrivacyValue::Id,
    ///     PrivacyValue::Critical,
    /// ]);
    /// ```
    pub fn add_privacy_header(request: &mut Request, privacy_values: Vec<sip_core::PrivacyValue>) {
        use sip_core::PrivacyHeader;

        let privacy = PrivacyHeader::new(privacy_values);
        request
            .headers
            .push(SmolStr::new("Privacy"), SmolStr::new(privacy.to_string()));
    }

    /// Creates a new request with Privacy header (RFC 3323).
    ///
    /// This is a convenience method that takes an existing request and returns
    /// a new request with the Privacy header added.
    ///
    /// # Arguments
    /// * `request` - The base request
    /// * `privacy_values` - The privacy values to include
    ///
    /// # Returns
    /// A new request with the Privacy header added
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::PrivacyValue;
    /// use sip_uac::UserAgentClient;
    ///
    /// let uac = UserAgentClient::new(local_uri, contact_uri);
    /// let invite = uac.create_invite(&remote_uri, Some(sdp));
    ///
    /// // Create invite with privacy
    /// let private_invite = UserAgentClient::with_privacy(
    ///     invite,
    ///     vec![PrivacyValue::Id, PrivacyValue::Critical],
    /// );
    /// ```
    pub fn with_privacy(
        mut request: Request,
        privacy_values: Vec<sip_core::PrivacyValue>,
    ) -> Request {
        Self::add_privacy_header(&mut request, privacy_values);
        request
    }

    /// Adds a Reason header to a request (RFC 3326).
    ///
    /// # Arguments
    /// * `request` - The request to add the Reason header to
    /// * `reason` - The Reason header to add
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{ReasonHeader, Q850Cause};
    /// use sip_uac::UserAgentClient;
    ///
    /// let uac = UserAgentClient::new(local_uri, contact_uri);
    /// let mut bye = uac.create_bye(&dialog);
    ///
    /// // Add Q.850 reason for normal call clearing
    /// let reason = ReasonHeader::q850(Q850Cause::NormalCallClearing);
    /// UserAgentClient::add_reason_header(&mut bye, reason);
    /// ```
    pub fn add_reason_header(request: &mut Request, reason: sip_core::ReasonHeader) {
        request
            .headers
            .push(SmolStr::new("Reason"), SmolStr::new(reason.to_string()));
    }

    /// Creates a BYE request with a Reason header (RFC 3326).
    ///
    /// This is a convenience method for terminating a call with a reason.
    ///
    /// # Arguments
    /// * `dialog` - The dialog to terminate
    /// * `reason` - The reason for terminating the call
    ///
    /// # Returns
    /// A BYE request with Reason header ready to send
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{ReasonHeader, Q850Cause};
    /// use sip_uac::UserAgentClient;
    ///
    /// let uac = UserAgentClient::new(local_uri, contact_uri);
    ///
    /// // Normal call clearing
    /// let reason = ReasonHeader::q850(Q850Cause::NormalCallClearing);
    /// let bye = uac.create_bye_with_reason(&dialog, reason);
    ///
    /// // User busy
    /// let reason = ReasonHeader::q850(Q850Cause::UserBusy);
    /// let bye = uac.create_bye_with_reason(&dialog, reason);
    ///
    /// // SIP reason code
    /// let reason = ReasonHeader::sip(480, None);
    /// let bye = uac.create_bye_with_reason(&dialog, reason);
    /// ```
    pub fn create_bye_with_reason(
        &self,
        dialog: &Dialog,
        reason: sip_core::ReasonHeader,
    ) -> Request {
        let mut bye = self.create_bye(dialog);
        Self::add_reason_header(&mut bye, reason);
        bye
    }

    /// Adds a P-Preferred-Identity header to a request (RFC 3325).
    ///
    /// This header is used by a UAC to express a preference about which identity
    /// should be asserted by a trusted proxy when the user has multiple identities.
    ///
    /// # Arguments
    /// * `request` - The request to add the P-Preferred-Identity header to
    /// * `header` - The P-Preferred-Identity header to add
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{PPreferredIdentityHeader, SipUri};
    /// use sip_uac::UserAgentClient;
    ///
    /// let uac = UserAgentClient::new(local_uri, contact_uri);
    /// let mut invite = uac.create_invite(&remote_uri, Some(sdp));
    ///
    /// // Prefer a specific SIP identity
    /// let preferred_uri = SipUri::parse("sip:alice.smith@company.com").unwrap();
    /// let ppi = PPreferredIdentityHeader::single_sip(preferred_uri);
    /// UserAgentClient::add_p_preferred_identity_header(&mut invite, ppi);
    ///
    /// // Prefer a telephone number
    /// let ppi = PPreferredIdentityHeader::single_tel("+15551234567");
    /// UserAgentClient::add_p_preferred_identity_header(&mut invite, ppi);
    /// ```
    pub fn add_p_preferred_identity_header(
        request: &mut Request,
        header: sip_core::PPreferredIdentityHeader,
    ) {
        request.headers.push(
            SmolStr::new("P-Preferred-Identity"),
            SmolStr::new(header.to_string()),
        );
    }

    /// Creates a new request with P-Preferred-Identity header (RFC 3325).
    ///
    /// This is a convenience method that takes an existing request and returns
    /// a new request with the P-Preferred-Identity header added.
    ///
    /// # Arguments
    /// * `request` - The base request
    /// * `header` - The P-Preferred-Identity header to add
    ///
    /// # Returns
    /// A new request with the P-Preferred-Identity header added
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{PPreferredIdentityHeader, SipUri};
    /// use sip_uac::UserAgentClient;
    ///
    /// let uac = UserAgentClient::new(local_uri, contact_uri);
    /// let invite = uac.create_invite(&remote_uri, Some(sdp));
    ///
    /// // Create invite with preferred identity
    /// let preferred_uri = SipUri::parse("sip:alice.smith@company.com").unwrap();
    /// let ppi = PPreferredIdentityHeader::single_sip(preferred_uri);
    /// let invite = UserAgentClient::with_p_preferred_identity(invite, ppi);
    /// ```
    pub fn with_p_preferred_identity(
        mut request: Request,
        header: sip_core::PPreferredIdentityHeader,
    ) -> Request {
        Self::add_p_preferred_identity_header(&mut request, header);
        request
    }

    /// Adds a P-Asserted-Identity header to a request (RFC 3325).
    ///
    /// **IMPORTANT**: P-Asserted-Identity should only be added by trusted proxies
    /// within a trust domain. UACs should typically use P-Preferred-Identity instead.
    /// This method is provided for testing and special cases where the UAC is acting
    /// as a trusted element.
    ///
    /// # Arguments
    /// * `request` - The request to add the P-Asserted-Identity header to
    /// * `header` - The P-Asserted-Identity header to add
    ///
    /// # Trust Domain Warning
    ///
    /// This header should be removed at trust domain boundaries. Only use this if:
    /// - You are implementing a trusted proxy
    /// - You are in a testing/development environment
    /// - You understand the RFC 3325 trust domain requirements
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{PAssertedIdentityHeader, SipUri};
    /// use sip_uac::UserAgentClient;
    ///
    /// let uac = UserAgentClient::new(local_uri, contact_uri);
    /// let mut invite = uac.create_invite(&remote_uri, Some(sdp));
    ///
    /// // Assert identity (typically done by proxy, not UAC)
    /// let asserted_uri = SipUri::parse("sip:alice@example.com").unwrap();
    /// let pai = PAssertedIdentityHeader::single_sip(asserted_uri);
    /// UserAgentClient::add_p_asserted_identity_header(&mut invite, pai);
    /// ```
    pub fn add_p_asserted_identity_header(
        request: &mut Request,
        header: sip_core::PAssertedIdentityHeader,
    ) {
        request.headers.push(
            SmolStr::new("P-Asserted-Identity"),
            SmolStr::new(header.to_string()),
        );
    }

    /// Creates a PRACK request to acknowledge a reliable provisional response (RFC 3262).
    ///
    /// # Arguments
    /// * `invite_request` - The original INVITE request
    /// * `reliable_provisional` - The reliable provisional response (1xx with RSeq header)
    /// * `dialog` - The dialog (from early dialog establishment)
    ///
    /// # Returns
    /// A PRACK request ready to send
    ///
    /// # RFC 3262 PRACK
    /// PRACK reliably acknowledges provisional responses that contain an RSeq header.
    /// The RAck header contains: RSeq CSeq-number Method
    pub fn create_prack(
        &self,
        invite_request: &Request,
        reliable_provisional: &Response,
        dialog: &Dialog,
    ) -> Result<Request> {
        // Extract RSeq from response
        let rseq_str = header(&reliable_provisional.headers, "RSeq")
            .ok_or_else(|| anyhow!("No RSeq header in provisional response"))?;
        let rseq: u32 = rseq_str
            .parse()
            .map_err(|_| anyhow!("Invalid RSeq value: {}", rseq_str))?;

        // Extract CSeq number from original INVITE
        let cseq_str = header(&invite_request.headers, "CSeq")
            .ok_or_else(|| anyhow!("No CSeq header in INVITE"))?;
        let cseq_parts: Vec<&str> = cseq_str.split_whitespace().collect();
        if cseq_parts.len() < 2 {
            return Err(anyhow!("Invalid CSeq header format"));
        }
        let invite_cseq: u32 = cseq_parts[0]
            .parse()
            .map_err(|_| anyhow!("Invalid CSeq number: {}", cseq_parts[0]))?;
        let invite_method = cseq_parts[1];

        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (with local tag)
        let from = if let Some(ref display) = self.display_name {
            format!(
                "\"{}\" <{}>;tag={}",
                display,
                self.local_uri.as_str(),
                dialog.id.local_tag.as_str()
            )
        } else {
            format!(
                "<{}>;tag={}",
                self.local_uri.as_str(),
                dialog.id.local_tag.as_str()
            )
        };
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To (with remote tag from provisional response)
        let to = format!(
            "<{}>;tag={}",
            dialog.remote_uri.as_str(),
            dialog.id.remote_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID
        headers.push(SmolStr::new("Call-ID"), dialog.id.call_id.clone());

        // CSeq (next local CSeq for PRACK)
        let mut mutable_dialog = dialog.clone();
        let prack_cseq = mutable_dialog.next_local_cseq();
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} PRACK", prack_cseq)),
        );

        // RAck: RSeq CSeq-number Method
        headers.push(
            SmolStr::new("RAck"),
            SmolStr::new(format!("{} {} {}", rseq, invite_cseq, invite_method)),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Content-Length
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        // Request-URI is the remote target (Contact from provisional response)
        let request_uri = dialog.remote_target.clone();

        Ok(Request::new(
            RequestLine::new(Method::Prack, request_uri),
            headers,
            Bytes::new(),
        ))
    }

    /// Processes a response to establish a dialog (for UAC).
    ///
    /// # Arguments
    /// * `request` - The original request that created the dialog
    /// * `response` - The response (1xx or 2xx)
    ///
    /// # Returns
    /// The created dialog, if successful
    pub fn process_invite_response(
        &self,
        request: &Request,
        response: &Response,
    ) -> Option<Dialog> {
        let dialog = Dialog::new_uac(
            request,
            response,
            self.local_uri.clone(),
            extract_to_uri(response)?,
        )?;

        info!(
            call_id = %dialog.id.call_id,
            state = ?dialog.state,
            "UAC created dialog"
        );

        // Store in dialog manager
        self.dialog_manager.insert(dialog.clone());

        Some(dialog)
    }

    /// Creates a SUBSCRIBE request to establish an event subscription (RFC 3265).
    ///
    /// # Arguments
    /// * `target_uri` - URI of the resource to subscribe to
    /// * `event` - Event package (e.g., "refer", "message-summary", "presence")
    /// * `expires` - Subscription duration in seconds (0 to unsubscribe)
    ///
    /// # Returns
    /// A SUBSCRIBE request ready to send
    pub fn create_subscribe(&self, target_uri: &SipUri, event: &str, expires: u32) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From
        let from = self.format_from_header();
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To
        headers.push(
            SmolStr::new("To"),
            SmolStr::new(format!("<{}>", target_uri.as_str())),
        );

        // Call-ID
        let call_id = generate_call_id();
        headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id));

        // CSeq
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 SUBSCRIBE".to_owned()));

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Event
        headers.push(SmolStr::new("Event"), SmolStr::new(event));

        // Expires
        headers.push(SmolStr::new("Expires"), SmolStr::new(expires.to_string()));

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // User-Agent
        headers.push(
            SmolStr::new("User-Agent"),
            SmolStr::new("siphon-rs/0.1.0".to_owned()),
        );

        // Content-Length
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        Request::new(
            RequestLine::new(Method::Subscribe, target_uri.clone()),
            headers,
            Bytes::new(),
        )
    }

    /// Processes a SUBSCRIBE response to create a subscription.
    ///
    /// # Arguments
    /// * `request` - The original SUBSCRIBE request
    /// * `response` - The 200 OK response
    ///
    /// # Returns
    /// The created subscription, if successful
    pub fn process_subscribe_response(
        &self,
        request: &Request,
        response: &Response,
    ) -> Option<Subscription> {
        let subscription = Subscription::new_subscriber(
            request,
            response,
            self.local_uri.clone(),
            extract_to_uri(response)?,
        )?;

        info!(
            call_id = %subscription.id.call_id,
            event = %subscription.id.event,
            "UAC created subscription"
        );

        // Store in subscription manager
        self.subscription_manager.insert(subscription.clone());

        Some(subscription)
    }

    /// Creates a NOTIFY request to report subscription state (RFC 3265).
    ///
    /// # Arguments
    /// * `subscription` - The subscription to notify
    /// * `state` - Subscription state (active, pending, terminated)
    /// * `body` - Optional body content (event-specific)
    ///
    /// # Returns
    /// A NOTIFY request ready to send
    pub fn create_notify(
        &self,
        subscription: &Subscription,
        state: SubscriptionState,
        body: Option<&str>,
    ) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From
        let from = format!(
            "<{}>;tag={}",
            self.local_uri.as_str(),
            subscription.id.to_tag.as_str()
        );
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To
        let to = format!(
            "<{}>;tag={}",
            subscription.remote_uri.as_str(),
            subscription.id.from_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID
        headers.push(SmolStr::new("Call-ID"), subscription.id.call_id.clone());

        // CSeq (use subscription's CSeq)
        let cseq = subscription.local_cseq + 1;
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} NOTIFY", cseq)),
        );

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Event
        headers.push(SmolStr::new("Event"), subscription.id.event.clone());

        // Subscription-State
        headers.push(
            SmolStr::new("Subscription-State"),
            SmolStr::new(state.as_str()),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Handle body
        let request_body = if let Some(content) = body {
            // Content-Type (depends on event package, defaulting to plain text)
            headers.push(
                SmolStr::new("Content-Type"),
                SmolStr::new("text/plain".to_owned()),
            );
            headers.push(
                SmolStr::new("Content-Length"),
                SmolStr::new(content.len().to_string()),
            );
            Bytes::from(content.as_bytes().to_vec())
        } else {
            headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));
            Bytes::new()
        };

        Request::new(
            RequestLine::new(Method::Notify, subscription.contact.clone()),
            headers,
            request_body,
        )
    }

    /// Creates a SUBSCRIBE request for the "reg" event package (RFC 3680).
    ///
    /// The "reg" event package allows clients to subscribe to registration state
    /// changes for an address-of-record. NOTIFY messages contain application/reginfo+xml
    /// bodies describing the current registration state.
    ///
    /// # Arguments
    /// * `target_uri` - The address-of-record to monitor
    /// * `expires` - Subscription duration in seconds (default: 3761 per RFC 3680)
    ///
    /// # Returns
    /// A SUBSCRIBE request for registration state
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sip_uac::UserAgentClient;
    /// use sip_core::SipUri;
    ///
    /// let uac = UserAgentClient::new(
    ///     SipUri::parse("sip:alice@example.com").unwrap(),
    ///     SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
    /// );
    ///
    /// // Subscribe to registration state
    /// let subscribe = uac.create_reg_subscribe(
    ///     &SipUri::parse("sip:bob@example.com").unwrap(),
    ///     3761
    /// );
    ///
    /// // Send SUBSCRIBE and receive NOTIFY with reginfo
    /// ```
    pub fn create_reg_subscribe(&self, target_uri: &SipUri, expires: u32) -> Request {
        // Use the generic create_subscribe but ensure proper Accept header
        let mut request = self.create_subscribe(target_uri, "reg", expires);

        // RFC 3680: Accept header must include application/reginfo+xml
        request.headers.push(
            SmolStr::new("Accept"),
            SmolStr::new("application/reginfo+xml"),
        );

        request
    }

    /// Creates a NOTIFY request for the "reg" event with RegInfo body (RFC 3680).
    ///
    /// Sends registration state information in application/reginfo+xml format.
    ///
    /// # Arguments
    /// * `subscription` - The reg event subscription
    /// * `state` - Subscription state (active, pending, terminated)
    /// * `reginfo` - Registration information to include in body
    ///
    /// # Returns
    /// A NOTIFY request with reginfo XML body
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sip_uac::UserAgentClient;
    /// use sip_core::{SipUri, RegInfo, RegInfoState, Registration, RegistrationState,
    ///                Contact, ContactState, ContactEvent};
    /// use sip_dialog::{Subscription, SubscriptionState};
    /// use smol_str::SmolStr;
    ///
    /// let uac = UserAgentClient::new(
    ///     SipUri::parse("sip:alice@example.com").unwrap(),
    ///     SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
    /// );
    ///
    /// // Create registration info
    /// let mut reginfo = RegInfo::new(1, RegInfoState::Full);
    ///
    /// let mut registration = Registration::new(
    ///     SmolStr::new("sip:bob@example.com"),
    ///     SmolStr::new("reg1"),
    ///     RegistrationState::Active
    /// );
    ///
    /// let contact = Contact::new(
    ///     SmolStr::new("contact1"),
    ///     ContactState::Active,
    ///     SmolStr::new("sip:bob@192.168.1.200:5060")
    /// ).with_event(ContactEvent::Registered)
    ///   .with_expires(3600);
    ///
    /// registration.add_contact(contact);
    /// reginfo.add_registration(registration);
    ///
    /// // Create NOTIFY with reginfo body
    /// # let subscription = todo!();
    /// let notify = uac.create_reg_notify(
    ///     &subscription,
    ///     SubscriptionState::Active,
    ///     &reginfo
    /// );
    /// ```
    pub fn create_reg_notify(
        &self,
        subscription: &Subscription,
        state: SubscriptionState,
        reginfo: &sip_core::RegInfo,
    ) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From
        let from = format!(
            "<{}>;tag={}",
            self.local_uri.as_str(),
            subscription.id.to_tag.as_str()
        );
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To
        let to = format!(
            "<{}>;tag={}",
            subscription.remote_uri.as_str(),
            subscription.id.from_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID
        headers.push(SmolStr::new("Call-ID"), subscription.id.call_id.clone());

        // CSeq (use subscription's CSeq)
        let cseq = subscription.local_cseq + 1;
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} NOTIFY", cseq)),
        );

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Event: reg
        headers.push(SmolStr::new("Event"), SmolStr::new("reg"));

        // Subscription-State
        headers.push(
            SmolStr::new("Subscription-State"),
            SmolStr::new(state.as_str()),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Content-Type: application/reginfo+xml
        headers.push(
            SmolStr::new("Content-Type"),
            SmolStr::new("application/reginfo+xml"),
        );

        // Body (reginfo XML)
        let body = reginfo.to_string();
        headers.push(
            SmolStr::new("Content-Length"),
            SmolStr::new(body.len().to_string()),
        );

        Request::new(
            RequestLine::new(Method::Notify, subscription.contact.clone()),
            headers,
            Bytes::from(body.into_bytes()),
        )
    }

    /// Creates a REFER request for call transfer (RFC 3515).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send REFER in (existing call)
    /// * `refer_to_uri` - URI to transfer the call to (Refer-To header)
    ///
    /// # Returns
    /// A REFER request ready to send
    ///
    /// # Call Transfer
    /// This creates an implicit subscription to the "refer" event.
    /// The transferee will send NOTIFY requests with sipfrag bodies
    /// reporting the progress of the transfer.
    pub fn create_refer(&self, dialog: &Dialog, refer_to_uri: &SipUri) -> Request {
        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (with local tag from dialog)
        let from = format!(
            "<{}>;tag={}",
            self.local_uri.as_str(),
            dialog.id.local_tag.as_str()
        );
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To (with remote tag from dialog)
        let to = format!(
            "<{}>;tag={}",
            dialog.remote_uri.as_str(),
            dialog.id.remote_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID (same as dialog)
        headers.push(SmolStr::new("Call-ID"), dialog.id.call_id.clone());

        // CSeq (next in dialog)
        let mut mutable_dialog = dialog.clone();
        let cseq = mutable_dialog.next_local_cseq();
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} REFER", cseq)),
        );

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Refer-To (the transfer target)
        headers.push(
            SmolStr::new("Refer-To"),
            SmolStr::new(format!("<{}>", refer_to_uri.as_str())),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Content-Length
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        Request::new(
            RequestLine::new(Method::Refer, dialog.remote_target.clone()),
            headers,
            Bytes::new(),
        )
    }

    /// Creates a REFER request with Replaces header for attended transfer (RFC 3891).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send REFER in (existing call with A)
    /// * `refer_to_uri` - URI to transfer to (will have Replaces parameter)
    /// * `target_dialog` - The dialog being replaced (existing call with B)
    ///
    /// # Returns
    /// A REFER request for attended transfer
    ///
    /// # Attended Transfer
    /// Transfers party A to party B by having A replace the existing dialog with B.
    /// The Refer-To URI includes a Replaces parameter with the target dialog information.
    pub fn create_refer_with_replaces(
        &self,
        dialog: &Dialog,
        refer_to_uri: &SipUri,
        target_dialog: &Dialog,
    ) -> Request {
        // Build Replaces parameter: call-id;to-tag=X;from-tag=Y
        let replaces = format!(
            "{};to-tag={};from-tag={}",
            urlencoding::encode(&target_dialog.id.call_id),
            urlencoding::encode(&target_dialog.id.remote_tag),
            urlencoding::encode(&target_dialog.id.local_tag)
        );

        // Create Refer-To with Replaces parameter
        let refer_to_with_replaces = format!("<{}?Replaces={}>", refer_to_uri.as_str(), replaces);

        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From (with local tag from dialog)
        let from = format!(
            "<{}>;tag={}",
            self.local_uri.as_str(),
            dialog.id.local_tag.as_str()
        );
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To (with remote tag from dialog)
        let to = format!(
            "<{}>;tag={}",
            dialog.remote_uri.as_str(),
            dialog.id.remote_tag.as_str()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to));

        // Call-ID (same as dialog)
        headers.push(SmolStr::new("Call-ID"), dialog.id.call_id.clone());

        // CSeq (next in dialog)
        let mut mutable_dialog = dialog.clone();
        let cseq = mutable_dialog.next_local_cseq();
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} REFER", cseq)),
        );

        // Contact
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
        );

        // Refer-To with Replaces
        headers.push(
            SmolStr::new("Refer-To"),
            SmolStr::new(refer_to_with_replaces),
        );

        // Referred-By (optional but recommended for attended transfer)
        headers.push(
            SmolStr::new("Referred-By"),
            SmolStr::new(format!("<{}>", self.local_uri.as_str())),
        );

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Content-Length
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        Request::new(
            RequestLine::new(Method::Refer, dialog.remote_target.clone()),
            headers,
            Bytes::new(),
        )
    }

    /// Creates a MESSAGE request for instant messaging (RFC 3428).
    ///
    /// MESSAGE requests don't establish dialogs and operate in "pager mode".
    /// Each message stands alone, similar to SMS/pager messages.
    ///
    /// # Arguments
    /// * `target_uri` - Recipient's URI (Request-URI)
    /// * `content_type` - MIME type of the message body (typically "text/plain")
    /// * `body` - Message content
    ///
    /// # Size Limitations
    /// Per RFC 3428, MESSAGE requests MUST NOT exceed 1300 bytes unless you have
    /// positive knowledge that the path supports larger messages. This implementation
    /// does NOT enforce the size limit automatically.
    ///
    /// # Returns
    /// A MESSAGE request ready to send
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sip_uac::UserAgentClient;
    /// use sip_core::SipUri;
    ///
    /// let uac = UserAgentClient::new(
    ///     SipUri::parse("sip:alice@example.com").unwrap(),
    ///     SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
    /// );
    ///
    /// let message = uac.create_message(
    ///     &SipUri::parse("sip:bob@example.com").unwrap(),
    ///     "text/plain",
    ///     "Hello Bob!"
    /// );
    /// ```
    pub fn create_message(&self, target_uri: &SipUri, content_type: &str, body: &str) -> Request {
        let mut headers = Headers::new();

        // Via header (will be filled by transport layer)
        let branch = generate_branch();
        headers.push(
            SmolStr::new("Via"),
            SmolStr::new(format!("SIP/2.0/UDP placeholder;branch={}", branch)),
        );

        // From header with tag
        let from = self.format_from_header();
        headers.push(SmolStr::new("From"), SmolStr::new(from));

        // To header (no tag for out-of-dialog MESSAGE)
        headers.push(
            SmolStr::new("To"),
            SmolStr::new(format!("<{}>", target_uri.as_str())),
        );

        // Call-ID
        let call_id = generate_call_id();
        headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id));

        // CSeq
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 MESSAGE".to_owned()));

        // Max-Forwards
        headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70".to_owned()));

        // Content-Type
        headers.push(
            SmolStr::new("Content-Type"),
            SmolStr::new(content_type.to_owned()),
        );

        // Content-Length
        headers.push(
            SmolStr::new("Content-Length"),
            SmolStr::new(body.len().to_string()),
        );

        // NOTE: RFC 3428 explicitly forbids Contact header in MESSAGE requests
        // "User Agents MUST NOT insert Contact header fields into MESSAGE requests"

        Request::new(
            RequestLine::new(Method::Message, target_uri.clone()),
            headers,
            Bytes::from(body.to_owned()),
        )
    }

    /// Creates a MESSAGE request with custom headers.
    ///
    /// This allows setting additional headers like Date, Expires, etc.
    ///
    /// # Arguments
    /// * `target_uri` - Recipient's URI
    /// * `content_type` - MIME type of the message body
    /// * `body` - Message content
    /// * `extra_headers` - Additional headers to include
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sip_uac::UserAgentClient;
    /// use sip_core::{SipUri, Headers};
    /// use smol_str::SmolStr;
    ///
    /// let uac = UserAgentClient::new(
    ///     SipUri::parse("sip:alice@example.com").unwrap(),
    ///     SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
    /// );
    ///
    /// let mut extra_headers = Headers::new();
    /// extra_headers.push(SmolStr::new("Expires".to_owned()), SmolStr::new("300".to_owned()));
    /// extra_headers.push(SmolStr::new("Date".to_owned()), SmolStr::new("Wed, 21 Jan 2025 12:00:00 GMT".to_owned()));
    ///
    /// let message = uac.create_message_with_headers(
    ///     &SipUri::parse("sip:bob@example.com").unwrap(),
    ///     "text/plain",
    ///     "Hello Bob!",
    ///     extra_headers
    /// );
    /// ```
    pub fn create_message_with_headers(
        &self,
        target_uri: &SipUri,
        content_type: &str,
        body: &str,
        extra_headers: Headers,
    ) -> Request {
        let mut request = self.create_message(target_uri, content_type, body);

        // Add extra headers
        for header in extra_headers.iter() {
            request
                .headers
                .push(header.name.clone(), header.value.clone());
        }

        request
    }

    fn format_from_header(&self) -> String {
        if let Some(ref display) = self.display_name {
            format!(
                "\"{}\" <{}>;tag={}",
                display,
                self.local_uri.as_str(),
                self.local_tag.as_str()
            )
        } else {
            format!(
                "<{}>;tag={}",
                self.local_uri.as_str(),
                self.local_tag.as_str()
            )
        }
    }
}

/// Helper to generate a random tag.
fn generate_tag() -> SmolStr {
    let tag: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    SmolStr::new(tag)
}

/// Helper to generate a branch parameter (RFC 3261 magic cookie).
fn generate_branch() -> String {
    let random: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    format!("z9hG4bK{}", random)
}

/// Helper to generate a Call-ID.
fn generate_call_id() -> String {
    let random: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    format!("{}@localhost", random)
}

/// Parse WWW-Authenticate header into key-value pairs.
fn parse_www_authenticate(value: &SmolStr) -> Result<std::collections::HashMap<String, String>> {
    use std::collections::HashMap;

    let mut map = HashMap::new();

    // Simple parser for Digest challenges
    if !value.starts_with("Digest ") {
        return Err(anyhow!("Not a Digest challenge"));
    }

    let params = &value[7..]; // Skip "Digest "

    for param in params.split(',') {
        let trimmed = param.trim();
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos + 1..].trim();

            // Remove quotes if present
            let value = if value.starts_with('"') && value.ends_with('"') {
                value[1..value.len() - 1].to_string()
            } else {
                value.to_string()
            };

            map.insert(key, value);
        }
    }

    Ok(map)
}

/// Extract To URI from response.
fn extract_to_uri(response: &Response) -> Option<SipUri> {
    let to_header = header(&response.headers, "To")?;
    // Simple extraction - look for URI between < >
    let uri_str = if let Some(start) = to_header.find('<') {
        if let Some(end) = to_header[start + 1..].find('>') {
            &to_header[start + 1..start + 1 + end]
        } else {
            return None;
        }
    } else {
        // No brackets, take until semicolon or end
        if let Some(semi) = to_header.find(';') {
            &to_header[..semi]
        } else {
            to_header.as_str()
        }
    };

    SipUri::parse(uri_str.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::StatusLine;

    #[test]
    fn creates_register_request() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let registrar_uri = SipUri::parse("sip:example.com").unwrap();
        let request = uac.create_register(&registrar_uri, 3600);

        assert_eq!(request.start.method, Method::Register);
        assert!(request.headers.get("From").is_some());
        assert!(request.headers.get("To").is_some());
        assert!(request.headers.get("Call-ID").is_some());
        assert!(request.headers.get("CSeq").is_some());
        assert!(request.headers.get("Contact").is_some());

        let contact = request.headers.get("Contact").unwrap();
        assert!(contact.contains("expires=3600"));
    }

    #[test]
    fn creates_invite_request() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_invite(&target_uri, None);

        assert_eq!(request.start.method, Method::Invite);
        assert!(request.headers.get("From").is_some());
        assert!(request.headers.get("To").is_some());
        assert!(request.headers.get("Contact").is_some());
    }

    #[test]
    fn creates_invite_with_sdp() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.100\r\n";
        let request = uac.create_invite(&target_uri, Some(sdp));

        assert_eq!(request.body.len(), sdp.len());
        assert_eq!(
            request.headers.get("Content-Type").unwrap().as_str(),
            "application/sdp"
        );
    }

    #[test]
    fn formats_from_header_with_display_name() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri)
            .with_display_name("Alice Smith".to_string());

        let from = uac.format_from_header();
        assert!(from.contains("\"Alice Smith\""));
        assert!(from.contains("sip:alice@example.com"));
        assert!(from.contains("tag="));
    }

    #[test]
    fn generates_valid_branch() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK"));
        assert!(branch.len() > 7);
    }

    #[test]
    fn generates_valid_tag() {
        let tag = generate_tag();
        assert!(!tag.is_empty());
    }

    #[test]
    fn parses_www_authenticate_header() {
        let auth = SmolStr::new(
            "Digest realm=\"example.com\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\"",
        );
        let parsed = parse_www_authenticate(&auth).unwrap();

        assert_eq!(parsed.get("realm"), Some(&"example.com".to_string()));
        assert_eq!(parsed.get("nonce"), Some(&"abc123".to_string()));
        assert_eq!(parsed.get("algorithm"), Some(&"MD5".to_string()));
        assert_eq!(parsed.get("qop"), Some(&"auth".to_string()));
    }

    #[test]
    fn extracts_to_uri_with_brackets() {
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:bob@example.com>;tag=xyz"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        let uri = extract_to_uri(&response).unwrap();
        assert_eq!(uri.as_str(), "sip:bob@example.com");
    }

    #[test]
    fn extracts_to_uri_without_brackets() {
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("To"),
            SmolStr::new("sip:bob@example.com;tag=xyz"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        let uri = extract_to_uri(&response).unwrap();
        assert_eq!(uri.as_str(), "sip:bob@example.com");
    }

    #[test]
    fn creates_ack_for_early_offer() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Create INVITE with SDP offer (early offer)
        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let sdp_offer = "v=0\r\no=- 123 456 IN IP4 192.168.1.100\r\n";
        let invite = uac.create_invite(&target_uri, Some(sdp_offer));

        // Simulate 200 OK response with SDP answer
        let mut response_headers = Headers::new();
        // Copy required headers from request
        if let Some(from) = invite.headers.get("From") {
            response_headers.push(SmolStr::new("From"), from.clone());
        }
        if let Some(call_id) = invite.headers.get("Call-ID") {
            response_headers.push(SmolStr::new("Call-ID"), call_id.clone());
        }
        if let Some(cseq) = invite.headers.get("CSeq") {
            response_headers.push(SmolStr::new("CSeq"), cseq.clone());
        }
        response_headers.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:bob@example.com>;tag=abc123"),
        );
        response_headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@192.168.1.200:5060>"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            response_headers,
            Bytes::new(),
        );

        // Create dialog
        let dialog = uac.process_invite_response(&invite, &response).unwrap();

        // Create ACK without SDP (early offer - answer was in 200 OK)
        let ack = uac.create_ack(&invite, &response, &dialog, None);

        assert_eq!(ack.start.method, Method::Ack);
        assert_eq!(ack.body.len(), 0);
        assert_eq!(ack.headers.get("Content-Length").unwrap().as_str(), "0");
        assert!(ack.headers.get("Content-Type").is_none());
    }

    #[test]
    fn creates_ack_for_late_offer() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Create INVITE without SDP (late offer)
        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let invite = uac.create_invite(&target_uri, None);

        assert_eq!(invite.body.len(), 0);
        assert!(invite.headers.get("Content-Type").is_none());

        // Simulate 200 OK response with SDP offer
        let mut response_headers = Headers::new();
        // Copy required headers from request
        if let Some(from) = invite.headers.get("From") {
            response_headers.push(SmolStr::new("From"), from.clone());
        }
        if let Some(call_id) = invite.headers.get("Call-ID") {
            response_headers.push(SmolStr::new("Call-ID"), call_id.clone());
        }
        if let Some(cseq) = invite.headers.get("CSeq") {
            response_headers.push(SmolStr::new("CSeq"), cseq.clone());
        }
        response_headers.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:bob@example.com>;tag=abc123"),
        );
        response_headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@192.168.1.200:5060>"),
        );

        let sdp_offer = "v=0\r\no=- 234 567 IN IP4 192.168.1.200\r\n";
        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            response_headers,
            Bytes::from(sdp_offer.as_bytes().to_vec()),
        );

        // Create dialog
        let dialog = uac.process_invite_response(&invite, &response).unwrap();

        // Create ACK with SDP answer (late offer - answer goes in ACK)
        let sdp_answer = "v=0\r\no=- 345 678 IN IP4 192.168.1.100\r\n";
        let ack = uac.create_ack(&invite, &response, &dialog, Some(sdp_answer));

        assert_eq!(ack.start.method, Method::Ack);
        assert_eq!(ack.body.len(), sdp_answer.len());
        assert_eq!(
            ack.headers.get("Content-Type").unwrap().as_str(),
            "application/sdp"
        );
        assert_eq!(
            ack.headers.get("Content-Length").unwrap().as_str(),
            sdp_answer.len().to_string()
        );
    }

    #[test]
    fn creates_subscribe_request() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_subscribe(&target_uri, "refer", 3600);

        assert_eq!(request.start.method, Method::Subscribe);
        assert_eq!(request.headers.get("Event").unwrap().as_str(), "refer");
        assert_eq!(request.headers.get("Expires").unwrap().as_str(), "3600");
        assert!(request.headers.get("Contact").is_some());
    }

    #[test]
    fn creates_refer_request() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Create a mock dialog
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=abc123"),
        );
        headers.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:bob@example.com>;tag=def456"),
        );
        headers.push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"));
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"));
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@192.168.1.200:5060>"),
        );

        let invite = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers.clone(),
            Bytes::new(),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        let dialog = uac.process_invite_response(&invite, &response).unwrap();

        // Create REFER
        let transfer_target = SipUri::parse("sip:charlie@example.com").unwrap();
        let refer = uac.create_refer(&dialog, &transfer_target);

        assert_eq!(refer.start.method, Method::Refer);
        assert!(refer
            .headers
            .get("Refer-To")
            .unwrap()
            .contains("charlie@example.com"));
        assert_eq!(
            refer.headers.get("Call-ID").unwrap().as_str(),
            "test-call-id"
        );
    }

    #[test]
    fn creates_refer_with_replaces() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Create two mock dialogs
        let mut headers1 = Headers::new();
        headers1.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=abc123"),
        );
        headers1.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:bob@example.com>;tag=def456"),
        );
        headers1.push(SmolStr::new("Call-ID"), SmolStr::new("call-1"));
        headers1.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"));
        headers1.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@192.168.1.200:5060>"),
        );

        let invite1 = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers1.clone(),
            Bytes::new(),
        );

        let response1 = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers1,
            Bytes::new(),
        );

        let dialog1 = uac.process_invite_response(&invite1, &response1).unwrap();

        // Second dialog
        let mut headers2 = Headers::new();
        headers2.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=xyz789"),
        );
        headers2.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:charlie@example.com>;tag=uvw321"),
        );
        headers2.push(SmolStr::new("Call-ID"), SmolStr::new("call-2"));
        headers2.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"));
        headers2.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:charlie@192.168.1.300:5060>"),
        );

        let invite2 = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:charlie@example.com").unwrap(),
            ),
            headers2.clone(),
            Bytes::new(),
        );

        let response2 = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers2,
            Bytes::new(),
        );

        let dialog2 = uac.process_invite_response(&invite2, &response2).unwrap();

        // Create REFER with Replaces (attended transfer)
        let transfer_target = SipUri::parse("sip:charlie@example.com").unwrap();
        let refer = uac.create_refer_with_replaces(&dialog1, &transfer_target, &dialog2);

        assert_eq!(refer.start.method, Method::Refer);
        let refer_to = refer.headers.get("Refer-To").unwrap();
        assert!(refer_to.contains("charlie@example.com"));
        assert!(refer_to.contains("Replaces="));
        assert!(refer_to.contains("call-2"));
        assert!(refer.headers.get("Referred-By").is_some());
    }

    #[test]
    fn creates_notify_request() {
        use sip_dialog::SubscriptionState;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri.clone());

        // Create a mock subscription
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=abc123"),
        );
        headers.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:bob@example.com>;tag=def456"),
        );
        headers.push(SmolStr::new("Call-ID"), SmolStr::new("sub-call-id"));
        headers.push(SmolStr::new("CSeq"), SmolStr::new("1 SUBSCRIBE"));
        headers.push(SmolStr::new("Event"), SmolStr::new("refer"));
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@192.168.1.200:5060>"),
        );

        let subscribe = Request::new(
            RequestLine::new(
                Method::Subscribe,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers.clone(),
            Bytes::new(),
        );

        let mut resp_headers = headers.clone();
        resp_headers.push(SmolStr::new("Expires"), SmolStr::new("3600"));

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            resp_headers,
            Bytes::new(),
        );

        let subscription = uac
            .process_subscribe_response(&subscribe, &response)
            .unwrap();

        // Create NOTIFY
        let notify = uac.create_notify(&subscription, SubscriptionState::Active, Some("test body"));

        assert_eq!(notify.start.method, Method::Notify);
        assert_eq!(notify.headers.get("Event").unwrap().as_str(), "refer");
        assert_eq!(
            notify.headers.get("Subscription-State").unwrap().as_str(),
            "active"
        );
        assert_eq!(notify.body.len(), 9); // "test body"
    }

    #[test]
    fn creates_prack_request() {
        use sip_core::RefresherRole;
        use sip_dialog::{Dialog, DialogId, DialogStateType};
        use std::time::Duration;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri.clone())
            .with_display_name("Alice".to_string());

        // Create original INVITE request
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let invite = uac.create_invite(&remote_uri, Some("v=0\r\n"));

        // Mock dialog (early dialog from 180 Ringing)
        let dialog = Dialog {
            id: DialogId {
                call_id: "test-call-id".into(),
                local_tag: "alice-tag".into(),
                remote_tag: "bob-tag".into(),
            },
            state: DialogStateType::Early,
            local_uri: local_uri.clone(),
            remote_uri: remote_uri.clone(),
            remote_target: SipUri::parse("sip:bob@192.168.1.200:5060").unwrap(),
            local_cseq: 1,
            remote_cseq: 0,
            route_set: vec![],
            secure: false,
            session_expires: Some(Duration::from_secs(1800)),
            refresher: Some(RefresherRole::Uac),
            is_uac: true,
        };

        // Create reliable provisional response (180 Ringing with RSeq)
        let mut prov_headers = Headers::new();
        prov_headers.push(
            SmolStr::new("Via"),
            SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
        );
        prov_headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
        );
        prov_headers.push(
            SmolStr::new("To"),
            SmolStr::new("<sip:bob@example.com>;tag=bob-tag"),
        );
        prov_headers.push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"));
        prov_headers.push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"));
        prov_headers.push(SmolStr::new("RSeq"), SmolStr::new("1"));
        prov_headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@192.168.1.200:5060>"),
        );

        let reliable_provisional = Response::new(
            StatusLine::new(180, SmolStr::new("Ringing")),
            prov_headers,
            Bytes::new(),
        );

        // Create PRACK
        let prack = uac
            .create_prack(&invite, &reliable_provisional, &dialog)
            .unwrap();

        // Verify PRACK request
        assert_eq!(prack.start.method, Method::Prack);
        assert_eq!(prack.start.uri.as_str(), "sip:bob@192.168.1.200:5060");

        // Verify RAck header: RSeq CSeq-number Method
        let rack = prack.headers.get("RAck").unwrap();
        assert_eq!(rack.as_str(), "1 1 INVITE");

        // Verify dialog tags
        assert!(prack.headers.get("From").unwrap().contains("alice-tag"));
        assert!(prack.headers.get("To").unwrap().contains("bob-tag"));

        // Verify Call-ID matches
        assert_eq!(
            prack.headers.get("Call-ID").unwrap().as_str(),
            "test-call-id"
        );

        // Verify CSeq is for PRACK
        let cseq = prack.headers.get("CSeq").unwrap();
        assert!(cseq.contains("PRACK"));
    }

    #[test]
    fn creates_info_request() {
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let dialog = Dialog {
            id: DialogId {
                call_id: "test-call-id".into(),
                local_tag: "alice-tag".into(),
                remote_tag: "bob-tag".into(),
            },
            state: DialogStateType::Confirmed,
            local_uri: local_uri.clone(),
            remote_uri: remote_uri.clone(),
            remote_target: SipUri::parse("sip:bob@192.168.1.200:5060").unwrap(),
            local_cseq: 1,
            remote_cseq: 0,
            route_set: vec![],
            secure: false,
            session_expires: None,
            refresher: None,
            is_uac: true,
        };

        // Create INFO with DTMF payload
        let dtmf_body = "Signal=1\r\nDuration=100\r\n";
        let info = uac.create_info(&dialog, "application/dtmf-relay", dtmf_body);

        // Verify INFO request
        assert_eq!(info.start.method, Method::Info);
        assert_eq!(info.start.uri.as_str(), "sip:bob@192.168.1.200:5060");

        // Verify headers
        assert!(info.headers.get("From").unwrap().contains("alice-tag"));
        assert!(info.headers.get("To").unwrap().contains("bob-tag"));
        assert_eq!(
            info.headers.get("Call-ID").unwrap().as_str(),
            "test-call-id"
        );

        // Verify CSeq is incremented (was 1, should be 2)
        let cseq = info.headers.get("CSeq").unwrap();
        assert!(cseq.contains("2 INFO"));

        // Verify Content-Type
        assert_eq!(
            info.headers.get("Content-Type").unwrap().as_str(),
            "application/dtmf-relay"
        );

        // Verify Content-Length
        assert_eq!(
            info.headers.get("Content-Length").unwrap().as_str(),
            dtmf_body.len().to_string()
        );

        // Verify body
        assert_eq!(String::from_utf8_lossy(&info.body), dtmf_body);
    }

    #[test]
    fn creates_info_with_json_payload() {
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let dialog = Dialog {
            id: DialogId {
                call_id: "test-call-id".into(),
                local_tag: "alice-tag".into(),
                remote_tag: "bob-tag".into(),
            },
            state: DialogStateType::Confirmed,
            local_uri: local_uri.clone(),
            remote_uri: remote_uri.clone(),
            remote_target: SipUri::parse("sip:bob@192.168.1.200:5060").unwrap(),
            local_cseq: 5,
            remote_cseq: 0,
            route_set: vec![],
            secure: false,
            session_expires: None,
            refresher: None,
            is_uac: true,
        };

        // Create INFO with JSON payload
        let json_body = r#"{"action":"mute","value":true}"#;
        let info = uac.create_info(&dialog, "application/json", json_body);

        // Verify method
        assert_eq!(info.start.method, Method::Info);

        // Verify Content-Type
        assert_eq!(
            info.headers.get("Content-Type").unwrap().as_str(),
            "application/json"
        );

        // Verify body
        assert_eq!(String::from_utf8_lossy(&info.body), json_body);

        // Verify CSeq is incremented (was 5, should be 6)
        let cseq = info.headers.get("CSeq").unwrap();
        assert!(cseq.contains("6 INFO"));
    }

    #[test]
    fn adds_privacy_header_to_request() {
        use sip_core::PrivacyValue;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let mut invite = uac.create_invite(&remote_uri, None);

        // Add Privacy header
        UserAgentClient::add_privacy_header(&mut invite, vec![PrivacyValue::Id]);

        // Verify Privacy header is present
        let privacy = invite.headers.get("Privacy").unwrap();
        assert_eq!(privacy.as_str(), "id");
    }

    #[test]
    fn adds_multiple_privacy_values() {
        use sip_core::PrivacyValue;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let mut invite = uac.create_invite(&remote_uri, None);

        // Add multiple Privacy values
        UserAgentClient::add_privacy_header(
            &mut invite,
            vec![PrivacyValue::Id, PrivacyValue::Critical],
        );

        // Verify Privacy header
        let privacy = invite.headers.get("Privacy").unwrap();
        assert_eq!(privacy.as_str(), "id; critical");
    }

    #[test]
    fn with_privacy_creates_request_with_header() {
        use sip_core::PrivacyValue;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let invite = uac.create_invite(&remote_uri, None);

        // Create request with Privacy
        let private_invite = UserAgentClient::with_privacy(
            invite,
            vec![PrivacyValue::Header, PrivacyValue::Session],
        );

        // Verify Privacy header
        let privacy = private_invite.headers.get("Privacy").unwrap();
        assert_eq!(privacy.as_str(), "header; session");
        assert_eq!(private_invite.start.method, Method::Invite);
    }

    #[test]
    fn adds_privacy_to_register() {
        use sip_core::PrivacyValue;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let registrar_uri = SipUri::parse("sip:registrar.example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let mut register = uac.create_register(&registrar_uri, 3600);

        // Add Privacy header to REGISTER
        UserAgentClient::add_privacy_header(&mut register, vec![PrivacyValue::Id]);

        // Verify
        assert_eq!(register.start.method, Method::Register);
        let privacy = register.headers.get("Privacy").unwrap();
        assert_eq!(privacy.as_str(), "id");
    }

    #[test]
    fn adds_reason_header_to_bye() {
        use sip_core::{Q850Cause, ReasonHeader};
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let dialog = Dialog {
            id: DialogId {
                call_id: "test-call-id".into(),
                local_tag: "alice-tag".into(),
                remote_tag: "bob-tag".into(),
            },
            state: DialogStateType::Confirmed,
            local_uri: local_uri.clone(),
            remote_uri: remote_uri.clone(),
            remote_target: SipUri::parse("sip:bob@192.168.1.200:5060").unwrap(),
            local_cseq: 1,
            remote_cseq: 0,
            route_set: vec![],
            secure: false,
            session_expires: None,
            refresher: None,
            is_uac: true,
        };

        let mut bye = uac.create_bye(&dialog);

        // Add Reason header
        let reason = ReasonHeader::q850(Q850Cause::NormalCallClearing);
        UserAgentClient::add_reason_header(&mut bye, reason);

        // Verify Reason header
        let reason_header = bye.headers.get("Reason").unwrap();
        assert_eq!(
            reason_header.as_str(),
            "Q.850;cause=16;text=\"Normal Call Clearing\""
        );
    }

    #[test]
    fn creates_bye_with_reason_q850() {
        use sip_core::{Q850Cause, ReasonHeader};
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let dialog = Dialog {
            id: DialogId {
                call_id: "test-call-id".into(),
                local_tag: "alice-tag".into(),
                remote_tag: "bob-tag".into(),
            },
            state: DialogStateType::Confirmed,
            local_uri: local_uri.clone(),
            remote_uri: remote_uri.clone(),
            remote_target: SipUri::parse("sip:bob@192.168.1.200:5060").unwrap(),
            local_cseq: 5,
            remote_cseq: 0,
            route_set: vec![],
            secure: false,
            session_expires: None,
            refresher: None,
            is_uac: true,
        };

        // Create BYE with reason
        let reason = ReasonHeader::q850(Q850Cause::UserBusy);
        let bye = uac.create_bye_with_reason(&dialog, reason);

        // Verify BYE request
        assert_eq!(bye.start.method, Method::Bye);
        assert_eq!(bye.start.uri.as_str(), "sip:bob@192.168.1.200:5060");

        // Verify Reason header
        let reason_header = bye.headers.get("Reason").unwrap();
        assert_eq!(reason_header.as_str(), "Q.850;cause=17;text=\"User Busy\"");

        // Verify other headers
        assert!(bye.headers.get("From").unwrap().contains("alice-tag"));
        assert!(bye.headers.get("To").unwrap().contains("bob-tag"));
        assert_eq!(bye.headers.get("Call-ID").unwrap().as_str(), "test-call-id");
    }

    #[test]
    fn creates_bye_with_reason_sip() {
        use sip_core::ReasonHeader;
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let dialog = Dialog {
            id: DialogId {
                call_id: "test-call-id".into(),
                local_tag: "alice-tag".into(),
                remote_tag: "bob-tag".into(),
            },
            state: DialogStateType::Confirmed,
            local_uri: local_uri.clone(),
            remote_uri: remote_uri.clone(),
            remote_target: SipUri::parse("sip:bob@192.168.1.200:5060").unwrap(),
            local_cseq: 1,
            remote_cseq: 0,
            route_set: vec![],
            secure: false,
            session_expires: None,
            refresher: None,
            is_uac: true,
        };

        // Create BYE with SIP reason code
        let reason = ReasonHeader::sip(480, None);
        let bye = uac.create_bye_with_reason(&dialog, reason);

        // Verify method
        assert_eq!(bye.start.method, Method::Bye);

        // Verify Reason header
        let reason_header = bye.headers.get("Reason").unwrap();
        assert_eq!(
            reason_header.as_str(),
            "SIP;cause=480;text=\"Temporarily Unavailable\""
        );
    }

    #[test]
    fn adds_reason_to_any_request() {
        use sip_core::{Q850Cause, ReasonHeader};

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let mut invite = uac.create_invite(&remote_uri, None);

        // Add Reason to INVITE (unusual but possible for forked calls)
        let reason = ReasonHeader::q850(Q850Cause::CallRejected);
        UserAgentClient::add_reason_header(&mut invite, reason);

        // Verify
        assert_eq!(invite.start.method, Method::Invite);
        let reason_header = invite.headers.get("Reason").unwrap();
        assert_eq!(
            reason_header.as_str(),
            "Q.850;cause=21;text=\"Call Rejected\""
        );
    }

    #[test]
    fn adds_p_preferred_identity_sip() {
        use sip_core::PPreferredIdentityHeader;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let mut invite = uac.create_invite(&remote_uri, None);

        // Add P-Preferred-Identity with SIP URI
        let preferred_uri = SipUri::parse("sip:alice.smith@company.com").unwrap();
        let ppi = PPreferredIdentityHeader::single_sip(preferred_uri);
        UserAgentClient::add_p_preferred_identity_header(&mut invite, ppi);

        // Verify
        assert_eq!(invite.start.method, Method::Invite);
        let ppi_header = invite.headers.get("P-Preferred-Identity").unwrap();
        assert!(ppi_header.as_str().contains("sip:alice.smith@company.com"));
    }

    #[test]
    fn adds_p_preferred_identity_tel() {
        use sip_core::PPreferredIdentityHeader;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let mut invite = uac.create_invite(&remote_uri, None);

        // Add P-Preferred-Identity with Tel URI
        let ppi = PPreferredIdentityHeader::single_tel("+15551234567");
        UserAgentClient::add_p_preferred_identity_header(&mut invite, ppi);

        // Verify
        assert_eq!(invite.start.method, Method::Invite);
        let ppi_header = invite.headers.get("P-Preferred-Identity").unwrap();
        assert!(ppi_header.as_str().contains("tel:+15551234567"));
    }

    #[test]
    fn with_p_preferred_identity() {
        use sip_core::PPreferredIdentityHeader;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let invite = uac.create_invite(&remote_uri, None);

        // Create with P-Preferred-Identity
        let preferred_uri = SipUri::parse("sip:alice.smith@company.com").unwrap();
        let ppi = PPreferredIdentityHeader::single_sip(preferred_uri);
        let invite = UserAgentClient::with_p_preferred_identity(invite, ppi);

        // Verify
        assert_eq!(invite.start.method, Method::Invite);
        let ppi_header = invite.headers.get("P-Preferred-Identity").unwrap();
        assert!(ppi_header.as_str().contains("sip:alice.smith@company.com"));
    }

    #[test]
    fn adds_p_asserted_identity() {
        use sip_core::PAssertedIdentityHeader;

        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);
        let mut invite = uac.create_invite(&remote_uri, None);

        // Add P-Asserted-Identity (for testing/proxy use)
        let asserted_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let pai = PAssertedIdentityHeader::sip_and_tel(asserted_uri, "+15551234567");
        UserAgentClient::add_p_asserted_identity_header(&mut invite, pai);

        // Verify
        assert_eq!(invite.start.method, Method::Invite);
        let pai_header = invite.headers.get("P-Asserted-Identity").unwrap();
        assert!(pai_header.as_str().contains("sip:alice@example.com"));
        assert!(pai_header.as_str().contains("tel:+15551234567"));
    }

    #[test]
    fn creates_message_request() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_message(&target_uri, "text/plain", "Hello, Bob!");

        assert_eq!(request.start.method, Method::Message);
        assert_eq!(request.body.len(), 11); // "Hello, Bob!" length
        assert!(request.headers.get("From").is_some());
        assert!(request.headers.get("To").is_some());
        assert!(request.headers.get("Call-ID").is_some());
        assert!(request.headers.get("CSeq").is_some());
        assert_eq!(request.headers.get("CSeq").unwrap().as_str(), "1 MESSAGE");
        assert_eq!(
            request.headers.get("Content-Type").unwrap().as_str(),
            "text/plain"
        );
        assert_eq!(
            request.headers.get("Content-Length").unwrap().as_str(),
            "11"
        );
    }

    #[test]
    fn message_has_no_contact_header() {
        // RFC 3428: User Agents MUST NOT insert Contact header fields into MESSAGE requests
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_message(&target_uri, "text/plain", "Test message");

        // Verify Contact header is NOT present
        assert!(request.headers.get("Contact").is_none());
    }

    #[test]
    fn creates_message_with_html_content() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let html_body = "<html><body><h1>Hello</h1></body></html>";
        let request = uac.create_message(&target_uri, "text/html", html_body);

        assert_eq!(request.start.method, Method::Message);
        assert_eq!(
            request.headers.get("Content-Type").unwrap().as_str(),
            "text/html"
        );
        assert_eq!(request.body.len(), html_body.len());
        assert_eq!(String::from_utf8_lossy(&request.body), html_body);
    }

    #[test]
    fn creates_message_with_custom_headers() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();

        // Create custom headers
        let mut extra_headers = Headers::new();
        extra_headers.push(
            SmolStr::new("Date"),
            SmolStr::new("Wed, 15 Jan 2025 10:00:00 GMT"),
        );
        extra_headers.push(SmolStr::new("Expires"), SmolStr::new("3600"));

        let request = uac.create_message_with_headers(
            &target_uri,
            "text/plain",
            "Urgent message",
            extra_headers,
        );

        assert_eq!(request.start.method, Method::Message);
        assert!(request.headers.get("Date").is_some());
        assert_eq!(
            request.headers.get("Date").unwrap().as_str(),
            "Wed, 15 Jan 2025 10:00:00 GMT"
        );
        assert!(request.headers.get("Expires").is_some());
        assert_eq!(request.headers.get("Expires").unwrap().as_str(), "3600");
    }

    #[test]
    fn message_has_required_headers() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_message(&target_uri, "text/plain", "Test");

        // Verify all required headers per RFC 3428
        assert!(request.headers.get("Via").is_some());
        assert!(request.headers.get("From").is_some());
        assert!(request.headers.get("To").is_some());
        assert!(request.headers.get("Call-ID").is_some());
        assert!(request.headers.get("CSeq").is_some());
        assert!(request.headers.get("Max-Forwards").is_some());
        assert!(request.headers.get("Content-Type").is_some());
        assert!(request.headers.get("Content-Length").is_some());

        // Verify Max-Forwards value
        assert_eq!(request.headers.get("Max-Forwards").unwrap().as_str(), "70");
    }

    #[test]
    fn message_to_header_has_no_tag() {
        // MESSAGE is out-of-dialog, so To header should not have a tag
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_message(&target_uri, "text/plain", "Hello");

        let to_header = request.headers.get("To").unwrap();
        assert!(to_header.contains("sip:bob@example.com"));
        assert!(!to_header.contains("tag="));
    }

    #[test]
    fn message_from_header_has_tag() {
        // From header should always have a tag
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_message(&target_uri, "text/plain", "Hello");

        let from_header = request.headers.get("From").unwrap();
        assert!(from_header.contains("sip:alice@example.com"));
        assert!(from_header.contains("tag="));
    }

    #[test]
    fn creates_message_with_empty_body() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let request = uac.create_message(&target_uri, "text/plain", "");

        assert_eq!(request.body.len(), 0);
        assert_eq!(request.headers.get("Content-Length").unwrap().as_str(), "0");
        assert_eq!(
            request.headers.get("Content-Type").unwrap().as_str(),
            "text/plain"
        );
    }

    #[test]
    fn processes_service_route_from_register_response() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let mut uac = UserAgentClient::new(local_uri, contact_uri);

        // Initially no service route
        assert!(uac.get_service_route().is_none());

        // Create 200 OK response with Service-Route
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Service-Route"),
            SmolStr::new("<sip:proxy.example.com;lr>"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        // Process response
        uac.process_register_response(&response);

        // Should now have service route stored
        assert!(uac.get_service_route().is_some());
        let service_route = uac.get_service_route().unwrap();
        assert_eq!(service_route.len(), 1);
        assert!(service_route.routes[0]
            .uri
            .as_str()
            .contains("proxy.example.com"));
    }

    #[test]
    fn processes_multiple_service_routes() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let mut uac = UserAgentClient::new(local_uri, contact_uri);

        // Create 200 OK response with multiple Service-Route entries
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Service-Route"),
            SmolStr::new("<sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        uac.process_register_response(&response);

        let service_route = uac.get_service_route().unwrap();
        assert_eq!(service_route.len(), 2);
        assert!(service_route.routes[0]
            .uri
            .as_str()
            .contains("proxy1.example.com"));
        assert!(service_route.routes[1]
            .uri
            .as_str()
            .contains("proxy2.example.com"));
    }

    #[test]
    fn clears_service_route_when_not_present() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let mut uac = UserAgentClient::new(local_uri, contact_uri);

        // First, set a service route
        let mut headers1 = Headers::new();
        headers1.push(
            SmolStr::new("Service-Route"),
            SmolStr::new("<sip:proxy.example.com;lr>"),
        );

        let response1 = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers1,
            Bytes::new(),
        );

        uac.process_register_response(&response1);
        assert!(uac.get_service_route().is_some());

        // Now send response without Service-Route
        let headers2 = Headers::new();
        let response2 = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers2,
            Bytes::new(),
        );

        uac.process_register_response(&response2);

        // Service route should be cleared
        assert!(uac.get_service_route().is_none());
    }

    #[test]
    fn ignores_non_200_responses_for_service_route() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let mut uac = UserAgentClient::new(local_uri, contact_uri);

        // Create 401 response with Service-Route (shouldn't be processed)
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Service-Route"),
            SmolStr::new("<sip:proxy.example.com;lr>"),
        );

        let response = Response::new(
            StatusLine::new(401, SmolStr::new("Unauthorized")),
            headers,
            Bytes::new(),
        );

        uac.process_register_response(&response);

        // Should not store service route from non-200 response
        assert!(uac.get_service_route().is_none());
    }

    #[test]
    fn applies_service_route_to_request() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let mut uac = UserAgentClient::new(local_uri, contact_uri);

        // Set up service route
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Service-Route"),
            SmolStr::new("<sip:proxy.example.com;lr>"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        uac.process_register_response(&response);

        // Create a request
        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let mut invite = uac.create_invite(&target_uri, None);

        // Initially no Route header
        assert!(invite.headers.get("Route").is_none());

        // Apply service route
        uac.apply_service_route(&mut invite);

        // Should now have Route header
        let route_header = invite.headers.get("Route").unwrap();
        assert!(route_header.contains("proxy.example.com"));
        assert!(route_header.contains("lr"));
    }

    #[test]
    fn applies_multiple_service_routes_in_order() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let mut uac = UserAgentClient::new(local_uri, contact_uri);

        // Set up multiple service routes
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Service-Route"),
            SmolStr::new("<sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        uac.process_register_response(&response);

        // Create a request
        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let mut invite = uac.create_invite(&target_uri, None);

        // Apply service route
        uac.apply_service_route(&mut invite);

        // Should have multiple Route headers in order
        let routes: Vec<_> = invite.headers.get_all("Route").collect();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains("proxy1.example.com"));
        assert!(routes[1].contains("proxy2.example.com"));
    }

    #[test]
    fn apply_service_route_does_nothing_when_not_set() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let uac = UserAgentClient::new(local_uri, contact_uri);

        // No service route set
        assert!(uac.get_service_route().is_none());

        // Create a request
        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let mut invite = uac.create_invite(&target_uri, None);

        // Apply service route (should do nothing)
        uac.apply_service_route(&mut invite);

        // Should still have no Route header
        assert!(invite.headers.get("Route").is_none());
    }

    #[test]
    fn service_route_with_message_request() {
        let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();

        let mut uac = UserAgentClient::new(local_uri, contact_uri);

        // Set up service route
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Service-Route"),
            SmolStr::new("<sip:im-proxy.example.com;lr>"),
        );

        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        );

        uac.process_register_response(&response);

        // Create MESSAGE request
        let target_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let mut message = uac.create_message(&target_uri, "text/plain", "Hello!");

        // Apply service route
        uac.apply_service_route(&mut message);

        // Should have Route header for IM proxy
        let route_header = message.headers.get("Route").unwrap();
        assert!(route_header.contains("im-proxy.example.com"));
    }
}
