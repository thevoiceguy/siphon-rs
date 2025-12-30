// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! UAS (User Agent Server) helper for receiving and responding to SIP requests.
//!
//! Provides high-level APIs for handling INVITE, BYE, SUBSCRIBE, REFER, and PRACK
//! with automatic dialog management, authentication, and reliable provisional responses.
//!
//! # Example
//! ```
//! use sip_uas::UserAgentServer;
//! # use sip_core::SipUri;
//! let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
//! let contact_uri = SipUri::parse("sip:bob@192.168.1.100").unwrap();
//! let uas = UserAgentServer::new(local_uri, contact_uri);
//! ```

pub mod integrated;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use sip_auth::Authenticator;
use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri, StatusLine};
use sip_dialog::prack_validator::PrackValidator;
use sip_dialog::session_timer_manager::validate_session_expires;
use sip_dialog::{Dialog, DialogManager, RSeqManager, Subscription, SubscriptionManager};
use sip_parse::{header, parse_session_expires};
pub use sip_sdp::profiles::{MediaProfileBuilder, SdpProfile};
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

// Security constants for DoS prevention and input validation
const MAX_REASON_PHRASE_LENGTH: usize = 128;
const MAX_SIP_ETAG_LENGTH: usize = 256;
const MAX_BODY_LENGTH: usize = 1_048_576; // 1 MB max body
const MAX_USER_AGENT_LENGTH: usize = 256;

/// Error type for UAS operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UasError {
    /// Reason phrase contains control characters
    ReasonPhraseContainsControlChars,
    /// Reason phrase exceeds maximum length
    ReasonPhraseTooLong { max: usize, actual: usize },
    /// SIP-ETag contains control characters
    SipETagContainsControlChars,
    /// SIP-ETag exceeds maximum length
    SipETagTooLong { max: usize, actual: usize },
    /// Body exceeds maximum length
    BodyTooLong { max: usize, actual: usize },
    /// User-Agent contains control characters
    UserAgentContainsControlChars,
    /// User-Agent exceeds maximum length
    UserAgentTooLong { max: usize, actual: usize },
}

impl std::fmt::Display for UasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UasError::ReasonPhraseContainsControlChars => {
                write!(f, "Reason phrase contains control characters")
            }
            UasError::ReasonPhraseTooLong { max, actual } => {
                write!(
                    f,
                    "Reason phrase too long (max: {}, actual: {})",
                    max, actual
                )
            }
            UasError::SipETagContainsControlChars => {
                write!(f, "SIP-ETag contains control characters")
            }
            UasError::SipETagTooLong { max, actual } => {
                write!(f, "SIP-ETag too long (max: {}, actual: {})", max, actual)
            }
            UasError::BodyTooLong { max, actual } => {
                write!(f, "Body too long (max: {}, actual: {})", max, actual)
            }
            UasError::UserAgentContainsControlChars => {
                write!(f, "User-Agent contains control characters")
            }
            UasError::UserAgentTooLong { max, actual } => {
                write!(f, "User-Agent too long (max: {}, actual: {})", max, actual)
            }
        }
    }
}

impl std::error::Error for UasError {}

// Validation functions
fn validate_reason_phrase(phrase: &str) -> std::result::Result<(), UasError> {
    if phrase.len() > MAX_REASON_PHRASE_LENGTH {
        return Err(UasError::ReasonPhraseTooLong {
            max: MAX_REASON_PHRASE_LENGTH,
            actual: phrase.len(),
        });
    }
    if phrase.chars().any(|c| c.is_control()) {
        return Err(UasError::ReasonPhraseContainsControlChars);
    }
    Ok(())
}

fn validate_sip_etag(etag: &str) -> std::result::Result<(), UasError> {
    if etag.len() > MAX_SIP_ETAG_LENGTH {
        return Err(UasError::SipETagTooLong {
            max: MAX_SIP_ETAG_LENGTH,
            actual: etag.len(),
        });
    }
    if etag.chars().any(|c| c.is_control()) {
        return Err(UasError::SipETagContainsControlChars);
    }
    Ok(())
}

fn validate_body(body: &str) -> std::result::Result<(), UasError> {
    if body.len() > MAX_BODY_LENGTH {
        return Err(UasError::BodyTooLong {
            max: MAX_BODY_LENGTH,
            actual: body.len(),
        });
    }
    Ok(())
}

fn validate_user_agent(agent: &str) -> std::result::Result<(), UasError> {
    if agent.len() > MAX_USER_AGENT_LENGTH {
        return Err(UasError::UserAgentTooLong {
            max: MAX_USER_AGENT_LENGTH,
            actual: agent.len(),
        });
    }
    if agent.chars().any(|c| c.is_control()) {
        return Err(UasError::UserAgentContainsControlChars);
    }
    Ok(())
}

/// Trait implemented by SIP applications that consume transactions.
pub trait TransactionUser: Send + Sync {
    fn on_request(&self, request: &Request) -> Result<Response>;
}

/// Application-level hook for dialog lifecycle notifications.
pub trait Application: Send + Sync {
    fn on_new_dialog(&self, response: &Response);
}

/// UAS (User Agent Server) helper for receiving and responding to SIP requests.
///
/// Provides high-level APIs for handling INVITE, BYE, and other requests,
/// with automatic dialog management and authentication.
pub struct UserAgentServer {
    /// Local SIP URI (To/Contact)
    pub local_uri: SipUri,

    /// Contact URI for responses
    pub contact_uri: SipUri,

    /// Dialog manager for call state
    pub dialog_manager: Arc<DialogManager>,

    /// Subscription manager for event subscriptions (RFC 3265)
    pub subscription_manager: Arc<SubscriptionManager>,

    /// RSeq manager for reliable provisional responses (RFC 3262)
    pub rseq_manager: Arc<RSeqManager>,

    /// PRACK validator for reliable provisional responses (RFC 3262)
    pub prack_validator: Arc<PrackValidator>,

    /// Optional authenticator for challenge/response
    authenticator: Option<Arc<dyn Authenticator>>,
}

impl UserAgentServer {
    /// Creates a new UAS with the given local URI and contact.
    pub fn new(local_uri: SipUri, contact_uri: SipUri) -> Self {
        Self {
            local_uri,
            contact_uri,
            dialog_manager: Arc::new(DialogManager::new()),
            subscription_manager: Arc::new(SubscriptionManager::new()),
            rseq_manager: Arc::new(RSeqManager::new()),
            prack_validator: Arc::new(PrackValidator::new()),
            authenticator: None,
        }
    }

    /// Configures an authenticator for 401 challenges.
    pub fn with_authenticator(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Creates a generic response with the given status code and reason.
    ///
    /// # Arguments
    /// * `request` - The request to respond to
    /// * `code` - Status code (e.g., 200, 404, 500)
    /// * `reason` - Reason phrase (e.g., "OK", "Not Found")
    ///
    /// # Returns
    /// A response with standard headers copied from the request
    pub fn create_response(request: &Request, code: u16, reason: &str) -> Response {
        let mut headers = Headers::new();

        // Copy Via, From, Call-ID, CSeq from request
        for via in request.headers().get_all_smol("Via") {
            headers.push(SmolStr::new("Via"), via).unwrap();
        }
        if let Some(from) = request.headers().get("From") {
            headers.push(SmolStr::new("From"), from).unwrap();
        }
        if let Some(call_id) = request.headers().get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id).unwrap();
        }
        if let Some(cseq) = request.headers().get("CSeq") {
            headers.push(SmolStr::new("CSeq"), cseq).unwrap();
        }

        // Add To header (without tag for now - will be added by specific methods)
        if let Some(to) = request.headers().get("To") {
            headers.push(SmolStr::new("To"), to).unwrap();
        }

        // Content-Length
        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();

        Response::new(
            StatusLine::new(code, reason).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response")
    }

    /// Creates a 100 Trying response.
    pub fn create_trying(request: &Request) -> Response {
        Self::create_response(request, 100, "Trying")
    }

    /// Creates a 180 Ringing response.
    pub fn create_ringing(&self, request: &Request) -> Response {
        let mut response = Self::create_response(request, 180, "Ringing");
        self.ensure_to_tag(&mut response);
        response
    }

    /// Creates a 200 OK response with optional body.
    ///
    /// # Arguments
    /// * `request` - The request to respond to
    /// * `body` - Optional SDP or other body content
    ///
    /// # Returns
    /// A 200 OK response
    pub fn create_ok(
        &self,
        request: &Request,
        body: Option<&str>,
    ) -> std::result::Result<Response, UasError> {
        // Validate body if provided
        if let Some(body_content) = body {
            validate_body(body_content)?;
        }

        let mut response = Self::create_response(request, 200, "OK");

        // Add Contact header
        response
            .headers_mut()
            .push(
                SmolStr::new("Contact"),
                SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
            )
            .unwrap();

        // Add tag to To header if not present
        self.ensure_to_tag(&mut response);

        // Add body if provided
        if let Some(body_content) = body {
            // Update Content-Length
            let content_length = body_content.len().to_string();
            response
                .headers_mut()
                .set_or_push("Content-Length", &content_length)
                .expect("content-length should be valid");

            // Add Content-Type for SDP
            response
                .headers_mut()
                .push(
                    SmolStr::new("Content-Type"),
                    SmolStr::new("application/sdp"),
                )
                .unwrap();

            let (start, headers, _) = response.into_parts();
            response = Response::new(
                start,
                headers,
                Bytes::from(body_content.as_bytes().to_vec()),
            )
            .expect("valid response");
        }

        Ok(response)
    }

    /// Creates a 200 OK response for MESSAGE requests.
    pub fn accept_message(&self, request: &Request) -> Response {
        // For MESSAGE, body is not echoed; respond 200 OK with zero Content-Length
        Self::create_response(request, 200, "OK")
    }

    /// Creates a 200 OK response for PUBLISH requests (RFC 3903).
    ///
    /// Optionally sets a SIP-ETag header if provided.
    pub fn accept_publish(
        &self,
        request: &Request,
        sip_etag: Option<&str>,
    ) -> std::result::Result<Response, UasError> {
        // Validate SIP-ETag if provided
        if let Some(etag) = sip_etag {
            validate_sip_etag(etag)?;
        }

        let mut response = Self::create_response(request, 200, "OK");
        if let Some(etag) = sip_etag {
            response
                .headers_mut()
                .push(SmolStr::new("SIP-ETag"), SmolStr::new(etag))
                .unwrap();
        }
        Ok(response)
    }

    /// Creates an error response for MESSAGE or PUBLISH.
    pub fn reject_message_publish(&self, request: &Request, code: u16, reason: &str) -> Response {
        Self::create_response(request, code, reason)
    }

    /// Creates a 401 Unauthorized response with WWW-Authenticate challenge.
    pub fn create_unauthorized(&self, request: &Request) -> Result<Response> {
        let authenticator = self
            .authenticator
            .as_ref()
            .ok_or_else(|| anyhow!("No authenticator configured"))?;

        authenticator.challenge(request)
    }

    /// Creates a 486 Busy Here response.
    pub fn create_busy(&self, request: &Request) -> Response {
        let mut response = Self::create_response(request, 486, "Busy Here");
        self.ensure_to_tag(&mut response);
        response
    }

    /// Creates a 603 Decline response.
    pub fn create_decline(&self, request: &Request) -> Response {
        let mut response = Self::create_response(request, 603, "Decline");
        self.ensure_to_tag(&mut response);
        response
    }

    /// Creates a 487 Request Terminated response (for CANCEL).
    pub fn create_request_terminated(request: &Request) -> Response {
        let mut response = Self::create_response(request, 487, "Request Terminated");
        ensure_to_tag_header(&mut response);
        response
    }

    /// Creates a 487 Request Terminated response based on a CANCEL request.
    ///
    /// Ensures the CSeq method is INVITE per RFC 3261.
    pub fn create_request_terminated_from_cancel(request: &Request) -> Response {
        let mut response = Self::create_request_terminated(request);
        if let Some(cseq) = request.headers().get("CSeq") {
            let cseq_number = cseq.split_whitespace().next().unwrap_or("0");
            let cseq_value = format!("{} INVITE", cseq_number);
            response
                .headers_mut()
                .set_or_push("CSeq", &cseq_value)
                .expect("cseq should be valid");
        }
        response
    }

    /// Creates a 422 Session Interval Too Small response (RFC 4028).
    ///
    /// # Arguments
    /// * `request` - The INVITE request with too-small Session-Expires
    /// * `min_se` - Minimum acceptable session expiration in seconds
    ///
    /// # Returns
    /// A 422 response with Min-SE header
    ///
    /// # RFC 4028
    /// When a UAS receives a Session-Expires value smaller than its minimum,
    /// it must reject with 422 and include its Min-SE requirement.
    pub fn create_session_interval_too_small(request: &Request, min_se: u32) -> Response {
        let mut response = Self::create_response(request, 422, "Session Interval Too Small");

        // Add Min-SE header per RFC 4028
        response
            .headers_mut()
            .push(SmolStr::new("Min-SE"), SmolStr::new(min_se.to_string()))
            .unwrap();

        ensure_to_tag_header(&mut response);
        response
    }

    /// Validates Session-Expires header in an INVITE request.
    ///
    /// # Arguments
    /// * `request` - The INVITE request to validate
    /// * `min_se` - Optional minimum session expiration (defaults to 90s per RFC 4028)
    ///
    /// # Returns
    /// - `Ok(())`: Session-Expires is valid or not present
    /// - `Err(Response)`: 422 response if Session-Expires is too small
    ///
    /// # RFC 4028 Section 8
    /// If the Session-Expires interval is too brief, the UAS rejects the request
    /// with a 422 (Session Interval Too Small) response.
    pub fn validate_session_timer(
        request: &Request,
        min_se: Option<Duration>,
    ) -> Result<(), Response> {
        // Extract Session-Expires header
        if let Some(se_header) = header(request.headers(), "Session-Expires") {
            if let Some(session_expires) = parse_session_expires(se_header) {
                let duration = Duration::from_secs(session_expires.delta_seconds() as u64);

                // Validate against Min-SE
                if let Err(required_min) = validate_session_expires(duration, min_se) {
                    // Too small - return 422 response
                    return Err(Self::create_session_interval_too_small(
                        request,
                        required_min.as_secs() as u32,
                    ));
                }
            }
        }

        // No Session-Expires header or validation passed
        Ok(())
    }

    /// Accepts an INVITE request and creates a dialog.
    ///
    /// # Arguments
    /// * `request` - The INVITE request
    /// * `sdp_body` - Optional SDP answer body
    ///
    /// # Returns
    /// A tuple of (200 OK response, created dialog)
    pub fn accept_invite(
        &self,
        request: &Request,
        sdp_body: Option<&str>,
    ) -> Result<(Response, Dialog)> {
        if request.method().as_str() != "INVITE" {
            return Err(anyhow!("Not an INVITE request"));
        }

        if let Err(_response) = Self::validate_invite_headers(request) {
            return Err(anyhow!("Bad INVITE request"));
        }

        // Verify authentication if configured
        if let Some(auth) = &self.authenticator {
            if !auth.verify(request, request.headers())? {
                return Err(anyhow!(
                    "Authentication required - use create_unauthorized first"
                ));
            }
        }

        // Create 200 OK response
        let response = self.create_ok(request, sdp_body);

        // Extract remote URI from From header
        let remote_uri = extract_from_uri(request)?;

        // Unwrap response Result
        let response = response?;

        // Create dialog
        let dialog = Dialog::new_uas(request, &response, self.local_uri.clone(), remote_uri)
            .ok_or_else(|| anyhow!("Failed to create dialog"))?;

        info!(
            call_id = %dialog.id().call_id(),
            state = ?dialog.state(),
            "UAS created dialog"
        );

        // Store in dialog manager
        let _ = self.dialog_manager.insert(dialog.clone());

        Ok((response, dialog))
    }

    /// Rejects an INVITE request with the given status code.
    ///
    /// # Arguments
    /// * `request` - The INVITE request to reject
    /// * `code` - Status code (e.g., 486 for Busy, 603 for Decline)
    /// * `reason` - Reason phrase
    ///
    /// # Returns
    /// A response with the specified status
    pub fn reject_invite(request: &Request, code: u16, reason: &str) -> Response {
        let mut response = Self::create_response(request, code, reason);
        ensure_to_tag_header(&mut response);
        response
    }

    /// Handles a BYE request to terminate a dialog.
    ///
    /// # Arguments
    /// * `request` - The BYE request
    /// * `dialog` - The dialog to terminate
    ///
    /// # Returns
    /// A 200 OK response
    pub fn handle_bye(&self, request: &Request, dialog: &Dialog) -> Result<Response> {
        if request.method().as_str() != "BYE" {
            return Err(anyhow!("Not a BYE request"));
        }

        validate_dialog_request(request, dialog)?;

        // Remove dialog from manager
        self.dialog_manager.remove(dialog.id());

        info!(
            call_id = %dialog.id().call_id(),
            "UAS terminated dialog"
        );

        // Create 200 OK response
        self.create_ok(request, None)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Handles an INFO request within a dialog (RFC 2976).
    ///
    /// # Arguments
    /// * `request` - The INFO request
    /// * `dialog` - The dialog the INFO was received in
    ///
    /// # Returns
    /// A 200 OK response
    ///
    /// # RFC 2976 INFO Method
    /// INFO carries session-related control information during an established dialog.
    /// The application should examine the Content-Type and body to process the information.
    ///
    /// # Common Content Types
    /// - `application/dtmf-relay`: DTMF digit signaling
    /// - `application/json`: Custom JSON payloads
    /// - `text/plain`: Plain text information
    /// - Custom application types
    ///
    /// # Example
    /// ```ignore
    /// match uas.handle_info(&info_request, &dialog) {
    ///     Ok(response) => {
    ///         // Extract and process INFO payload
    ///         let content_type = header(info_request.headers(), "Content-Type");
    ///         let body = String::from_utf8_lossy(info_request.body());
    ///
    ///         if content_type == Some(&"application/dtmf-relay") {
    ///             // Process DTMF: body contains "Signal=1\r\nDuration=100\r\n"
    ///             process_dtmf(&body);
    ///         }
    ///
    ///         // Send 200 OK response
    ///         Ok(response)
    ///     }
    ///     Err(e) => Err(e)
    /// }
    /// ```
    pub fn handle_info(&self, request: &Request, dialog: &Dialog) -> Result<Response> {
        if request.method().as_str() != "INFO" {
            return Err(anyhow!("Not an INFO request"));
        }

        validate_dialog_request(request, dialog)?;

        info!(
            call_id = %dialog.id().call_id(),
            content_type = ?header(request.headers(), "Content-Type"),
            body_len = request.body().len(),
            "UAS received INFO request"
        );

        // Create 200 OK response
        self.create_ok(request, None)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Handles a CANCEL request.
    ///
    /// # Arguments
    /// * `request` - The CANCEL request
    ///
    /// # Returns
    /// A 200 OK response for the CANCEL
    pub fn handle_cancel(&self, request: &Request) -> Result<Response> {
        if request.method().as_str() != "CANCEL" {
            return Err(anyhow!("Not a CANCEL request"));
        }

        // CANCEL always gets 200 OK
        // The original INVITE transaction should get 487 Request Terminated
        Ok(Self::create_response(request, 200, "OK"))
    }

    /// Verifies authentication for a request.
    ///
    /// # Arguments
    /// * `request` - The request to verify
    ///
    /// # Returns
    /// `true` if authenticated (or no auth configured), `false` otherwise
    pub fn verify_authentication(&self, request: &Request) -> Result<bool> {
        if let Some(auth) = &self.authenticator {
            auth.verify(request, request.headers())
        } else {
            // No auth configured, allow by default
            Ok(true)
        }
    }

    /// Handles a SUBSCRIBE request to establish an event subscription (RFC 3265).
    ///
    /// # Arguments
    /// * `request` - The SUBSCRIBE request
    /// * `expires` - Subscription duration in seconds (optionally override request)
    ///
    /// # Returns
    /// A tuple of (200 OK response, created subscription)
    pub fn accept_subscribe(
        &self,
        request: &Request,
        expires: Option<u32>,
    ) -> Result<(Response, Subscription)> {
        if request.method().as_str() != "SUBSCRIBE" {
            return Err(anyhow!("Not a SUBSCRIBE request"));
        }

        // Verify authentication if configured
        if let Some(auth) = &self.authenticator {
            if !auth.verify(request, request.headers())? {
                return Err(anyhow!(
                    "Authentication required - use create_unauthorized first"
                ));
            }
        }

        // Create 200 OK response
        let mut response = Self::create_response(request, 200, "OK");

        // Add Contact header
        response
            .headers_mut()
            .push(
                SmolStr::new("Contact"),
                SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
            )
            .unwrap();

        // Add Expires header
        let expires_value = expires.unwrap_or_else(|| {
            request
                .headers()
                .get("Expires")
                .and_then(|e| e.parse().ok())
                .unwrap_or(3600)
        });
        response
            .headers_mut()
            .push(
                SmolStr::new("Expires"),
                SmolStr::new(expires_value.to_string()),
            )
            .unwrap();

        // Add tag to To header
        self.ensure_to_tag(&mut response);

        // Extract remote URI from From header
        let remote_uri = extract_from_uri(request)?;

        // Create subscription
        let subscription =
            Subscription::new_notifier(request, &response, self.local_uri.clone(), remote_uri)
                .ok_or_else(|| anyhow!("Failed to create subscription"))?;

        info!(
            call_id = %subscription.id().call_id(),
            event = %subscription.id().event(),
            "UAS created subscription"
        );

        // Store in subscription manager
        let _ = self.subscription_manager.insert(subscription.clone());

        Ok((response, subscription))
    }

    /// Creates a NOTIFY request with sipfrag body for REFER progress (RFC 3515).
    ///
    /// # Arguments
    /// * `subscription` - The subscription created by REFER
    /// * `status_code` - SIP status code of the transfer attempt (e.g., 100, 200, 603)
    /// * `reason_phrase` - SIP reason phrase (e.g., "Trying", "OK", "Decline")
    ///
    /// # Returns
    /// A NOTIFY request with message/sipfrag body
    pub fn create_notify_sipfrag(
        &self,
        subscription: &mut Subscription,
        status_code: u16,
        reason_phrase: &str,
    ) -> std::result::Result<Request, UasError> {
        // Validate reason phrase for CRLF injection and length
        validate_reason_phrase(reason_phrase)?;

        let mut headers = Headers::new();

        // Via
        let branch = generate_branch();
        let transport = self
            .contact_uri
            .params()
            .get("transport")
            .and_then(|v| v.as_ref())
            .map(|v| v.as_str().to_ascii_uppercase())
            .unwrap_or_else(|| "UDP".to_string());
        let host = self.contact_uri.host();
        let port = self
            .contact_uri
            .port()
            .map(|p| format!(":{}", p))
            .unwrap_or_default();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new(format!(
                    "SIP/2.0/{} {}{};branch={}",
                    transport, host, port, branch
                )),
            )
            .unwrap();

        // From (we are the notifier, so use local URI with To tag from subscription)
        let from = format!(
            "<{}>;tag={}",
            self.local_uri.as_str(),
            subscription.id().to_tag()
        );
        headers
            .push(SmolStr::new("From"), SmolStr::new(from))
            .unwrap();

        // To (subscriber, use From tag from subscription)
        let to = format!(
            "<{}>;tag={}",
            subscription.remote_uri().as_str(),
            subscription.id().from_tag()
        );
        headers.push(SmolStr::new("To"), SmolStr::new(to)).unwrap();

        // Call-ID
        headers
            .push(SmolStr::new("Call-ID"), subscription.id().call_id())
            .unwrap();

        // CSeq
        let cseq = subscription.next_local_cseq();
        headers
            .push(
                SmolStr::new("CSeq"),
                SmolStr::new(format!("{} NOTIFY", cseq)),
            )
            .unwrap();

        // Contact
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
            )
            .unwrap();

        // Event (should be "refer")
        headers
            .push(SmolStr::new("Event"), subscription.id().event())
            .unwrap();

        // Subscription-State (terminated after final response)
        let state = if (200..300).contains(&status_code) {
            "terminated;reason=noresource"
        } else if status_code >= 300 {
            "terminated;reason=rejected"
        } else {
            "active"
        };
        headers
            .push(SmolStr::new("Subscription-State"), SmolStr::new(state))
            .unwrap();

        // Content-Type: message/sipfrag;version=2.0
        headers
            .push(
                SmolStr::new("Content-Type"),
                SmolStr::new("message/sipfrag;version=2.0"),
            )
            .unwrap();

        // Sipfrag body (just the status line)
        let sipfrag_body = format!("SIP/2.0 {} {}\r\n", status_code, reason_phrase);
        headers
            .push(
                SmolStr::new("Content-Length"),
                SmolStr::new(sipfrag_body.len().to_string()),
            )
            .unwrap();

        // Max-Forwards
        headers
            .push(SmolStr::new("Max-Forwards"), SmolStr::new("70"))
            .unwrap();

        Ok(Request::new(
            RequestLine::new(Method::Notify, subscription.contact().clone()),
            headers,
            Bytes::from(sipfrag_body.as_bytes().to_vec()),
        )
        .expect("valid request"))
    }

    /// Handles a REFER request for call transfer (RFC 3515).
    ///
    /// # Arguments
    /// * `request` - The REFER request
    /// * `dialog` - The dialog the REFER was received in
    ///
    /// # Returns
    /// A tuple of (202 Accepted response, created subscription for implicit "refer" event)
    ///
    /// # Call Transfer
    /// REFER creates an implicit subscription to the "refer" event.
    /// The handler should:
    /// 1. Accept with 202 Accepted
    /// 2. Extract Refer-To URI
    /// 3. Attempt the transfer (send INVITE to Refer-To target)
    /// 4. Send NOTIFY messages with sipfrag bodies reporting progress
    pub fn accept_refer(&self, request: &Request, dialog: &Dialog) -> Result<(Response, String)> {
        if request.method().as_str() != "REFER" {
            return Err(anyhow!("Not a REFER request"));
        }

        validate_dialog_request(request, dialog)?;

        // Extract Refer-To header
        let refer_to = header(request.headers(), "Refer-To")
            .ok_or_else(|| anyhow!("Missing Refer-To header"))?
            .to_string();

        // Create 202 Accepted response
        let mut response = Self::create_response(request, 202, "Accepted");

        // Add Contact header
        response
            .headers_mut()
            .push(
                SmolStr::new("Contact"),
                SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
            )
            .unwrap();

        // Add tag to To header
        self.ensure_to_tag(&mut response);

        info!(
            call_id = %dialog.id().call_id(),
            refer_to = %refer_to,
            "UAS accepted REFER request"
        );

        Ok((response, refer_to))
    }

    /// Rejects a REFER request.
    ///
    /// # Arguments
    /// * `request` - The REFER request to reject
    /// * `code` - Status code (e.g., 603 for Decline)
    /// * `reason` - Reason phrase
    ///
    /// # Returns
    /// A response with the specified status
    pub fn reject_refer(request: &Request, code: u16, reason: &str) -> Response {
        Self::create_response(request, code, reason)
    }

    /// Creates a reliable provisional response with RSeq header (RFC 3262).
    ///
    /// # Arguments
    /// * `request` - The INVITE request to respond to
    /// * `dialog` - The early dialog
    /// * `code` - Status code (must be 1xx, typically 180 or 183)
    /// * `reason` - Reason phrase (e.g., "Ringing", "Session Progress")
    /// * `sdp_body` - Optional SDP body for early media
    ///
    /// # Returns
    /// A reliable provisional response with RSeq header
    ///
    /// # RFC 3262 Reliable Provisionals
    /// Reliable provisional responses require PRACK acknowledgement.
    /// The UAS must retransmit until PRACK is received.
    pub fn create_reliable_provisional(
        &self,
        request: &Request,
        dialog: &Dialog,
        code: u16,
        reason: &str,
        sdp_body: Option<&str>,
    ) -> std::result::Result<Response, UasError> {
        if !(100..200).contains(&code) {
            panic!("Reliable provisional must be 1xx response, got {}", code);
        }

        // Validate reason phrase
        validate_reason_phrase(reason)?;

        // Validate body if provided
        if let Some(body_content) = sdp_body {
            validate_body(body_content)?;
        }

        let mut response = Self::create_response(request, code, reason);

        // Add RSeq header
        let rseq = self.rseq_manager.next_rseq(dialog.id());
        response
            .headers_mut()
            .push(SmolStr::new("RSeq"), SmolStr::new(rseq.to_string()))
            .unwrap();

        // Add Require: 100rel
        response
            .headers_mut()
            .push(SmolStr::new("Require"), SmolStr::new("100rel"))
            .unwrap();

        // Add Contact header
        response
            .headers_mut()
            .push(
                SmolStr::new("Contact"),
                SmolStr::new(format!("<{}>", self.contact_uri.as_str())),
            )
            .unwrap();

        // Add tag to To header if not present
        self.ensure_to_tag(&mut response);

        if let Some(cseq) = header(request.headers(), "CSeq") {
            if let Some(cseq_num) = cseq.split_whitespace().next() {
                if let Ok(cseq_num) = cseq_num.parse::<u32>() {
                    self.prack_validator.register_reliable_provisional(
                        &dialog_id_key(dialog.id()),
                        rseq,
                        cseq_num,
                        request.method().clone(),
                        code,
                    );
                }
            }
        }

        // Add body if provided
        if let Some(body_content) = sdp_body {
            // Update Content-Length
            let content_length = body_content.len().to_string();
            response
                .headers_mut()
                .set_or_push("Content-Length", &content_length)
                .expect("content-length should be valid");

            // Add Content-Type for SDP
            response
                .headers_mut()
                .push(
                    SmolStr::new("Content-Type"),
                    SmolStr::new("application/sdp"),
                )
                .unwrap();

            let (start, headers, _) = response.into_parts();
            response = Response::new(
                start,
                headers,
                Bytes::from(body_content.as_bytes().to_vec()),
            )
            .expect("valid response");
        }

        Ok(response)
    }

    /// Handles a PRACK request (RFC 3262).
    ///
    /// # Arguments
    /// * `request` - The PRACK request
    /// * `dialog` - The dialog the PRACK was received in
    ///
    /// # Returns
    /// A 200 OK response
    pub fn handle_prack(&self, request: &Request, dialog: &Dialog) -> Result<Response> {
        if request.method().as_str() != "PRACK" {
            return Err(anyhow!("Not a PRACK request"));
        }

        validate_dialog_request(request, dialog)?;

        if let Err(err) = self
            .prack_validator
            .validate_prack(&dialog_id_key(dialog.id()), request)
        {
            let err_msg = err.to_string();
            // RFC 3262 §4: Return 400 for malformed/invalid RAck, 481 for no dialog/transaction
            let response = if err_msg.contains("missing RAck")
                || err_msg.contains("Invalid RAck")
                || err_msg.contains("does not match")
                || err_msg.contains("Duplicate PRACK")
            {
                Self::create_response(request, 400, "Bad Request")
            } else {
                // "No pending reliable provisionals" → 481
                Self::create_response(request, 481, "Call/Transaction Does Not Exist")
            };
            return Ok(response);
        }

        info!(
            call_id = %dialog.id().call_id(),
            "UAS received PRACK"
        );

        // Create 200 OK response
        self.create_ok(request, None)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Adds a tag to the To header if not already present.
    fn ensure_to_tag(&self, response: &mut Response) {
        ensure_to_tag_header(response);
    }

    /// Validates required headers for an INVITE request.
    ///
    /// Returns a 400 Bad Request response if required headers are missing.
    pub fn validate_invite_headers(request: &Request) -> Result<(), Response> {
        if request.method().as_str() != "INVITE" {
            return Ok(());
        }

        for required in ["Via", "From", "To", "Call-ID", "CSeq"] {
            if request.headers().get(required).is_none() {
                return Err(Self::create_bad_request(request, "Bad Request"));
            }
        }

        let from_header = header(request.headers(), "From")
            .ok_or_else(|| Self::create_bad_request(request, "Bad Request"))?;
        if extract_tag_param(from_header).is_none() {
            return Err(Self::create_bad_request(request, "Bad Request"));
        }

        Ok(())
    }

    /// Creates a 400 Bad Request response.
    pub fn create_bad_request(request: &Request, reason: &str) -> Response {
        let mut response = Self::create_response(request, 400, reason);
        ensure_to_tag_header(&mut response);
        response
    }
}

/// Helper to generate a random tag.
fn generate_tag() -> SmolStr {
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    if let Some(counter) = deterministic_counter() {
        return SmolStr::new(format!("t{:010x}", counter));
    }

    let tag: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    SmolStr::new(tag)
}

/// Helper to generate a branch parameter (RFC 3261 magic cookie).
fn generate_branch() -> String {
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    if let Some(counter) = deterministic_counter() {
        return format!("z9hG4bK{:016x}", counter);
    }

    let random: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    format!("z9hG4bK{}", random)
}

fn deterministic_counter() -> Option<u64> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    static SEED: OnceLock<Option<u64>> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seed = SEED.get_or_init(|| {
        std::env::var("SIPHON_ID_SEED")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
    });

    seed.map(|base| base.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed)))
}

/// Extracts tag parameter from From/To header value.
fn extract_tag_param(value: &SmolStr) -> Option<SmolStr> {
    value.split(';').find_map(|segment| {
        let trimmed = segment.trim();
        if trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case("tag=") {
            Some(SmolStr::new(&trimmed[4..]))
        } else {
            None
        }
    })
}

/// Builds a stable dialog key for PRACK tracking.
fn dialog_id_key(id: &sip_dialog::DialogId) -> String {
    format!("{}:{}:{}", id.call_id(), id.local_tag(), id.remote_tag())
}

/// Validates that a request matches the dialog's Call-ID and tags.
fn validate_dialog_request(request: &Request, dialog: &Dialog) -> Result<()> {
    let call_id = header(request.headers(), "Call-ID").ok_or_else(|| anyhow!("Missing Call-ID"))?;
    if call_id != dialog.id().call_id() {
        return Err(anyhow!("Call-ID mismatch"));
    }

    let from_header =
        header(request.headers(), "From").ok_or_else(|| anyhow!("Missing From header"))?;
    let to_header = header(request.headers(), "To").ok_or_else(|| anyhow!("Missing To header"))?;

    let from_tag = extract_tag_param(from_header).ok_or_else(|| anyhow!("Missing From tag"))?;
    let to_tag = extract_tag_param(to_header).ok_or_else(|| anyhow!("Missing To tag"))?;

    if from_tag != dialog.id().remote_tag() {
        return Err(anyhow!("From tag mismatch"));
    }
    if to_tag != dialog.id().local_tag() {
        return Err(anyhow!("To tag mismatch"));
    }

    Ok(())
}

/// Adds a tag to the To header if not already present.
fn ensure_to_tag_header(response: &mut Response) {
    let mut to_value = None;
    let mut has_tag = false;

    // Find To header and check for tag
    for header in response.headers().iter() {
        if header.name() == "To" {
            to_value = Some(header.value_smol().clone());
            has_tag = header.value().contains(";tag=");
            break;
        }
    }

    // Add tag if missing
    if let Some(to) = to_value {
        if !has_tag {
            let tag = generate_tag();
            let new_to = format!("{};tag={}", to.as_str(), tag.as_str());

            // Replace To header
            response
                .headers_mut()
                .set_or_push("To", &new_to)
                .expect("to header should be valid");
        }
    }
}

/// Extract From URI from request.
fn extract_from_uri(request: &Request) -> Result<SipUri> {
    let from_header =
        header(request.headers(), "From").ok_or_else(|| anyhow!("Missing From header"))?;

    // Simple extraction - look for URI between < >
    let uri_str = if let Some(start) = from_header.find('<') {
        if let Some(end) = from_header[start + 1..].find('>') {
            &from_header[start + 1..start + 1 + end]
        } else {
            return Err(anyhow!("Malformed From header"));
        }
    } else {
        // No brackets, take until semicolon or end
        if let Some(semi) = from_header.find(';') {
            &from_header[..semi]
        } else {
            from_header
        }
    };

    SipUri::parse(uri_str.trim()).map_err(|_| anyhow!("Failed to parse From URI"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, Method, RequestLine, SipUri, StatusLine};

    struct EchoUas;

    impl TransactionUser for EchoUas {
        fn on_request(&self, request: &Request) -> Result<Response> {
            Ok(Response::new(
                StatusLine::new(200, "OK")?,
                request.headers().clone(),
                request.body().clone(),
            )?)
        }
    }

    #[test]
    fn echoes_request_headers() {
        let request = Request::new(
            RequestLine::new(Method::Options, SipUri::parse("sip:example.com").unwrap()),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid request");
        let uas = EchoUas;
        let response = uas.on_request(&request).expect("response");
        assert_eq!(response.code(), 200);
    }

    #[test]
    fn creates_trying_response() {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = UserAgentServer::create_trying(&request);

        assert_eq!(response.code(), 100);
        assert_eq!(response.reason(), "Trying");
        assert!(response.headers().get("Via").is_some());
        assert!(response.headers().get("From").is_some());
        assert!(response.headers().get("To").is_some());
        assert!(response.headers().get("Call-ID").is_some());
        assert!(response.headers().get("CSeq").is_some());
    }

    #[test]
    fn creates_ringing_response() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = uas.create_ringing(&request);

        assert_eq!(response.code(), 180);
        assert_eq!(response.reason(), "Ringing");

        // Verify To tag was added
        let to_header = response.headers().get("To").unwrap();
        assert!(to_header.contains(";tag="));
    }

    #[test]
    fn creates_ok_response_with_contact() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = uas.create_ok(&request, None).expect("valid 200 OK");

        assert_eq!(response.code(), 200);
        assert_eq!(response.reason(), "OK");
        assert!(response.headers().get("Contact").is_some());

        // Verify To tag was added
        let to_header = response.headers().get("To").unwrap();
        assert!(to_header.contains(";tag="));
    }

    #[test]
    fn creates_ok_with_sdp_body() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.100\r\n";
        let response = uas.create_ok(&request, Some(sdp)).expect("valid 200 OK");

        assert_eq!(response.body().len(), sdp.len());
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/sdp"
        );
    }

    #[test]
    fn creates_busy_response() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = uas.create_busy(&request);

        assert_eq!(response.code(), 486);
        assert_eq!(response.reason(), "Busy Here");

        // Verify To tag was added
        let to_header = response.headers().get("To").unwrap();
        assert!(to_header.contains(";tag="));
    }

    #[test]
    fn creates_decline_response() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = uas.create_decline(&request);

        assert_eq!(response.code(), 603);
        assert_eq!(response.reason(), "Decline");

        // Verify To tag was added
        let to_header = response.headers().get("To").unwrap();
        assert!(to_header.contains(";tag="));
    }

    #[test]
    fn accepts_invite_creates_dialog() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:alice@192.168.1.200:5060>"),
            )
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let result = uas.accept_invite(&request, None);
        assert!(result.is_ok());

        let (response, dialog) = result.unwrap();
        assert_eq!(response.code(), 200);
        assert_eq!(dialog.id().call_id(), "test-call-id");
    }

    #[test]
    fn rejects_invite_with_custom_code() {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = UserAgentServer::reject_invite(&request, 486, "Busy Here");

        assert_eq!(response.code(), 486);
        assert_eq!(response.reason(), "Busy Here");
    }

    #[test]
    fn handles_cancel_request() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 CANCEL"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Cancel,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let result = uas.handle_cancel(&request);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.code(), 200);
    }

    #[test]
    fn extracts_from_uri_with_brackets() {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let uri = extract_from_uri(&request).unwrap();
        assert_eq!(uri.as_str(), "sip:alice@example.com");
    }

    #[test]
    fn extracts_from_uri_without_brackets() {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("sip:alice@example.com;tag=abc"),
            )
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let uri = extract_from_uri(&request).unwrap();
        assert_eq!(uri.as_str(), "sip:alice@example.com");
    }

    #[test]
    fn generates_valid_tag() {
        let tag = generate_tag();
        assert!(!tag.is_empty());
        assert!(tag.len() == 10);
    }

    #[test]
    fn accepts_subscribe_request() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 SUBSCRIBE"))
            .unwrap();
        headers
            .push(SmolStr::new("Event"), SmolStr::new("refer"))
            .unwrap();
        headers
            .push(SmolStr::new("Expires"), SmolStr::new("3600"))
            .unwrap();
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:alice@192.168.1.200:5060>"),
            )
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Subscribe,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let result = uas.accept_subscribe(&request, None);
        assert!(result.is_ok());

        let (response, subscription) = result.unwrap();

        // Verify response
        assert_eq!(response.code(), 200);
        assert_eq!(response.reason(), "OK");
        assert!(response.headers().get("Contact").is_some());
        assert!(response.headers().get("Expires").is_some());

        // Verify To tag was added
        let to_header = response.headers().get("To").unwrap();
        assert!(to_header.contains(";tag="));

        // Verify subscription
        assert_eq!(subscription.id().call_id(), "test-call-id");
        assert_eq!(subscription.id().event(), "refer");
    }

    #[test]
    fn accepts_refer_request() {
        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri, contact_uri);

        // First create a dialog
        let mut invite_headers = Headers::new();
        invite_headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        invite_headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        invite_headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        invite_headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        invite_headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();
        invite_headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:alice@192.168.1.200:5060>"),
            )
            .unwrap();

        let invite_request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            invite_headers,
            Bytes::new(),
        )
        .expect("valid request");

        let (_response, dialog) = uas.accept_invite(&invite_request, None).unwrap();

        // Now create REFER request
        let mut refer_headers = Headers::new();
        refer_headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK456"),
            )
            .unwrap();
        refer_headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        refer_headers
            .push(
                SmolStr::new("To"),
                SmolStr::new(format!(
                    "<sip:bob@example.com>;tag={}",
                    dialog.id().local_tag()
                )),
            )
            .unwrap();
        refer_headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        refer_headers
            .push(SmolStr::new("CSeq"), SmolStr::new("2 REFER"))
            .unwrap();
        refer_headers
            .push(
                SmolStr::new("Refer-To"),
                SmolStr::new("<sip:charlie@example.com>"),
            )
            .unwrap();

        let refer_request = Request::new(
            RequestLine::new(Method::Refer, SipUri::parse("sip:bob@example.com").unwrap()),
            refer_headers,
            Bytes::new(),
        )
        .expect("valid request");

        let result = uas.accept_refer(&refer_request, &dialog);
        assert!(result.is_ok());

        let (response, refer_to) = result.unwrap();

        // Verify response
        assert_eq!(response.code(), 202);
        assert_eq!(response.reason(), "Accepted");
        assert!(response.headers().get("Contact").is_some());

        // Verify Refer-To was extracted
        assert_eq!(refer_to, "<sip:charlie@example.com>");
    }

    #[test]
    fn creates_notify_sipfrag_request() {
        use sip_dialog::{Subscription, SubscriptionState};
        use std::time::Duration;

        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.100:5060").unwrap();

        let uas = UserAgentServer::new(local_uri.clone(), contact_uri);

        // Create a mock subscription
        let remote_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let subscription_id = sip_dialog::SubscriptionId::unchecked_new(
            "test-call-id",
            "abc123",
            "def456",
            "refer",
        );
        let mut subscription = Subscription::unchecked_new(
            subscription_id,
            SubscriptionState::Active,
            local_uri.clone(),
            remote_uri.clone(),
            remote_uri,
            Duration::from_secs(3600),
            1,  // local_cseq
            1,  // remote_cseq
        );

        // Test with 100 Trying (should be active)
        let notify_100 = uas
            .create_notify_sipfrag(&mut subscription, 100, "Trying")
            .expect("valid notify");

        assert_eq!(notify_100.method(), &Method::Notify);
        assert!(notify_100.headers().get("Event").is_some());
        assert_eq!(notify_100.headers().get("Event").unwrap(), "refer");
        assert!(notify_100.headers().get("Subscription-State").is_some());
        assert_eq!(
            notify_100.headers().get("Subscription-State").unwrap(),
            "active"
        );
        assert!(notify_100.headers().get("Content-Type").is_some());
        assert_eq!(
            notify_100.headers().get("Content-Type").unwrap(),
            "message/sipfrag;version=2.0"
        );

        let body = String::from_utf8(notify_100.body().to_vec()).unwrap();
        assert!(body.contains("SIP/2.0 100 Trying"));

        // Test with 200 OK (should be terminated with noresource)
        let notify_200 = uas
            .create_notify_sipfrag(&mut subscription, 200, "OK")
            .expect("valid notify");

        assert_eq!(
            notify_200.headers().get("Subscription-State").unwrap(),
            "terminated;reason=noresource"
        );

        let body = String::from_utf8(notify_200.body().to_vec()).unwrap();
        assert!(body.contains("SIP/2.0 200 OK"));

        // Test with 603 Decline (should be terminated with rejected)
        let notify_603 = uas
            .create_notify_sipfrag(&mut subscription, 603, "Decline")
            .expect("valid notify");

        assert_eq!(
            notify_603.headers().get("Subscription-State").unwrap(),
            "terminated;reason=rejected"
        );

        let body = String::from_utf8(notify_603.body().to_vec()).unwrap();
        assert!(body.contains("SIP/2.0 603 Decline"));
    }

    #[test]
    fn rejects_refer_request() {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("2 REFER"))
            .unwrap();
        headers
            .push(
                SmolStr::new("Refer-To"),
                SmolStr::new("<sip:charlie@example.com>"),
            )
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Refer, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = UserAgentServer::reject_refer(&request, 603, "Decline");

        assert_eq!(response.code(), 603);
        assert_eq!(response.reason(), "Decline");
    }

    #[test]
    fn creates_reliable_provisional_response() {
        use sip_core::RefresherRole;
        use sip_dialog::{Dialog, DialogId, DialogStateType};
        use std::time::Duration;

        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.200:5060").unwrap();

        let uas = UserAgentServer::new(local_uri.clone(), contact_uri);

        // Create INVITE request
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:alice@192.168.1.100:5060>"),
            )
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Mock dialog
        let remote_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let dialog_id = DialogId::unchecked_new("test-call-id", "bob-tag", "alice-tag");
        let dialog = Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Early,
            local_uri.clone(),
            remote_uri,
            SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
            0,  // local_cseq
            1,  // remote_cseq
            None,  // last_ack_cseq
            vec![],  // route_set
            false,  // secure
            Some(Duration::from_secs(1800)),  // session_expires
            Some(RefresherRole::Uas),  // refresher
            false,  // is_uac
        );

        // Create reliable provisional response (180 Ringing)
        let response = uas
            .create_reliable_provisional(&request, &dialog, 180, "Ringing", None)
            .expect("valid reliable provisional");

        // Verify response
        assert_eq!(response.code(), 180);
        assert_eq!(response.reason(), "Ringing");

        // Verify RSeq header (should be 1 for first reliable provisional)
        assert!(response.headers().get("RSeq").is_some());
        assert_eq!(response.headers().get("RSeq").unwrap(), "1");

        // Verify Require: 100rel
        assert_eq!(response.headers().get("Require").unwrap(), "100rel");

        // Verify To tag was added
        let to_header = response.headers().get("To").unwrap();
        assert!(to_header.contains(";tag="));

        // Verify Contact header
        assert!(response.headers().get("Contact").is_some());
    }

    #[test]
    fn handles_prack_request() {
        use sip_core::RefresherRole;
        use sip_dialog::{Dialog, DialogId, DialogStateType};
        use std::time::Duration;

        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.200:5060").unwrap();

        let uas = UserAgentServer::new(local_uri.clone(), contact_uri);

        let mut invite_headers = Headers::new();
        invite_headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        invite_headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
            )
            .unwrap();
        invite_headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        invite_headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        invite_headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();
        invite_headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:alice@192.168.1.100:5060>"),
            )
            .unwrap();

        let invite_request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            invite_headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Mock dialog
        let remote_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let dialog_id = DialogId::unchecked_new("test-call-id", "bob-tag", "alice-tag");
        let dialog = Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Early,
            local_uri.clone(),
            remote_uri,
            SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
            0,  // local_cseq
            1,  // remote_cseq
            None,  // last_ack_cseq
            vec![],  // route_set
            false,  // secure
            Some(Duration::from_secs(1800)),  // session_expires
            Some(RefresherRole::Uas),  // refresher
            false,  // is_uac
        );

        let _provisional = uas
            .create_reliable_provisional(&invite_request, &dialog, 180, "Ringing", None)
            .expect("valid reliable provisional");

        // Create PRACK request
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK456"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new("<sip:bob@example.com>;tag=bob-tag"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("2 PRACK"))
            .unwrap();
        headers
            .push(SmolStr::new("RAck"), SmolStr::new("1 1 INVITE"))
            .unwrap();

        let prack_request = Request::new(
            RequestLine::new(Method::Prack, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Handle PRACK
        let result = uas.handle_prack(&prack_request, &dialog);
        assert!(result.is_ok());

        let response = result.unwrap();

        // Verify 200 OK response
        assert_eq!(response.code(), 200);
        assert_eq!(response.reason(), "OK");
    }

    #[test]
    fn validates_session_expires_success() {
        // Valid Session-Expires (>= 90s)
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();
        headers
            .push(SmolStr::new("Session-Expires"), SmolStr::new("1800"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Should succeed - 1800s is valid
        assert!(UserAgentServer::validate_session_timer(&request, None).is_ok());
    }

    #[test]
    fn validates_session_expires_too_small() {
        // Invalid Session-Expires (< 90s) - parser rejects, treated as not present
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();
        headers
            .push(SmolStr::new("Session-Expires"), SmolStr::new("60"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Parser rejects Session-Expires below 90, so validation passes (no valid header)
        let result = UserAgentServer::validate_session_timer(&request, None);
        assert!(result.is_ok());
    }

    #[test]
    fn validates_session_expires_custom_min() {
        // Test with custom minimum (120s)
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();
        headers
            .push(SmolStr::new("Session-Expires"), SmolStr::new("100"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Should fail - 100s < 120s
        let result =
            UserAgentServer::validate_session_timer(&request, Some(Duration::from_secs(120)));
        assert!(result.is_err());

        let response = result.unwrap_err();
        assert_eq!(response.code(), 422);

        // Verify Min-SE header shows 120s
        assert_eq!(response.headers().get("Min-SE").unwrap(), "120");
    }

    #[test]
    fn validates_session_expires_no_header() {
        // No Session-Expires header should pass validation
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Should succeed - no Session-Expires means no validation needed
        assert!(UserAgentServer::validate_session_timer(&request, None).is_ok());
    }

    #[test]
    fn creates_422_response() {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK123"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=abc"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 INVITE"))
            .unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = UserAgentServer::create_session_interval_too_small(&request, 90);

        assert_eq!(response.code(), 422);
        assert_eq!(response.reason(), "Session Interval Too Small");
        assert_eq!(response.headers().get("Min-SE").unwrap(), "90");

        // Verify standard headers are copied
        assert!(response.headers().get("Via").is_some());
        assert!(response.headers().get("From").is_some());
        assert!(response.headers().get("To").is_some());
        assert!(response.headers().get("Call-ID").is_some());
        assert!(response.headers().get("CSeq").is_some());
    }

    #[test]
    fn handles_info_request() {
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.200:5060").unwrap();

        let uas = UserAgentServer::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let dialog_id = DialogId::unchecked_new("test-call-id", "bob-tag", "alice-tag");
        let dialog = Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Confirmed,
            local_uri.clone(),
            remote_uri,
            SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
            0,  // local_cseq
            1,  // remote_cseq
            None,  // last_ack_cseq
            vec![],  // route_set
            false,  // secure
            None,  // session_expires
            None,  // refresher
            false,  // is_uac
        );

        // Create INFO request with DTMF payload
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK456"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new("<sip:bob@example.com>;tag=bob-tag"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("2 INFO"))
            .unwrap();
        headers
            .push(
                SmolStr::new("Content-Type"),
                SmolStr::new("application/dtmf-relay"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("26"))
            .unwrap();

        let dtmf_body = "Signal=1\r\nDuration=100\r\n";
        let info_request = Request::new(
            RequestLine::new(Method::Info, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::from(dtmf_body),
        )
        .expect("valid request");

        // Handle INFO
        let result = uas.handle_info(&info_request, &dialog);
        assert!(result.is_ok());

        let response = result.unwrap();

        // Verify 200 OK response
        assert_eq!(response.code(), 200);
        assert_eq!(response.reason(), "OK");

        // Verify headers copied
        assert!(response.headers().get("Via").is_some());
        assert!(response.headers().get("From").is_some());
        assert!(response.headers().get("To").is_some());
        assert_eq!(response.headers().get("Call-ID").unwrap(), "test-call-id");
        assert_eq!(response.headers().get("CSeq").unwrap(), "2 INFO");
    }

    #[test]
    fn handles_info_with_json_payload() {
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.200:5060").unwrap();

        let uas = UserAgentServer::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let dialog_id = DialogId::unchecked_new("call-123", "bob-tag", "alice-tag");
        let dialog = Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Confirmed,
            local_uri.clone(),
            remote_uri,
            SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
            0,  // local_cseq
            5,  // remote_cseq
            None,  // last_ack_cseq
            vec![],  // route_set
            false,  // secure
            None,  // session_expires
            None,  // refresher
            false,  // is_uac
        );

        // Create INFO request with JSON payload
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK789"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new("<sip:bob@example.com>;tag=bob-tag"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("call-123"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("6 INFO"))
            .unwrap();
        headers
            .push(
                SmolStr::new("Content-Type"),
                SmolStr::new("application/json"),
            )
            .unwrap();

        let json_body = r#"{"action":"mute","value":true}"#;
        headers
            .push(
                SmolStr::new("Content-Length"),
                SmolStr::new(json_body.len().to_string()),
            )
            .unwrap();

        let info_request = Request::new(
            RequestLine::new(Method::Info, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::from(json_body),
        )
        .expect("valid request");

        // Handle INFO
        let result = uas.handle_info(&info_request, &dialog);
        assert!(result.is_ok());

        let response = result.unwrap();

        // Verify 200 OK response
        assert_eq!(response.code(), 200);
        assert_eq!(response.reason(), "OK");
    }

    #[test]
    fn rejects_info_with_wrong_call_id() {
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.200:5060").unwrap();

        let uas = UserAgentServer::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let dialog_id = DialogId::unchecked_new("correct-call-id", "bob-tag", "alice-tag");
        let dialog = Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Confirmed,
            local_uri.clone(),
            remote_uri,
            SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
            0,  // local_cseq
            1,  // remote_cseq
            None,  // last_ack_cseq
            vec![],  // route_set
            false,  // secure
            None,  // session_expires
            None,  // refresher
            false,  // is_uac
        );

        // Create INFO request with WRONG Call-ID
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK456"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new("<sip:bob@example.com>;tag=bob-tag"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("wrong-call-id"))
            .unwrap(); // Wrong!
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("2 INFO"))
            .unwrap();
        headers
            .push(SmolStr::new("Content-Type"), SmolStr::new("text/plain"))
            .unwrap();
        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();

        let info_request = Request::new(
            RequestLine::new(Method::Info, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Handle INFO - should fail
        let result = uas.handle_info(&info_request, &dialog);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Call-ID mismatch"));
    }

    #[test]
    fn rejects_non_info_request() {
        use sip_dialog::{Dialog, DialogId, DialogStateType};

        let local_uri = SipUri::parse("sip:bob@example.com").unwrap();
        let contact_uri = SipUri::parse("sip:bob@192.168.1.200:5060").unwrap();

        let uas = UserAgentServer::new(local_uri.clone(), contact_uri);

        // Mock dialog
        let remote_uri = SipUri::parse("sip:alice@example.com").unwrap();
        let dialog_id = DialogId::unchecked_new("test-call-id", "bob-tag", "alice-tag");
        let dialog = Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Confirmed,
            local_uri.clone(),
            remote_uri,
            SipUri::parse("sip:alice@192.168.1.100:5060").unwrap(),
            0,  // local_cseq
            1,  // remote_cseq
            None,  // last_ack_cseq
            vec![],  // route_set
            false,  // secure
            None,  // session_expires
            None,  // refresher
            false,  // is_uac
        );

        // Create BYE request (not INFO)
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK456"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new("<sip:alice@example.com>;tag=alice-tag"),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new("<sip:bob@example.com>;tag=bob-tag"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("test-call-id"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("2 BYE"))
            .unwrap();
        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();

        let bye_request = Request::new(
            RequestLine::new(Method::Bye, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Try to handle as INFO - should fail
        let result = uas.handle_info(&bye_request, &dialog);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not an INFO request"));
    }
}
