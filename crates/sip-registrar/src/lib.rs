// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 3261 §10 compliant REGISTER request handling and location service.
//!
//! Provides binding management with expiry tracking, wildcard deregistration,
//! q-value prioritization, and optional Digest authentication integration.
//!
//! # Example
//! ```no_run
//! use sip_registrar::{BasicRegistrar, MemoryLocationStore};
//! use sip_auth::{DigestAuthenticator, MemoryCredentialStore};
//! # use sip_core::{Request, Headers, RequestLine, Method, SipUri};
//! # use bytes::Bytes;
//! # async fn example() -> anyhow::Result<()> {
//! let store = MemoryLocationStore::new();
//! let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
//!     BasicRegistrar::new(store, None);
//! # let req = Request::new(RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()), Headers::new(), Bytes::new()).unwrap();
//! let response = registrar.handle_register_async(&req).await?;
//! # Ok(())
//! # }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sip_auth::Authenticator;
use sip_core::{Headers, Request, Response, SipUri, StatusLine, TelUri, Uri};
use sip_parse::{header, parse_to_header};
use sip_ratelimit::RateLimiter;
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{runtime::Handle, task};
use tracing::{info, warn};

/// Normalize an AOR for consistent storage and lookup.
///
/// Supports both SIP and tel URIs; rejects other schemes.
///
/// **SIP URIs:**
/// - Percent-decodes user/host (handled by `SipUri::parse`).
/// - Strips URI parameters by rebuilding without them.
/// - If the user contains an embedded `@domain` that matches the host, drop
///   the suffix (e.g., `bob%40192.168.1.81@192.168.1.81` → `bob`).
///
/// **tel URIs:**
/// - Uses the normalized number (visual separators removed).
/// - Includes phone-context for local numbers.
/// - Preserves other tel URI parameters (ext, isub, etc.) in canonical form.
/// - Parameters are sorted alphabetically for consistent normalization.
/// - phone-context domains are lowercased (ASCII domains only; use punycode for IDN).
///
/// # Examples
///
/// ```rust
/// use sip_registrar::normalize_aor;
/// use sip_core::Uri;
///
/// // SIP URI - parameters stripped
/// let uri = Uri::parse("sip:alice@example.com;transport=tcp").unwrap();
/// assert_eq!(normalize_aor(&uri).unwrap(), "sip:alice@example.com");
///
/// // Global tel URI - visual separators removed
/// let uri = Uri::parse("tel:+1-555-123-4567").unwrap();
/// assert_eq!(normalize_aor(&uri).unwrap(), "tel:+15551234567");
///
/// // Global tel URI with extension - parameters sorted
/// let uri = Uri::parse("tel:+1-555-123-4567;ext=123").unwrap();
/// assert_eq!(normalize_aor(&uri).unwrap(), "tel:+15551234567;ext=123");
///
/// // Different parameter order normalizes identically
/// let uri1 = Uri::parse("tel:+15551234567;ext=123;isub=xyz").unwrap();
/// let uri2 = Uri::parse("tel:+1.555.123.4567;isub=xyz;ext=123").unwrap();
/// assert_eq!(normalize_aor(&uri1).unwrap(), normalize_aor(&uri2).unwrap());
///
/// // Local tel URI - phone-context preserved and normalized
/// let uri = Uri::parse("tel:5551234;phone-context=EXAMPLE.COM").unwrap();
/// assert_eq!(normalize_aor(&uri).unwrap(), "tel:5551234;phone-context=example.com");
///
/// // Unsupported scheme - returns error
/// let uri = Uri::Absolute("mailto:alice@example.com".into());
/// assert!(normalize_aor(&uri).is_err());
/// ```
///
/// # Errors
///
/// Returns `NormalizeError::UnsupportedScheme` for non-SIP/non-tel URIs (e.g., mailto:, http:).
pub fn normalize_aor(uri: &Uri) -> Result<String, NormalizeError> {
    match uri {
        Uri::Sip(sip_uri) => Ok(normalize_sip_aor(sip_uri)),
        Uri::Tel(tel_uri) => Ok(normalize_tel_aor(tel_uri)),
        Uri::Absolute(_) => Err(NormalizeError::UnsupportedScheme),
    }
}

fn normalize_sip_aor(uri: &SipUri) -> String {
    let scheme = if uri.is_sips() { "sips" } else { "sip" };

    let host = uri.host().to_ascii_lowercase();
    let host_port = match uri.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.clone(),
    };

    let user = uri.user().map(|u| {
        if let Some((local, domain)) = u.rsplit_once('@') {
            if domain.eq_ignore_ascii_case(uri.host()) {
                return local.to_string();
            }
        }
        u.to_string()
    });

    match user {
        Some(user) if !user.is_empty() => format!("{}:{}@{}", scheme, user, host_port),
        _ => format!("{}:{}", scheme, host_port),
    }
}

/// Normalize a tel URI to canonical form per RFC 3966.
///
/// - Removes visual separators from the number
/// - Normalizes phone-context:
///   - If it starts with '+' (global number context), removes visual separators
///   - Otherwise (domain-based context), converts to lowercase (ASCII only)
/// - Preserves all parameters (ext, isub, etc.) in sorted order
/// - Returns canonical string representation
fn normalize_tel_aor(uri: &TelUri) -> String {
    // For tel URIs, remove visual separators and include phone-context for local numbers per RFC 3966.
    // Include all other tel URI parameters to avoid collisions (ext, isub, etc.).
    let number = normalize_tel_number(uri.number());
    let mut params = Vec::new();

    // Normalize phone-context value based on its format
    // RFC 3966 allows phone-context to be either a global number or a domain name
    let phone_context = uri.phone_context().map(|context| {
        if context.starts_with('+') {
            // Global number context: remove visual separators
            // Example: tel:123;phone-context=+1-555 -> tel:123;phone-context=+1555
            normalize_tel_number(context).to_string()
        } else {
            // Domain-based context: lowercase for case-insensitive comparison
            // Example: tel:123;phone-context=EXAMPLE.COM -> tel:123;phone-context=example.com
            // Note: This only handles ASCII domains. Use punycode for internationalized domains.
            context.to_ascii_lowercase()
        }
    });

    // Collect all parameters except phone-context (handled separately)
    // Normalize parameter keys to lowercase for canonical form
    for (key, value) in uri.parameters() {
        if key.as_str().eq_ignore_ascii_case("phone-context") {
            continue; // Skip phone-context, handled separately above
        }
        let key = key.as_str().to_ascii_lowercase();
        let value = value.as_ref().map(|v| v.as_str().to_owned());
        params.push((key, value));
    }

    // Sort parameters alphabetically for canonical ordering
    // This ensures tel:+1...;ext=123;isub=xyz and tel:+1...;isub=xyz;ext=123 normalize identically
    params.sort_by(|a, b| a.0.cmp(&b.0));

    if uri.is_global() {
        // Global number: tel:+15551234567
        let mut out = format!("tel:{}", number);
        for (key, value) in params {
            match value {
                Some(value) => {
                    out.push(';');
                    out.push_str(&key);
                    out.push('=');
                    out.push_str(&value);
                }
                None => {
                    out.push(';');
                    out.push_str(&key);
                }
            }
        }
        out
    } else {
        // Local number: tel:5551234;phone-context=example.com
        let mut out = format!("tel:{}", number);
        if let Some(context) = phone_context {
            out.push_str(";phone-context=");
            out.push_str(&context);
        }
        for (key, value) in params {
            match value {
                Some(value) => {
                    out.push(';');
                    out.push_str(&key);
                    out.push('=');
                    out.push_str(&value);
                }
                None => {
                    out.push(';');
                    out.push_str(&key);
                }
            }
        }
        out
    }
}

/// Remove visual separators from a telephone number per RFC 3966 §5.1.1.
///
/// Visual separators (-, ., space, parentheses) are removed to create the canonical form.
/// These separators are for human readability only and not significant for comparison.
///
/// # Examples
///
/// - `+1-555-123-4567` → `+15551234567`
/// - `+1.555.123.4567` → `+15551234567`
/// - `+1 (555) 123-4567` → `+15551234567`
fn normalize_tel_number(number: &str) -> SmolStr {
    let normalized: String = number
        .chars()
        .filter(|c| !matches!(c, '-' | '.' | ' ' | '(' | ')'))
        .collect();
    SmolStr::new(normalized)
}

/// Registration binding for an address-of-record (AOR).
///
/// Contains contact information and metadata for a registered endpoint.
#[derive(Debug, Clone)]
pub struct Binding {
    /// Address of Record (To URI)
    pub aor: SmolStr,

    /// Contact URI
    pub contact: SmolStr,

    /// Expiration duration from binding time
    pub expires: Duration,

    /// Call-ID of the REGISTER request that created/updated this binding
    pub call_id: SmolStr,

    /// CSeq of the REGISTER request
    pub cseq: u32,

    /// Quality value (q parameter, 0.0 to 1.0)
    pub q_value: f32,
}

impl Binding {
    pub fn new(aor: SmolStr, contact: SmolStr, expires: Duration) -> Self {
        Self {
            aor,
            contact,
            expires,
            call_id: SmolStr::new(""),
            cseq: 0,
            q_value: 1.0,
        }
    }

    pub fn with_call_id(mut self, call_id: SmolStr) -> Self {
        self.call_id = call_id;
        self
    }

    pub fn with_cseq(mut self, cseq: u32) -> Self {
        self.cseq = cseq;
        self
    }

    pub fn with_q_value(mut self, q_value: f32) -> Self {
        self.q_value = q_value.clamp(0.0, 1.0);
        self
    }
}

/// Abstract storage for registration bindings.
pub trait LocationStore: Send + Sync {
    /// Insert or update a binding
    fn upsert(&self, binding: Binding) -> Result<()>;

    /// Remove a specific binding
    fn remove(&self, aor: &str, contact: &str) -> Result<()>;

    /// Remove all bindings for an AOR
    fn remove_all(&self, aor: &str) -> Result<()>;

    /// Lookup all bindings for an AOR
    fn lookup(&self, aor: &str) -> Result<Vec<Binding>>;

    /// Cleanup expired bindings
    fn cleanup_expired(&self) -> Result<usize>;
}

/// Async storage for registration bindings.
#[async_trait]
pub trait AsyncLocationStore: Send + Sync {
    async fn upsert(&self, binding: Binding) -> Result<()>;
    async fn remove(&self, aor: &str, contact: &str) -> Result<()>;
    async fn remove_all(&self, aor: &str) -> Result<()>;
    async fn lookup(&self, aor: &str) -> Result<Vec<Binding>>;
    async fn cleanup_expired(&self) -> Result<usize>;
}

/// Adapter allowing an async store to satisfy the synchronous trait.
pub struct AsyncToSyncAdapter<T: AsyncLocationStore> {
    inner: T,
}

impl<T: AsyncLocationStore> AsyncToSyncAdapter<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        // Assume we are on a runtime; block_in_place to avoid starving.
        task::block_in_place(|| Handle::current().block_on(fut))
    }
}

impl<T: AsyncLocationStore> LocationStore for AsyncToSyncAdapter<T> {
    fn upsert(&self, binding: Binding) -> Result<()> {
        self.block_on(self.inner.upsert(binding))
    }

    fn remove(&self, aor: &str, contact: &str) -> Result<()> {
        self.block_on(self.inner.remove(aor, contact))
    }

    fn remove_all(&self, aor: &str) -> Result<()> {
        self.block_on(self.inner.remove_all(aor))
    }

    fn lookup(&self, aor: &str) -> Result<Vec<Binding>> {
        self.block_on(self.inner.lookup(aor))
    }

    fn cleanup_expired(&self) -> Result<usize> {
        self.block_on(self.inner.cleanup_expired())
    }
}

/// Adapter allowing synchronous stores to be used asynchronously.
pub struct SyncToAsyncAdapter<T: LocationStore> {
    inner: Arc<T>,
}

impl<T: LocationStore> SyncToAsyncAdapter<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

#[async_trait]
impl<T: LocationStore + 'static> AsyncLocationStore for SyncToAsyncAdapter<T> {
    async fn upsert(&self, binding: Binding) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        task::spawn_blocking(move || inner.upsert(binding))
            .await
            .map_err(|e| anyhow::anyhow!("task join error: {}", e))?
    }

    async fn remove(&self, aor: &str, contact: &str) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let aor = aor.to_owned();
        let contact = contact.to_owned();
        task::spawn_blocking(move || inner.remove(&aor, &contact))
            .await
            .map_err(|e| anyhow::anyhow!("task join error: {}", e))?
    }

    async fn remove_all(&self, aor: &str) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let aor = aor.to_owned();
        task::spawn_blocking(move || inner.remove_all(&aor))
            .await
            .map_err(|e| anyhow::anyhow!("task join error: {}", e))?
    }

    async fn lookup(&self, aor: &str) -> Result<Vec<Binding>> {
        let inner = Arc::clone(&self.inner);
        let aor = aor.to_owned();
        task::spawn_blocking(move || inner.lookup(&aor))
            .await
            .map_err(|e| anyhow::anyhow!("task join error: {}", e))?
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let inner = Arc::clone(&self.inner);
        task::spawn_blocking(move || inner.cleanup_expired())
            .await
            .map_err(|e| anyhow::anyhow!("task join error: {}", e))?
    }
}

/// Simple in-memory location store with expiry tracking.
#[derive(Default, Clone)]
pub struct MemoryLocationStore {
    inner: Arc<DashMap<SmolStr, Vec<StoredBinding>>>,
}

#[derive(Debug, Clone)]
struct StoredBinding {
    contact: SmolStr,
    expires_at: Instant,
    call_id: SmolStr,
    cseq: u32,
    q_value: f32,
}

impl MemoryLocationStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    fn purge_expired(&self, aor: &SmolStr) {
        if let Some(mut entry) = self.inner.get_mut(aor) {
            entry.retain(|b| b.expires_at > Instant::now());
        }
    }

    /// Convenience inherent helpers to avoid trait method ambiguity.
    pub fn upsert(&self, binding: Binding) -> Result<()> {
        LocationStore::upsert(self, binding)
    }

    pub fn remove(&self, aor: &str, contact: &str) -> Result<()> {
        LocationStore::remove(self, aor, contact)
    }

    pub fn remove_all(&self, aor: &str) -> Result<()> {
        LocationStore::remove_all(self, aor)
    }

    pub fn lookup(&self, aor: &str) -> Result<Vec<Binding>> {
        LocationStore::lookup(self, aor)
    }

    pub fn cleanup_expired(&self) -> Result<usize> {
        LocationStore::cleanup_expired(self)
    }
}

impl LocationStore for MemoryLocationStore {
    fn upsert(&self, binding: Binding) -> Result<()> {
        let expires_at = Instant::now() + binding.expires;
        let aor_key = binding.aor.clone();

        let mut list = self.inner.entry(aor_key).or_default();

        // Remove existing binding with same contact
        list.retain(|b| b.contact != binding.contact);

        // Add new binding
        list.push(StoredBinding {
            contact: binding.contact,
            expires_at,
            call_id: binding.call_id,
            cseq: binding.cseq,
            q_value: binding.q_value,
        });

        Ok(())
    }

    fn remove(&self, aor: &str, contact: &str) -> Result<()> {
        if let Some(mut entry) = self.inner.get_mut(&SmolStr::new(aor)) {
            entry.retain(|b| b.contact.as_str() != contact);
        }
        Ok(())
    }

    fn remove_all(&self, aor: &str) -> Result<()> {
        self.inner.remove(&SmolStr::new(aor));
        Ok(())
    }

    fn lookup(&self, aor: &str) -> Result<Vec<Binding>> {
        let aor_key = SmolStr::new(aor);
        self.purge_expired(&aor_key);

        if let Some(entry) = self.inner.get(&aor_key) {
            let now = Instant::now();
            Ok(entry
                .iter()
                .filter_map(|b| {
                    if b.expires_at > now {
                        Some(Binding {
                            aor: aor_key.clone(),
                            contact: b.contact.clone(),
                            expires: b.expires_at.saturating_duration_since(now),
                            call_id: b.call_id.clone(),
                            cseq: b.cseq,
                            q_value: b.q_value,
                        })
                    } else {
                        None
                    }
                })
                .collect())
        } else {
            Ok(Vec::new())
        }
    }

    fn cleanup_expired(&self) -> Result<usize> {
        let mut count = 0;
        let now = Instant::now();

        for mut entry in self.inner.iter_mut() {
            let before = entry.len();
            entry.retain(|b| b.expires_at > now);
            count += before - entry.len();
        }

        // Remove empty AORs
        self.inner.retain(|_, bindings| !bindings.is_empty());

        Ok(count)
    }
}

#[async_trait]
impl AsyncLocationStore for MemoryLocationStore {
    async fn upsert(&self, binding: Binding) -> Result<()> {
        LocationStore::upsert(self, binding)
    }

    async fn remove(&self, aor: &str, contact: &str) -> Result<()> {
        LocationStore::remove(self, aor, contact)
    }

    async fn remove_all(&self, aor: &str) -> Result<()> {
        LocationStore::remove_all(self, aor)
    }

    async fn lookup(&self, aor: &str) -> Result<Vec<Binding>> {
        LocationStore::lookup(self, aor)
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        LocationStore::cleanup_expired(self)
    }
}

/// Trait describing registrar behaviour for inbound REGISTER requests.
pub trait Registrar: Send + Sync {
    fn handle_register(&self, request: &Request) -> Result<Response>;
}

/// Basic registrar that stores contacts in a provided store and optionally enforces authentication.
pub struct BasicRegistrar<S, A> {
    store: S,
    authenticator: Option<A>,
    default_expires: Duration,
    min_expires: Duration,
    max_expires: Duration,
    rate_limiter: Option<RateLimiter>,
    #[allow(clippy::type_complexity)]
    rate_limit_key_fn: Option<Arc<dyn Fn(&Request) -> Option<SmolStr> + Send + Sync>>,
}

impl<S, A> BasicRegistrar<S, A> {
    pub fn new(store: S, authenticator: Option<A>) -> Self {
        Self {
            store,
            authenticator,
            default_expires: Duration::from_secs(3600),
            min_expires: Duration::from_secs(60),
            max_expires: Duration::from_secs(86400),
            rate_limiter: None,
            rate_limit_key_fn: None,
        }
    }

    pub fn with_default_expires(mut self, expires: Duration) -> Self {
        self.default_expires = expires;
        self
    }

    pub fn with_min_expires(mut self, expires: Duration) -> Self {
        self.min_expires = expires;
        self
    }

    pub fn with_max_expires(mut self, expires: Duration) -> Self {
        self.max_expires = expires;
        self
    }

    /// Configure rate limiting for REGISTER requests
    ///
    /// Rate limiting is applied based on a caller-provided key function to avoid
    /// trusting unverified headers for client identity.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_registrar::{BasicRegistrar, MemoryLocationStore};
    /// use sip_ratelimit::{RateLimiter, RateLimitConfig};
    /// use sip_auth::{DigestAuthenticator, MemoryCredentialStore};
    ///
    /// let store = MemoryLocationStore::new();
    /// let auth_store = MemoryCredentialStore::new();
    /// let auth = DigestAuthenticator::new("example.com", auth_store);
    /// let config = RateLimitConfig::register_preset(); // 60 per hour
    /// let key_fn = std::sync::Arc::new(|_req: &_| Some("192.0.2.10".into()));
    /// let registrar = BasicRegistrar::new(store, Some(auth))
    ///     .with_rate_limiter_key_fn(RateLimiter::new(config), key_fn);
    /// ```
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn with_rate_limiter_key_fn(
        mut self,
        limiter: RateLimiter,
        key_fn: Arc<dyn Fn(&Request) -> Option<SmolStr> + Send + Sync>,
    ) -> Self {
        self.rate_limiter = Some(limiter);
        self.rate_limit_key_fn = Some(key_fn);
        self
    }

    /// Get a reference to the location store
    pub fn location_store(&self) -> &S {
        &self.store
    }

    fn parse_expires(
        &self,
        request: &Request,
        contact_value: &str,
    ) -> Result<Duration, ExpiresError> {
        let contact_expires = match self.contact_param_value(contact_value, "expires") {
            Ok(Some(value)) => Some(value.parse::<u64>().map_err(|_| ExpiresError::Invalid)?),
            Ok(None) => None,
            Err(ContactParamError::Invalid) => return Err(ExpiresError::Invalid),
        };

        let header_expires = match request.headers().get("Expires") {
            Some(value) => Some(value.parse::<u64>().map_err(|_| ExpiresError::Invalid)?),
            None => None,
        };

        let seconds = contact_expires
            .or(header_expires)
            .unwrap_or(self.default_expires.as_secs());

        if seconds == 0 {
            return Ok(Duration::from_secs(0));
        }

        let min = self.min_expires.as_secs();
        let max = self.max_expires.as_secs();
        if seconds < min {
            return Err(ExpiresError::TooBrief(min));
        }
        if seconds > max {
            return Err(ExpiresError::TooLong(max));
        }

        Ok(Duration::from_secs(seconds))
    }

    fn parse_q_value(&self, contact_value: &str) -> Result<f32, ContactParamError> {
        let value = match self.contact_param_value(contact_value, "q")? {
            Some(value) => value
                .parse::<f32>()
                .map_err(|_| ContactParamError::Invalid)?,
            None => return Ok(1.0),
        };
        if (0.0..=1.0).contains(&value) {
            Ok(value)
        } else {
            Err(ContactParamError::Invalid)
        }
    }

    fn extract_contact_uri(&self, contact_header: &str) -> Result<SmolStr, ContactHeaderError> {
        let trimmed = contact_header.trim();

        // Handle <uri> format
        if let Some(start) = trimmed.find('<') {
            let end = trimmed[start + 1..]
                .find('>')
                .ok_or(ContactHeaderError::Invalid)?;
            let uri = trimmed[start + 1..start + 1 + end].trim();
            if uri.is_empty() {
                return Err(ContactHeaderError::Invalid);
            }
            return Ok(SmolStr::new(uri));
        }

        // Handle uri without brackets (stop at first semicolon)
        if let Some(pos) = trimmed.find(';') {
            let uri = trimmed[..pos].trim();
            if uri.is_empty() {
                return Err(ContactHeaderError::Invalid);
            }
            Ok(SmolStr::new(uri))
        } else if trimmed.is_empty() {
            Err(ContactHeaderError::Invalid)
        } else {
            Ok(SmolStr::new(trimmed))
        }
    }

    fn contact_param_value<'a>(
        &self,
        contact_value: &'a str,
        name: &str,
    ) -> Result<Option<&'a str>, ContactParamError> {
        let trimmed = contact_value.trim();
        if trimmed == "*" {
            return Ok(None);
        }

        let params_section = if let Some(start) = trimmed.find('<') {
            let end = trimmed[start + 1..]
                .find('>')
                .ok_or(ContactParamError::Invalid)?;
            let after = &trimmed[start + 1 + end + 1..];
            after.trim()
        } else if let Some(pos) = trimmed.find(';') {
            &trimmed[pos..]
        } else {
            return Ok(None);
        };

        let mut params = params_section.trim();
        params = params.strip_prefix(';').unwrap_or(params);
        if params.is_empty() {
            return Ok(None);
        }

        for param in params.split(';') {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            let (key, value) = match param.split_once('=') {
                Some((key, value)) => (key.trim(), value.trim()),
                None => {
                    if param.eq_ignore_ascii_case(name) {
                        return Err(ContactParamError::Invalid);
                    }
                    continue;
                }
            };
            if key.eq_ignore_ascii_case(name) {
                if value.is_empty() {
                    return Err(ContactParamError::Invalid);
                }
                return Ok(Some(value));
            }
        }

        Ok(None)
    }

    fn validate_required_headers(&self, request: &Request) -> Result<(), Response> {
        let required = [
            ("Via", "Bad Request - Missing Via header"),
            ("From", "Bad Request - Missing From header"),
            ("Call-ID", "Bad Request - Missing Call-ID header"),
            ("CSeq", "Bad Request - Missing CSeq header"),
        ];
        for (name, reason) in required {
            if request.headers().get(name).is_none() {
                return Err(self
                    .build_error_response(request, 400, reason)
                    .unwrap_or_else(|_| {
                        Response::new(
                            StatusLine::new(400, reason).expect("valid status line"),
                            Headers::new(),
                            Bytes::new(),
                        )
                        .expect("valid response")
                    }));
            }
        }
        Ok(())
    }

    fn parse_cseq_number(&self, request: &Request) -> Result<u32, Response> {
        let cseq = match header(request.headers(), "CSeq") {
            Some(value) => value,
            None => {
                return Err(self
                    .build_error_response(request, 400, "Bad Request - Missing CSeq header")
                    .unwrap_or_else(|_| {
                        Response::new(
                            StatusLine::new(400, "Bad Request - Missing CSeq")
                                .expect("valid status line"),
                            Headers::new(),
                            Bytes::new(),
                        )
                        .expect("valid response")
                    }))
            }
        };

        let mut parts = cseq.split_whitespace();
        let number = match parts.next().and_then(|n| n.parse::<u32>().ok()) {
            Some(number) => number,
            None => {
                return Err(self
                    .build_error_response(request, 400, "Bad Request - Invalid CSeq")
                    .unwrap_or_else(|_| {
                        Response::new(
                            StatusLine::new(400, "Bad Request - Invalid CSeq")
                                .expect("valid status line"),
                            Headers::new(),
                            Bytes::new(),
                        )
                        .expect("valid response")
                    }))
            }
        };
        let method = parts.next().unwrap_or("");
        if !method.eq_ignore_ascii_case("REGISTER") {
            return Err(self
                .build_error_response(request, 400, "Bad Request - Invalid CSeq")
                .unwrap_or_else(|_| {
                    Response::new(
                        StatusLine::new(400, "Bad Request - Invalid CSeq")
                            .expect("valid status line"),
                        Headers::new(),
                        Bytes::new(),
                    )
                    .expect("valid response")
                }));
        }
        Ok(number)
    }

    /// Builds an error response for malformed REGISTER requests.
    fn build_error_response(&self, request: &Request, code: u16, reason: &str) -> Result<Response> {
        let mut headers = Headers::new();

        // RFC 3261: Copy required headers from request to response
        if let Some(via) = request.headers().get("Via") {
            headers.push(SmolStr::new("Via"), via).unwrap();
        }
        if let Some(from) = request.headers().get("From") {
            headers.push(SmolStr::new("From"), from).unwrap();
        }
        // RFC 3261 §8.2.6.2: UAS MUST add tag to To header if not present
        if let Some(to) = request.headers().get("To") {
            headers.push(SmolStr::new("To"), ensure_to_tag(to)).unwrap();
        }
        if let Some(call_id) = request.headers().get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id).unwrap();
        }
        if let Some(cseq) = request.headers().get("CSeq") {
            headers.push(SmolStr::new("CSeq"), cseq).unwrap();
        }

        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();

        Ok(Response::new(
            StatusLine::new(code, reason)?,
            headers,
            Bytes::new(),
        )?)
    }

    fn build_interval_too_brief(&self, request: &Request, min_expires: u64) -> Result<Response> {
        let mut response = self.build_error_response(request, 423, "Interval Too Brief")?;
        response
            .headers_mut()
            .push(
                SmolStr::new("Min-Expires"),
                SmolStr::new(min_expires.to_string()),
            )
            .unwrap();
        Ok(response)
    }
}

#[derive(Debug)]
enum ExpiresError {
    TooBrief(u64),
    TooLong(u64),
    Invalid,
}

#[derive(Debug)]
enum ContactHeaderError {
    Invalid,
}

#[derive(Debug)]
enum ContactParamError {
    Invalid,
}

/// Error type for AOR normalization failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    /// The URI scheme is not supported for registration.
    ///
    /// Only SIP, SIPS, and tel URIs are supported as AORs.
    /// Other schemes (mailto:, http:, etc.) are rejected.
    UnsupportedScheme,
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NormalizeError::UnsupportedScheme => {
                write!(
                    f,
                    "URI scheme not supported for registration (only SIP/SIPS/tel URIs allowed)"
                )
            }
        }
    }
}

impl std::error::Error for NormalizeError {}

impl<S: AsyncLocationStore, A: Authenticator> BasicRegistrar<S, A> {
    /// Async variant of REGISTER handling for async storage backends.
    pub async fn handle_register_async(&self, request: &Request) -> Result<Response> {
        if let Err(response) = self.validate_required_headers(request) {
            return Ok(response);
        }

        // Rate limiting
        if let Some(ref limiter) = self.rate_limiter {
            if let Some(ref key_fn) = self.rate_limit_key_fn {
                if let Some(key) = key_fn(request) {
                    if !limiter.check_rate_limit(key.as_str()) {
                        warn!(key = %key, "REGISTER rate limit exceeded");
                        return Ok(self
                            .build_error_response(
                                request,
                                503,
                                "Service Unavailable - Rate Limit Exceeded",
                            )
                            .expect("valid request"));
                    }
                }
            } else {
                warn!("REGISTER rate limiting configured without a trusted key function");
            }
        }

        // Authentication (sync authenticator)
        if let Some(auth) = &self.authenticator {
            match auth.verify(request, request.headers()) {
                Ok(true) => {}
                Ok(false) => {
                    info!("REGISTER authentication failed, issuing challenge");
                    return auth.challenge(request);
                }
                Err(e) => {
                    warn!("REGISTER authentication error: {}, issuing challenge", e);
                    return auth.challenge(request);
                }
            }
        }

        let to_uri = match header(request.headers(), "To") {
            Some(h) => h,
            None => {
                warn!("REGISTER missing To header");
                return self.build_error_response(request, 400, "Bad Request - Missing To header");
            }
        };

        let to_parsed = match parse_to_header(to_uri) {
            Some(p) => p,
            None => {
                warn!("REGISTER invalid To header");
                return self.build_error_response(request, 400, "Bad Request - Invalid To header");
            }
        };
        let aor = match normalize_aor(to_parsed.inner().uri()) {
            Ok(aor) => aor,
            Err(NormalizeError::UnsupportedScheme) => {
                warn!("REGISTER To header has unsupported URI scheme");
                return self.build_error_response(
                    request,
                    400,
                    "Bad Request - Unsupported To URI scheme",
                );
            }
        };

        let call_id = header(request.headers(), "Call-ID")
            .cloned()
            .unwrap_or_else(|| SmolStr::new(""));

        let cseq = match self.parse_cseq_number(request) {
            Ok(cseq) => cseq,
            Err(response) => return Ok(response),
        };

        let contacts = contact_headers(request.headers());
        if contacts.is_empty() {
            warn!("REGISTER missing Contact header");
            return self.build_error_response(request, 400, "Bad Request - Missing Contact header");
        }

        if contacts.iter().any(|c| c.trim() == "*") && contacts.len() != 1 {
            return self.build_error_response(
                request,
                400,
                "Bad Request - Wildcard Contact must be the only Contact",
            );
        }

        if contacts.len() == 1 && contacts[0].trim() == "*" {
            let expires = match header(request.headers(), "Expires") {
                Some(value) => match value.parse::<u64>() {
                    Ok(value) => value,
                    Err(_) => {
                        return self.build_error_response(
                            request,
                            400,
                            "Bad Request - Invalid Expires",
                        );
                    }
                },
                None => 1,
            };
            if expires != 0 {
                return self.build_error_response(
                    request,
                    400,
                    "Bad Request - Wildcard Contact requires Expires: 0",
                );
            }
            self.store.remove_all(&aor).await?;
            info!(aor = %aor, "REGISTER removed all bindings (wildcard)");

            let mut headers = Headers::new();

            if let Some(via) = request.headers().get("Via") {
                headers.push(SmolStr::new("Via"), via).unwrap();
            }
            if let Some(from) = request.headers().get("From") {
                headers.push(SmolStr::new("From"), from).unwrap();
            }
            if let Some(to) = request.headers().get("To") {
                headers.push(SmolStr::new("To"), ensure_to_tag(to)).unwrap();
            }
            if let Some(call_id) = request.headers().get("Call-ID") {
                headers.push(SmolStr::new("Call-ID"), call_id).unwrap();
            }
            if let Some(cseq) = request.headers().get("CSeq") {
                headers.push(SmolStr::new("CSeq"), cseq).unwrap();
            }

            headers
                .push(SmolStr::new("Contact"), SmolStr::new("*"))
                .unwrap();
            headers
                .push(SmolStr::new("Date"), SmolStr::new(Utc::now().to_rfc2822()))
                .unwrap();
            headers
                .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
                .unwrap();

            return Ok(Response::new(
                StatusLine::new(200, "OK")?,
                headers,
                Bytes::new(),
            )?);
        }

        let existing = self.store.lookup(&aor).await?;
        let mut existing_by_contact = std::collections::HashMap::new();
        for binding in existing {
            existing_by_contact.insert(binding.contact.clone(), binding);
        }

        for contact in &contacts {
            let contact_uri = match self.extract_contact_uri(contact.as_str()) {
                Ok(uri) => uri,
                Err(ContactHeaderError::Invalid) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Invalid Contact header",
                    );
                }
            };
            match Uri::parse(contact_uri.as_str()) {
                Ok(Uri::Sip(_)) => {}
                _ => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Unsupported Contact URI scheme",
                    );
                }
            }
            let expires = match self.parse_expires(request, contact.as_str()) {
                Ok(expires) => expires,
                Err(ExpiresError::TooBrief(min)) => {
                    return self.build_interval_too_brief(request, min);
                }
                Err(ExpiresError::TooLong(_max)) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Expires too long",
                    );
                }
                Err(ExpiresError::Invalid) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Invalid Expires",
                    );
                }
            };
            let q_value = match self.parse_q_value(contact.as_str()) {
                Ok(value) => value,
                Err(ContactParamError::Invalid) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Invalid q value",
                    );
                }
            };

            if let Some(existing) = existing_by_contact.get(&contact_uri) {
                if existing.call_id == call_id && cseq <= existing.cseq {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - CSeq out of order",
                    );
                }
            }

            if expires.as_secs() == 0 {
                self.store.remove(&aor, contact_uri.as_str()).await?;
                info!(aor = %aor, contact = %contact_uri, "REGISTER removed binding");
            } else {
                let binding = Binding::new(SmolStr::new(aor.clone()), contact_uri.clone(), expires)
                    .with_call_id(call_id.clone())
                    .with_cseq(cseq)
                    .with_q_value(q_value);

                self.store.upsert(binding).await?;
                info!(aor = %aor, contact = %contact_uri, expires = %expires.as_secs(), "REGISTER stored binding");
            }
        }

        let mut headers = Headers::new();

        if let Some(via) = request.headers().get("Via") {
            headers.push(SmolStr::new("Via"), via).unwrap();
        }
        if let Some(from) = request.headers().get("From") {
            headers.push(SmolStr::new("From"), from).unwrap();
        }
        if let Some(to) = request.headers().get("To") {
            headers.push(SmolStr::new("To"), ensure_to_tag(to)).unwrap();
        }
        if let Some(call_id) = request.headers().get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id).unwrap();
        }
        if let Some(cseq) = request.headers().get("CSeq") {
            headers.push(SmolStr::new("CSeq"), cseq).unwrap();
        }

        let bindings = self.store.lookup(&aor).await?;
        for binding in &bindings {
            headers
                .push(
                    SmolStr::new("Contact"),
                    format_contact(&binding.contact, binding.expires, binding.q_value),
                )
                .unwrap();
        }

        headers
            .push(SmolStr::new("Date"), SmolStr::new(Utc::now().to_rfc2822()))
            .unwrap();
        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();

        Ok(Response::new(
            StatusLine::new(200, "OK")?,
            headers,
            Bytes::new(),
        )?)
    }
}

impl<S: LocationStore, A: Authenticator> Registrar for BasicRegistrar<S, A> {
    fn handle_register(&self, request: &Request) -> Result<Response> {
        if let Err(response) = self.validate_required_headers(request) {
            return Ok(response);
        }

        // Check rate limit first (before authentication and processing)
        if let Some(ref limiter) = self.rate_limiter {
            if let Some(ref key_fn) = self.rate_limit_key_fn {
                if let Some(key) = key_fn(request) {
                    if !limiter.check_rate_limit(key.as_str()) {
                        warn!(key = %key, "REGISTER rate limit exceeded");
                        return self.build_error_response(
                            request,
                            503,
                            "Service Unavailable - Rate Limit Exceeded",
                        );
                    }
                }
            } else {
                warn!("REGISTER rate limiting configured without a trusted key function");
            }
        }

        // Authenticate if authenticator is configured
        if let Some(auth) = &self.authenticator {
            match auth.verify(request, request.headers()) {
                Ok(true) => {
                    // Authentication succeeded, continue processing
                }
                Ok(false) => {
                    // Authentication failed - issue challenge
                    info!("REGISTER authentication failed, issuing challenge");
                    return auth.challenge(request);
                }
                Err(e) => {
                    // Authentication error (missing/invalid headers, unknown user, etc.)
                    // Treat as authentication failure and issue challenge instead of 500
                    warn!("REGISTER authentication error: {}, issuing challenge", e);
                    return auth.challenge(request);
                }
            }
        }

        // Extract AOR from To header
        let to_uri = match header(request.headers(), "To") {
            Some(h) => h,
            None => {
                warn!("REGISTER missing To header");
                return self.build_error_response(request, 400, "Bad Request - Missing To header");
            }
        };

        let to_parsed = match parse_to_header(to_uri) {
            Some(p) => p,
            None => {
                warn!("REGISTER invalid To header");
                return self.build_error_response(request, 400, "Bad Request - Invalid To header");
            }
        };
        let aor = match normalize_aor(to_parsed.inner().uri()) {
            Ok(aor) => aor,
            Err(NormalizeError::UnsupportedScheme) => {
                warn!("REGISTER To header has unsupported URI scheme");
                return self.build_error_response(
                    request,
                    400,
                    "Bad Request - Unsupported To URI scheme",
                );
            }
        };

        // Extract Call-ID and CSeq
        let call_id = header(request.headers(), "Call-ID")
            .cloned()
            .unwrap_or_else(|| SmolStr::new(""));

        let cseq = match self.parse_cseq_number(request) {
            Ok(cseq) => cseq,
            Err(response) => return Ok(response),
        };

        // Get all Contact headers
        let contacts = contact_headers(request.headers());
        if contacts.is_empty() {
            warn!("REGISTER missing Contact header");
            return self.build_error_response(request, 400, "Bad Request - Missing Contact header");
        }

        if contacts.iter().any(|c| c.trim() == "*") && contacts.len() != 1 {
            return self.build_error_response(
                request,
                400,
                "Bad Request - Wildcard Contact must be the only Contact",
            );
        }

        // Check for wildcard Contact (*)
        if contacts.len() == 1 && contacts[0].trim() == "*" {
            let expires = match header(request.headers(), "Expires") {
                Some(value) => match value.parse::<u64>() {
                    Ok(value) => value,
                    Err(_) => {
                        return self.build_error_response(
                            request,
                            400,
                            "Bad Request - Invalid Expires",
                        );
                    }
                },
                None => 1,
            };
            if expires != 0 {
                return self.build_error_response(
                    request,
                    400,
                    "Bad Request - Wildcard Contact requires Expires: 0",
                );
            }
            // Remove all bindings for this AOR
            self.store.remove_all(&aor)?;
            info!(aor = %aor, "REGISTER removed all bindings (wildcard)");

            let mut headers = Headers::new();

            // RFC 3261: Copy required headers from request to response
            if let Some(via) = request.headers().get("Via") {
                headers.push(SmolStr::new("Via"), via).unwrap();
            }
            if let Some(from) = request.headers().get("From") {
                headers.push(SmolStr::new("From"), from).unwrap();
            }
            // RFC 3261 §8.2.6.2: UAS MUST add tag to To header if not present
            if let Some(to) = request.headers().get("To") {
                headers.push(SmolStr::new("To"), ensure_to_tag(to)).unwrap();
            }
            if let Some(call_id) = request.headers().get("Call-ID") {
                headers.push(SmolStr::new("Call-ID"), call_id).unwrap();
            }
            if let Some(cseq) = request.headers().get("CSeq") {
                headers.push(SmolStr::new("CSeq"), cseq).unwrap();
            }

            headers
                .push(SmolStr::new("Contact"), SmolStr::new("*"))
                .unwrap();
            headers
                .push(SmolStr::new("Date"), SmolStr::new(Utc::now().to_rfc2822()))
                .unwrap();
            headers
                .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
                .unwrap();

            return Ok(Response::new(
                StatusLine::new(200, "OK")?,
                headers,
                Bytes::new(),
            )?);
        }

        // Process each contact
        let existing = self.store.lookup(&aor)?;
        let mut existing_by_contact = std::collections::HashMap::new();
        for binding in existing {
            existing_by_contact.insert(binding.contact.clone(), binding);
        }

        for contact in &contacts {
            let contact_uri = match self.extract_contact_uri(contact.as_str()) {
                Ok(uri) => uri,
                Err(ContactHeaderError::Invalid) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Invalid Contact header",
                    );
                }
            };
            match Uri::parse(contact_uri.as_str()) {
                Ok(Uri::Sip(_)) => {}
                _ => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Unsupported Contact URI scheme",
                    );
                }
            }
            let expires = match self.parse_expires(request, contact.as_str()) {
                Ok(expires) => expires,
                Err(ExpiresError::TooBrief(min)) => {
                    return self.build_interval_too_brief(request, min);
                }
                Err(ExpiresError::TooLong(_max)) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Expires too long",
                    );
                }
                Err(ExpiresError::Invalid) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Invalid Expires",
                    );
                }
            };
            let q_value = match self.parse_q_value(contact.as_str()) {
                Ok(value) => value,
                Err(ContactParamError::Invalid) => {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - Invalid q value",
                    );
                }
            };

            if let Some(existing) = existing_by_contact.get(&contact_uri) {
                if existing.call_id == call_id && cseq <= existing.cseq {
                    return self.build_error_response(
                        request,
                        400,
                        "Bad Request - CSeq out of order",
                    );
                }
            }

            if expires.as_secs() == 0 {
                // Remove binding
                self.store.remove(&aor, contact_uri.as_str())?;
                info!(aor = %aor, contact = %contact_uri, "REGISTER removed binding");
            } else {
                // Add or update binding
                let binding = Binding::new(SmolStr::new(aor.clone()), contact_uri.clone(), expires)
                    .with_call_id(call_id.clone())
                    .with_cseq(cseq)
                    .with_q_value(q_value);

                self.store.upsert(binding)?;
                info!(aor = %aor, contact = %contact_uri, expires = %expires.as_secs(), "REGISTER stored binding");
            }
        }

        // Build response
        let mut headers = Headers::new();

        // RFC 3261: Copy required headers from request to response
        if let Some(via) = request.headers().get("Via") {
            headers.push(SmolStr::new("Via"), via).unwrap();
        }
        if let Some(from) = request.headers().get("From") {
            headers.push(SmolStr::new("From"), from).unwrap();
        }
        // RFC 3261 §8.2.6.2: UAS MUST add tag to To header if not present
        if let Some(to) = request.headers().get("To") {
            headers.push(SmolStr::new("To"), ensure_to_tag(to)).unwrap();
        }
        if let Some(call_id) = request.headers().get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id).unwrap();
        }
        if let Some(cseq) = request.headers().get("CSeq") {
            headers.push(SmolStr::new("CSeq"), cseq).unwrap();
        }

        let bindings = self.store.lookup(&aor)?;
        for binding in &bindings {
            headers
                .push(
                    SmolStr::new("Contact"),
                    format_contact(&binding.contact, binding.expires, binding.q_value),
                )
                .unwrap();
        }

        headers
            .push(SmolStr::new("Date"), SmolStr::new(Utc::now().to_rfc2822()))
            .unwrap();
        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();

        Ok(Response::new(
            StatusLine::new(200, "OK")?,
            headers,
            Bytes::new(),
        )?)
    }
}

/// Collects all Contact header values from the provided headers.
pub fn contact_headers(headers: &Headers) -> Vec<SmolStr> {
    let mut contacts = Vec::new();
    for value in headers.get_all_smol("Contact") {
        for part in split_quoted_commas(value.as_str()) {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                contacts.push(SmolStr::new(trimmed));
            }
        }
    }
    contacts
}

fn format_contact(contact_uri: &SmolStr, expires: Duration, q_value: f32) -> SmolStr {
    if expires.as_secs() == 0 {
        SmolStr::new(format!("{};expires=0", contact_uri))
    } else {
        SmolStr::new(format!(
            "{};expires={};q={}",
            contact_uri,
            expires.as_secs(),
            q_value
        ))
    }
}

/// Ensures To header has a tag parameter (RFC 3261 §8.2.6.2)
/// If the To header doesn't have a tag, generates and adds one
fn ensure_to_tag(to_header: &str) -> SmolStr {
    // Check if tag already exists
    if to_header.contains(";tag=") {
        return SmolStr::new(to_header);
    }

    // Generate random tag (8 characters)
    let tag: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    // Append tag to To header
    SmolStr::new(format!("{};tag={}", to_header, tag))
}

fn split_quoted_commas(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escape_next = false;

    for ch in input.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escape_next = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_owned());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_owned());
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_auth::{Credentials, DigestAuthenticator, MemoryCredentialStore};
    use sip_core::{Headers, Method, RequestLine, SipUri};

    fn base_headers() -> Headers {
        let mut headers = Headers::new();
        headers
            .push("Via", "SIP/2.0/UDP client.example.com;branch=z9hG4bKtest")
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=from123")
            .unwrap();
        headers
    }

    #[test]
    fn collects_contact_headers() {
        let mut headers = Headers::new();
        headers.push("Contact", "<sip:a@example.com>").unwrap();
        headers.push("Contact", "<sip:b@example.com>").unwrap();
        let contacts = contact_headers(&headers);
        assert_eq!(contacts.len(), 2);
    }

    #[test]
    fn contact_headers_split_commas() {
        let mut headers = Headers::new();
        headers
            .push(
                "Contact",
                "\"Alice, A\" <sip:alice@example.com>, <sip:bob@example.com>",
            )
            .unwrap();
        let contacts = contact_headers(&headers);
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].as_str(), "\"Alice, A\" <sip:alice@example.com>");
        assert_eq!(contacts[1].as_str(), "<sip:bob@example.com>");
    }

    #[test]
    fn memory_store_adds_and_removes() {
        let store = MemoryLocationStore::new();
        store
            .upsert(Binding::new(
                "sip:alice@example.com".into(),
                "sip:ua.example.com".into(),
                Duration::from_secs(60),
            ))
            .unwrap();

        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 1);

        store
            .remove("sip:alice@example.com".into(), "sip:ua.example.com")
            .unwrap();

        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn memory_store_updates_existing_binding() {
        let store = MemoryLocationStore::new();

        // Add first binding
        store
            .upsert(Binding::new(
                "sip:alice@example.com".into(),
                "sip:ua.example.com".into(),
                Duration::from_secs(60),
            ))
            .unwrap();

        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 1);

        // Update with same contact but different expiry
        store
            .upsert(
                Binding::new(
                    "sip:alice@example.com".into(),
                    "sip:ua.example.com".into(),
                    Duration::from_secs(120),
                )
                .with_cseq(2),
            )
            .unwrap();

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].expires.as_secs() > 60); // Should be updated
        assert_eq!(bindings[0].cseq, 2);
    }

    #[test]
    fn memory_store_handles_multiple_contacts() {
        let store = MemoryLocationStore::new();

        store
            .upsert(Binding::new(
                "sip:alice@example.com".into(),
                "sip:ua1.example.com".into(),
                Duration::from_secs(60),
            ))
            .unwrap();

        store
            .upsert(Binding::new(
                "sip:alice@example.com".into(),
                "sip:ua2.example.com".into(),
                Duration::from_secs(60),
            ))
            .unwrap();

        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 2);
    }

    #[test]
    fn memory_store_cleanup_expired() {
        let store = MemoryLocationStore::new();

        // Add binding with very short expiry
        store
            .upsert(Binding::new(
                "sip:alice@example.com".into(),
                "sip:ua.example.com".into(),
                Duration::from_millis(10),
            ))
            .unwrap();

        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 1);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(15));

        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn memory_store_remove_all() {
        let store = MemoryLocationStore::new();

        store
            .upsert(Binding::new(
                "sip:alice@example.com".into(),
                "sip:ua1.example.com".into(),
                Duration::from_secs(60),
            ))
            .unwrap();

        store
            .upsert(Binding::new(
                "sip:alice@example.com".into(),
                "sip:ua2.example.com".into(),
                Duration::from_secs(60),
            ))
            .unwrap();

        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 2);

        store.remove_all("sip:alice@example.com").unwrap();
        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn basic_registrar_handles_register() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].contact.as_str(), "sip:ua.example.com");
        assert_eq!(bindings[0].call_id.as_str(), "call123");
        assert_eq!(bindings[0].cseq, 1);
    }

    #[test]
    fn basic_registrar_handles_multiple_contacts() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua1.example.com>;expires=60")
            .unwrap();
        headers
            .push("Contact", "<sip:ua2.example.com>;expires=120")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 2);
    }

    #[test]
    fn basic_registrar_handles_deregistration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        // First register
        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        registrar.handle_register(&request).expect("response");
        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 1);

        // Now deregister with expires=0
        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=0")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "2 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);
        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn basic_registrar_handles_wildcard_deregistration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        // Register multiple contacts
        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua1.example.com>;expires=60")
            .unwrap();
        headers
            .push("Contact", "<sip:ua2.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        registrar.handle_register(&request).expect("response");
        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 2);

        // Deregister all with wildcard
        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Contact", "*").unwrap();
        headers.push("Expires", "0").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "2 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);
        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn basic_registrar_parses_q_value() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;q=0.5;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        registrar.handle_register(&request).expect("response");

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        assert!((bindings[0].q_value - 0.5).abs() < 0.001);
    }

    #[test]
    fn basic_registrar_respects_min_expires() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None).with_min_expires(Duration::from_secs(100));

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=10")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 423);
        assert_eq!(response.headers().get("Min-Expires"), Some("100"));
    }

    #[test]
    fn basic_registrar_respects_max_expires() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None).with_max_expires(Duration::from_secs(1000));

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=99999")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn registrar_challenges_when_auth_configured() {
        let store = MemoryLocationStore::new();
        let creds = Credentials {
            username: "alice".into(),
            password: "secret".into(),
            realm: "example.com".into(),
        };
        let auth =
            DigestAuthenticator::new("example.com", MemoryCredentialStore::with(vec![creds]));
        let registrar = BasicRegistrar::new(store, Some(auth));

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=1234")
            .unwrap();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 401);

        // Verify WWW-Authenticate header is present
        assert!(response.headers().get("WWW-Authenticate").is_some());

        // RFC 3261: Verify required headers are copied from request
        assert_eq!(
            response.headers().get("Via"),
            Some("SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8")
        );
        assert_eq!(
            response.headers().get("From"),
            Some("<sip:alice@example.com>;tag=1234")
        );
        // RFC 3261 §8.2.6.2: Verify To header has tag added
        let to_header = response.headers().get("To").unwrap();
        assert!(to_header.starts_with("<sip:alice@example.com>"));
        assert!(to_header.contains(";tag=")); // Tag should be added
        assert_eq!(response.headers().get("Call-ID"), Some("call123"));
        assert_eq!(response.headers().get("CSeq"), Some("1 REGISTER"));
    }

    #[test]
    fn binding_builder_pattern() {
        let binding = Binding::new(
            "sip:alice@example.com".into(),
            "sip:ua.example.com".into(),
            Duration::from_secs(3600),
        )
        .with_call_id("call123".into())
        .with_cseq(42)
        .with_q_value(0.8);

        assert_eq!(binding.aor.as_str(), "sip:alice@example.com");
        assert_eq!(binding.contact.as_str(), "sip:ua.example.com");
        assert_eq!(binding.expires.as_secs(), 3600);
        assert_eq!(binding.call_id.as_str(), "call123");
        assert_eq!(binding.cseq, 42);
        assert!((binding.q_value - 0.8).abs() < 0.001);
    }

    #[test]
    fn extract_contact_uri_with_brackets() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let uri = registrar
            .extract_contact_uri("<sip:alice@example.com>;expires=3600")
            .expect("contact uri");
        assert_eq!(uri.as_str(), "sip:alice@example.com");
    }

    #[test]
    fn extract_contact_uri_without_brackets() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let uri = registrar
            .extract_contact_uri("sip:alice@example.com;expires=3600")
            .expect("contact uri");
        assert_eq!(uri.as_str(), "sip:alice@example.com");
    }

    #[test]
    fn registrar_returns_401_for_unknown_user() {
        let store = MemoryLocationStore::new();
        let creds = Credentials {
            username: "alice".into(),
            password: "secret".into(),
            realm: "example.com".into(),
        };
        let auth =
            DigestAuthenticator::new("example.com", MemoryCredentialStore::with(vec![creds]));
        let registrar = BasicRegistrar::new(store, Some(auth));

        // Build a REGISTER with valid auth headers but unknown user
        let nonce = registrar
            .authenticator
            .as_ref()
            .unwrap()
            .nonce_manager
            .generate();

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers
            .push("From", "<sip:bob@example.com>;tag=1234")
            .unwrap();
        headers.push("To", "<sip:bob@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();
        headers.push(
            "Authorization",            format!(
                "Digest username=\"bob\", realm=\"example.com\", nonce=\"{}\", uri=\"sip:example.com\", response=\"invalid\", opaque=\"{}\"",
                nonce.value,
                registrar.authenticator.as_ref().unwrap().opaque
            )
        ).unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Should return 401 challenge, not 500 error
        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(
            response.code(),
            401,
            "Unknown user should return 401, not 500"
        );
        assert!(response.headers().get("WWW-Authenticate").is_some());
    }

    #[test]
    fn registrar_returns_401_for_malformed_auth_header() {
        let store = MemoryLocationStore::new();
        let creds = Credentials {
            username: "alice".into(),
            password: "secret".into(),
            realm: "example.com".into(),
        };
        let auth =
            DigestAuthenticator::new("example.com", MemoryCredentialStore::with(vec![creds]));
        let registrar = BasicRegistrar::new(store, Some(auth));

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=1234")
            .unwrap();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();
        // Malformed Authorization header (missing required fields)
        headers
            .push("Authorization", "Digest username=\"alice\"")
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Should return 401 challenge, not 500 error
        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(
            response.code(),
            401,
            "Malformed auth should return 401, not 500"
        );
        assert!(response.headers().get("WWW-Authenticate").is_some());
    }

    #[test]
    fn registrar_returns_401_for_invalid_nonce_count() {
        let store = MemoryLocationStore::new();
        let creds = Credentials {
            username: "alice".into(),
            password: "secret".into(),
            realm: "example.com".into(),
        };
        let auth =
            DigestAuthenticator::new("example.com", MemoryCredentialStore::with(vec![creds]));
        let registrar = BasicRegistrar::new(store, Some(auth));

        let nonce = registrar
            .authenticator
            .as_ref()
            .unwrap()
            .nonce_manager
            .generate();

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=1234")
            .unwrap();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();
        // Invalid nc format (not hex)
        headers.push(
            "Authorization",            format!(
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"{}\", uri=\"sip:example.com\", response=\"test\", nc=INVALID, cnonce=\"abc\", qop=auth, opaque=\"{}\"",
                nonce.value,
                registrar.authenticator.as_ref().unwrap().opaque
            )
        ).unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Should return 401 challenge, not 500 error
        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(
            response.code(),
            401,
            "Invalid nc format should return 401, not 500"
        );
        assert!(response.headers().get("WWW-Authenticate").is_some());
    }

    #[test]
    fn registrar_returns_400_for_missing_to_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=1234")
            .unwrap();
        // Missing To header
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400, "Missing To header should return 400");
        assert!(response.reason().contains("To"));
    }

    #[test]
    fn registrar_returns_400_for_invalid_to_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=1234")
            .unwrap();
        headers.push("To", "invalid-header-format").unwrap(); // Invalid To header
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400, "Invalid To header should return 400");
        assert!(response.reason().contains("To"));
    }

    #[test]
    fn registrar_returns_400_for_missing_contact_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=1234")
            .unwrap();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        // Missing Contact header

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(
            response.code(),
            400,
            "Missing Contact header should return 400"
        );
        assert!(response.reason().contains("Contact"));
    }

    #[test]
    fn registrar_returns_400_for_missing_via_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = Headers::new();
        headers
            .push("From", "<sip:alice@example.com>;tag=1234")
            .unwrap();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Via"));
    }

    #[test]
    fn registrar_returns_400_for_missing_from_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = Headers::new();
        headers
            .push(
                "Via",
                "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8",
            )
            .unwrap();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("From"));
    }

    #[test]
    fn registrar_returns_400_for_missing_call_id_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Call-ID"));
    }

    #[test]
    fn registrar_returns_400_for_missing_cseq_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("CSeq"));
    }

    #[test]
    fn registrar_rejects_invalid_cseq_method() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Contact", "<sip:ua.example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 INVITE").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("CSeq"));
    }

    #[test]
    fn registrar_rejects_invalid_expires_param() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=abc")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Expires"));
    }

    #[test]
    fn registrar_rejects_invalid_q_param() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;q=abc;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("q"));
    }

    #[test]
    fn registrar_rejects_unsupported_contact_uri_scheme() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers
            .push("Contact", "<mailto:alice@example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Contact"));
    }

    #[test]
    fn registrar_400_response_includes_required_headers() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = Headers::new();
        headers
            .push("Via", "SIP/2.0/UDP client.example.com;branch=z9hG4bKtest")
            .unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=from123")
            .unwrap();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "callid-test-123").unwrap();
        headers.push("CSeq", "42 REGISTER").unwrap();
        // Missing Contact header to trigger 400

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar
            .handle_register(&request)
            .expect("should return response");
        assert_eq!(response.code(), 400);

        // Verify RFC 3261 required headers are present
        assert_eq!(
            response.headers().get("Via"),
            Some("SIP/2.0/UDP client.example.com;branch=z9hG4bKtest")
        );
        assert_eq!(
            response.headers().get("From"),
            Some("<sip:alice@example.com>;tag=from123")
        );
        assert_eq!(response.headers().get("Call-ID"), Some("callid-test-123"));
        assert_eq!(response.headers().get("CSeq"), Some("42 REGISTER"));

        // Verify To header has tag added
        let to = response
            .headers()
            .get("To")
            .expect("To header should be present");
        assert!(to.contains(";tag="), "To header should have tag added");
    }

    // ========== tel URI Tests ==========

    #[test]
    fn normalize_aor_handles_global_tel_uri() {
        use sip_core::{TelUri, Uri};

        // Global tel URI with visual separators
        let tel = TelUri::parse("tel:+1-555-123-4567").unwrap();
        let uri = Uri::Tel(tel);
        let normalized = normalize_aor(&uri).expect("normalize_aor");

        // Should normalize to remove visual separators
        assert_eq!(normalized, "tel:+15551234567");
    }

    #[test]
    fn normalize_aor_handles_local_tel_uri() {
        use sip_core::{TelUri, Uri};

        // Local tel URI with phone-context
        let tel = TelUri::parse("tel:5551234;phone-context=example.com").unwrap();
        let uri = Uri::Tel(tel);
        let normalized = normalize_aor(&uri).expect("normalize_aor");

        assert_eq!(normalized, "tel:5551234;phone-context=example.com");
    }

    #[test]
    fn normalize_aor_includes_tel_params() {
        use sip_core::{TelUri, Uri};

        let tel = TelUri::parse("tel:+1-555-123-4567;ext=123;isub=xyz").unwrap();
        let uri = Uri::Tel(tel);
        let normalized = normalize_aor(&uri).expect("normalize_aor");

        assert_eq!(normalized, "tel:+15551234567;ext=123;isub=xyz");
    }

    #[test]
    fn normalize_aor_normalizes_local_tel_context() {
        use sip_core::{TelUri, Uri};

        let tel = TelUri::parse("tel:555-1234;phone-context=EXAMPLE.com").unwrap();
        let uri = Uri::Tel(tel);
        let normalized = normalize_aor(&uri).expect("normalize_aor");

        assert_eq!(normalized, "tel:5551234;phone-context=example.com");
    }

    #[test]
    fn registrar_handles_global_tel_uri_registration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<tel:+1-555-123-4567>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        // Verify binding was stored with normalized tel URI
        let bindings = store.lookup("tel:+15551234567").unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].aor.as_str(), "tel:+15551234567");
        assert_eq!(bindings[0].contact.as_str(), "sip:ua.example.com");
    }

    #[test]
    fn registrar_handles_local_tel_uri_registration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers
            .push("To", "<tel:5551234;phone-context=example.com>")
            .unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        // Verify binding with phone-context
        let bindings = store
            .lookup("tel:5551234;phone-context=example.com")
            .unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].contact.as_str(), "sip:ua.example.com");
    }

    #[test]
    fn registrar_handles_tel_uri_deregistration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        // First register
        let mut headers = base_headers();
        headers.push("To", "<tel:+15551234567>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        registrar.handle_register(&request).expect("response");
        assert_eq!(store.lookup("tel:+15551234567").unwrap().len(), 1);

        // Now deregister with expires=0
        let mut headers = base_headers();
        headers.push("To", "<tel:+1-555-123-4567>").unwrap(); // Different format, same number
        headers
            .push("Contact", "<sip:ua.example.com>;expires=0")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "2 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        // Should be removed (normalization makes them equivalent)
        assert!(store.lookup("tel:+15551234567").unwrap().is_empty());
    }

    #[test]
    fn registrar_handles_multiple_tel_uri_contacts() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<tel:+15551234567>").unwrap();
        headers
            .push("Contact", "<sip:ua1.example.com>;expires=60")
            .unwrap();
        headers
            .push("Contact", "<sip:ua2.example.com>;expires=120")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        let bindings = store.lookup("tel:+15551234567").unwrap();
        assert_eq!(bindings.len(), 2);

        let contacts: Vec<&str> = bindings.iter().map(|b| b.contact.as_str()).collect();
        assert!(contacts.contains(&"sip:ua1.example.com"));
        assert!(contacts.contains(&"sip:ua2.example.com"));
    }

    #[test]
    fn registrar_handles_tel_uri_wildcard_deregistration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        // Register multiple contacts
        let mut headers = base_headers();
        headers.push("To", "<tel:+15551234567>").unwrap();
        headers
            .push("Contact", "<sip:ua1.example.com>;expires=60")
            .unwrap();
        headers
            .push("Contact", "<sip:ua2.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        registrar.handle_register(&request).expect("response");
        assert_eq!(store.lookup("tel:+15551234567").unwrap().len(), 2);

        // Deregister all with wildcard
        let mut headers = base_headers();
        headers.push("To", "<tel:+1-555-123-4567>").unwrap();
        headers.push("Contact", "*").unwrap();
        headers.push("Expires", "0").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "2 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);
        assert!(store.lookup("tel:+15551234567").unwrap().is_empty());
    }

    #[test]
    fn registrar_rejects_absolute_uri_in_to_header() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<mailto:alice@example.com>").unwrap();
        headers
            .push("Contact", "<sip:ua.example.com>;expires=60")
            .unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Unsupported"));
    }

    #[test]
    fn normalize_aor_preserves_sip_uri_behavior() {
        use sip_core::{SipUri, Uri};

        // Test that SIP URI normalization still works as before
        let sip = SipUri::parse("sip:alice@example.com;transport=tcp").unwrap();
        let uri = Uri::Sip(sip);
        let normalized = normalize_aor(&uri).expect("normalize_aor");

        // Parameters should be stripped
        assert_eq!(normalized, "sip:alice@example.com");
    }

    #[test]
    fn normalize_error_display() {
        let error = NormalizeError::UnsupportedScheme;
        let display = format!("{}", error);
        assert!(display.contains("not supported"));
        assert!(display.contains("SIP/SIPS/tel"));
    }

    #[test]
    fn normalize_error_is_error_trait() {
        use std::error::Error;
        let error: Box<dyn Error> = Box::new(NormalizeError::UnsupportedScheme);
        let display = format!("{}", error);
        assert!(display.contains("not supported"));
    }

    // ========== Edge Case Tests ==========

    #[test]
    fn registrar_handles_multiple_commas_in_contact() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        // Multiple commas and empty entries
        headers
            .push("Contact", "<sip:a@example.com>,,<sip:b@example.com>")
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        // Should have 2 bindings (empty entries ignored)
        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 2);
    }

    #[test]
    fn registrar_handles_contact_with_escaped_quotes() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        // Display name with escaped quote
        headers
            .push("Contact", r#""Alice \"CEO\"" <sip:alice@example.com>"#)
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].contact.as_str(), "sip:alice@example.com");
    }

    #[test]
    fn registrar_rejects_empty_contact_uri() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<>").unwrap(); // Empty URI

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Contact"));
    }

    #[test]
    fn registrar_rejects_unclosed_angle_bracket() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:alice@example.com").unwrap(); // Missing >

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Contact"));
    }

    #[test]
    fn registrar_rejects_wildcard_with_other_contacts() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Expires", "0").unwrap();
        headers.push("Contact", "*").unwrap();
        headers.push("Contact", "<sip:bob@example.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Wildcard"));
    }

    #[test]
    fn registrar_rejects_wildcard_without_expires_zero() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Expires", "3600").unwrap(); // Non-zero
        headers.push("Contact", "*").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Expires: 0"));
    }

    #[test]
    fn registrar_handles_case_insensitive_sip_host() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        // Register with uppercase domain
        let mut headers = base_headers();
        headers.push("To", "<sip:alice@EXAMPLE.COM>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<sip:alice@device.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        registrar.handle_register(&request).expect("response");

        // Lookup with lowercase should work
        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].contact.as_str(), "sip:alice@device.com");
    }

    #[test]
    fn registrar_rejects_negative_expires() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers
            .push("Contact", "<sip:alice@device.com>;expires=-1")
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Expires"));
    }

    #[test]
    fn registrar_rejects_non_numeric_expires() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers
            .push("Contact", "<sip:alice@device.com>;expires=abc")
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Expires"));
    }

    #[test]
    fn registrar_rejects_q_value_out_of_range() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers
            .push("Contact", "<sip:alice@device.com>;q=1.5")
            .unwrap(); // > 1.0

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("q value"));
    }

    #[test]
    fn registrar_rejects_non_numeric_q_value() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers
            .push("Contact", "<sip:alice@device.com>;q=high")
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("q value"));
    }

    #[test]
    fn registrar_handles_cseq_with_extra_whitespace() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "  1   REGISTER  ").unwrap(); // Extra whitespace
        headers.push("Contact", "<sip:alice@device.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
    }

    #[test]
    fn registrar_rejects_cseq_with_wrong_method() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 INVITE").unwrap(); // Wrong method
        headers.push("Contact", "<sip:alice@device.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("CSeq"));
    }

    #[test]
    fn registrar_rejects_cseq_with_missing_method() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1").unwrap(); // Missing method
        headers.push("Contact", "<sip:alice@device.com>").unwrap();

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("CSeq"));
    }

    #[test]
    fn registrar_rejects_tel_uri_in_contact() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers.push("Contact", "<tel:+15551234567>").unwrap(); // tel URI not allowed

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 400);
        assert!(response.reason().contains("Unsupported Contact URI"));
    }

    #[test]
    fn registrar_handles_contact_without_angle_brackets() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = base_headers();
        headers.push("To", "<sip:alice@example.com>").unwrap();
        headers.push("Call-ID", "call123").unwrap();
        headers.push("CSeq", "1 REGISTER").unwrap();
        headers
            .push("Contact", "sip:alice@device.com;expires=60")
            .unwrap(); // No angle brackets

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.code(), 200);

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].contact.as_str(), "sip:alice@device.com");
    }

    #[test]
    fn split_quoted_commas_handles_escaped_quotes() {
        let input = r#""Alice \"CEO\"" <sip:alice@example.com>, <sip:bob@example.com>"#;
        let parts = split_quoted_commas(input);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], r#""Alice \"CEO\"" <sip:alice@example.com>"#);
        assert_eq!(parts[1], "<sip:bob@example.com>");
    }

    #[test]
    fn split_quoted_commas_handles_nested_commas() {
        let input = r#""Smith, John" <sip:john@example.com>, "Doe, Jane" <sip:jane@example.com>"#;
        let parts = split_quoted_commas(input);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], r#""Smith, John" <sip:john@example.com>"#);
        assert_eq!(parts[1], r#""Doe, Jane" <sip:jane@example.com>"#);
    }

    #[test]
    fn split_quoted_commas_handles_empty_entries() {
        let input = "<sip:a@example.com>,,<sip:b@example.com>";
        let parts = split_quoted_commas(input);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "<sip:a@example.com>");
        assert_eq!(parts[1], "<sip:b@example.com>");
    }

    #[test]
    fn normalize_aor_lowercases_sip_host() {
        use sip_core::{SipUri, Uri};

        let sip = SipUri::parse("sip:alice@EXAMPLE.COM").unwrap();
        let uri = Uri::Sip(sip);
        let normalized = normalize_aor(&uri).expect("normalize_aor");

        assert_eq!(normalized, "sip:alice@example.com");
    }

    #[test]
    fn normalize_aor_lowercases_sip_host_with_port() {
        use sip_core::{SipUri, Uri};

        let sip = SipUri::parse("sip:alice@EXAMPLE.COM:5060").unwrap();
        let uri = Uri::Sip(sip);
        let normalized = normalize_aor(&uri).expect("normalize_aor");

        assert_eq!(normalized, "sip:alice@example.com:5060");
    }
}
