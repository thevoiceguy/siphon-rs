// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP Digest Authentication (RFC 7616/7617).
//!
//! This crate implements HTTP Digest authentication for SIP, supporting:
//! - **Algorithms**: MD5, SHA-256, SHA-512
//! - **Quality of Protection (qop)**: auth, auth-int
//! - **Nonce Management**: Automatic expiry tracking and replay protection
//! - **Server-side**: Challenge generation (401/407) and credential verification
//! - **Client-side**: Authorization header generation from challenges
//! - **Flexible Storage**: Pluggable credential backends (sync/async)
//!
//! # Examples
//!
//! ```no_run
//! # use sip_auth::*;
//! # use sip_core::Request;
//! // Server-side authentication
//! let store = MemoryCredentialStore::new();
//! let auth = DigestAuthenticator::new("example.com", store);
//!
//! // Generate 401 challenge
//! # let request = todo!();
//! let challenge = auth.challenge(&request)?;
//!
//! // Verify credentials from Authorization header
//! # let headers = todo!();
//! let valid = auth.verify(&request, &headers)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sha2::{Digest, Sha256, Sha512};
use sip_core::{Headers, Method, Request, Response, StatusLine};
use sip_parse::parse_authorization_header;
use sip_ratelimit::RateLimiter;
use smol_str::SmolStr;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{runtime::Handle, task};
use tracing::{info, warn};

/// Credentials used for SIP authentication.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: SmolStr,
    pub password: SmolStr,
    pub realm: SmolStr,
}

/// Authentication backend responsible for challenges and verification.
pub trait Authenticator: Send + Sync {
    fn challenge(&self, request: &Request) -> Result<Response>;
    fn verify(&self, request: &Request, headers: &Headers) -> Result<bool>;
    fn credentials_for(&self, method: &Method, uri: &str) -> Option<Credentials>;
}

/// Credential store abstraction for server-side verification.
pub trait CredentialStore: Send + Sync {
    fn fetch(&self, username: &str, realm: &str) -> Option<Credentials>;
}

/// Async credential store for non-blocking backends.
#[async_trait]
pub trait AsyncCredentialStore: Send + Sync {
    async fn fetch(&self, username: &str, realm: &str) -> Option<Credentials>;
}

/// Adapter to expose an async credential store as a sync store.
pub struct AsyncToSyncCredentialAdapter<T: AsyncCredentialStore> {
    inner: T,
}

impl<T: AsyncCredentialStore> AsyncToSyncCredentialAdapter<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        task::block_in_place(|| Handle::current().block_on(fut))
    }
}

impl<T: AsyncCredentialStore> CredentialStore for AsyncToSyncCredentialAdapter<T> {
    fn fetch(&self, username: &str, realm: &str) -> Option<Credentials> {
        self.block_on(self.inner.fetch(username, realm))
    }
}

/// Adapter to expose a synchronous store as async using spawn_blocking.
pub struct SyncToAsyncCredentialAdapter<T: CredentialStore> {
    inner: Arc<T>,
}

impl<T: CredentialStore> SyncToAsyncCredentialAdapter<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

#[async_trait]
impl<T: CredentialStore + 'static> AsyncCredentialStore for SyncToAsyncCredentialAdapter<T> {
    async fn fetch(&self, username: &str, realm: &str) -> Option<Credentials> {
        let inner = Arc::clone(&self.inner);
        let username = username.to_owned();
        let realm = realm.to_owned();
        task::spawn_blocking(move || inner.fetch(&username, &realm))
            .await
            .ok()
            .flatten()
    }
}

/// In-memory credential store for testing/demo.
#[derive(Default)]
pub struct MemoryCredentialStore {
    creds: Vec<Credentials>,
}

impl MemoryCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(creds: Vec<Credentials>) -> Self {
        Self { creds }
    }

    pub fn add(&mut self, creds: Credentials) {
        self.creds.push(creds);
    }

    /// Convenience inherent fetch that delegates to the sync trait implementation.
    pub fn fetch(&self, username: &str, realm: &str) -> Option<Credentials> {
        CredentialStore::fetch(self, username, realm)
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn fetch(&self, username: &str, realm: &str) -> Option<Credentials> {
        self.creds
            .iter()
            .find(|c| c.username == username && c.realm == realm)
            .cloned()
    }
}

#[async_trait]
impl AsyncCredentialStore for MemoryCredentialStore {
    async fn fetch(&self, username: &str, realm: &str) -> Option<Credentials> {
        CredentialStore::fetch(self, username, realm)
    }
}

/// Digest algorithm per RFC 7616.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
    Sha256,
    Sha512,
}

impl DigestAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            DigestAlgorithm::Md5 => "MD5",
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha512 => "SHA-512",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Some(DigestAlgorithm::Md5),
            "SHA-256" => Some(DigestAlgorithm::Sha256),
            "SHA-512" | "SHA-512-256" => Some(DigestAlgorithm::Sha512),
            _ => None,
        }
    }
}

impl std::str::FromStr for DigestAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

/// Quality of Protection (qop) options per RFC 7616.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qop {
    Auth,
    AuthInt,
}

impl Qop {
    pub fn as_str(&self) -> &'static str {
        match self {
            Qop::Auth => "auth",
            Qop::AuthInt => "auth-int",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auth" => Some(Qop::Auth),
            "auth-int" => Some(Qop::AuthInt),
            _ => None,
        }
    }
}

impl std::str::FromStr for Qop {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

/// Maximum number of nonces to keep in memory to prevent unbounded growth.
const MAX_NONCE_COUNT: usize = 10_000;
const DEFAULT_MAX_REQUEST_AGE: Duration = Duration::from_secs(10);
const MAX_PARAM_USERNAME_LEN: usize = 256;
const MAX_PARAM_REALM_LEN: usize = 256;
const MAX_PARAM_NONCE_LEN: usize = 128;
const MAX_PARAM_URI_LEN: usize = 2048;
const MAX_PARAM_RESPONSE_LEN: usize = 512;
const MAX_PARAM_CNONCE_LEN: usize = 256;
const MAX_PARAM_NC_LEN: usize = 8;
const MAX_PARAM_OPAQUE_LEN: usize = 256;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
const MAX_VIA_HOST_LEN: usize = 256;
const MAX_NC_VALUE: u32 = 1_000_000;
const MAX_NC_JUMP: u32 = 1_000;

fn validate_param(name: &str, value: &str, max_len: usize) -> Result<()> {
    if value.len() > max_len {
        return Err(anyhow!("{} too long", name));
    }
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err(anyhow!("{} contains invalid characters", name));
    }
    Ok(())
}

/// Nonce with expiry tracking and usage tracking for replay protection.
#[derive(Debug, Clone)]
pub struct Nonce {
    pub value: SmolStr,
    pub created_at: Instant,
    pub ttl: Duration,
    pub last_nc: u32, // Last nonce-count seen (for replay protection)
    pub last_request_hash: Option<String>, // Hash of last request (method:uri:body) for retransmission detection
    pub last_used: Instant, // Timestamp of last successful authentication (for request age validation)
}

impl Nonce {
    pub fn new(ttl: Duration) -> Self {
        let token: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let now = Instant::now();
        Self {
            value: SmolStr::new(token),
            created_at: now,
            ttl,
            last_nc: 0,
            last_request_hash: None,
            last_used: now,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.created_at.elapsed() <= self.ttl
    }

    /// Validates nonce-count with full request hash for replay protection.
    /// - If nc > last_nc: New request, accept and store hash
    /// - If nc == last_nc: Retransmission, accept only if request hash matches exactly
    /// - If nc < last_nc: Replay attack, reject
    ///
    /// This allows legitimate UDP retransmissions (same request, same nc) while
    /// blocking replay attacks (different request with same/old nc).
    ///
    /// Also validates request age to prevent replay attacks using cached credentials.
    /// Requests must be made within a reasonable time window after the previous request.
    pub fn validate_nc_with_request(
        &mut self,
        nc: u32,
        method: &Method,
        uri: &str,
        body: &[u8],
        max_request_age: Duration,
    ) -> bool {
        // Reject requests that are significantly delayed (potential replay attack)
        if self.last_nc > 0 && self.last_used.elapsed() > max_request_age {
            // If this isn't the first request (last_nc > 0) and it's been too long
            // since the last successful auth, reject as potential replay
            return false;
        }
        // Compute hash of request (method:uri:body bytes).
        let mut ctx = Sha256::new();
        ctx.update(method.as_str().as_bytes());
        ctx.update(b":");
        ctx.update(uri.as_bytes());
        ctx.update(b":");
        ctx.update(body);
        let request_hash = hex::encode(ctx.finalize());

        if nc > self.last_nc {
            // New request with incrementing nc - accept and store
            self.last_nc = nc;
            self.last_request_hash = Some(request_hash);
            self.last_used = Instant::now(); // Update last used time
            true
        } else if nc == self.last_nc {
            // Potential retransmission - accept only if request hash matches
            if let Some(ref last_hash) = self.last_request_hash {
                if last_hash == &request_hash {
                    // Valid retransmission, update last used time
                    self.last_used = Instant::now();
                    true
                } else {
                    false
                }
            } else {
                // First request with this nc
                self.last_request_hash = Some(request_hash);
                self.last_used = Instant::now();
                true
            }
        } else {
            // nc < last_nc is a replay attack (going backwards)
            false
        }
    }
}

/// Nonce manager with automatic cleanup and size limits.
#[derive(Debug)]
pub struct NonceManager {
    nonces: Arc<DashMap<SmolStr, Nonce>>,
    ttl: Duration,
    max_nonces: usize,
    max_request_age: Duration,
}

impl NonceManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            nonces: Arc::new(DashMap::new()),
            ttl,
            max_nonces: MAX_NONCE_COUNT,
            max_request_age: DEFAULT_MAX_REQUEST_AGE,
        }
    }

    pub fn with_max_nonces(mut self, max: usize) -> Self {
        self.max_nonces = max;
        self
    }

    pub fn with_max_request_age(mut self, max_request_age: Duration) -> Self {
        self.max_request_age = max_request_age;
        self
    }

    pub fn generate(&self) -> Nonce {
        // If we're at capacity, run cleanup before generating new nonce
        if self.nonces.len() >= self.max_nonces {
            self.cleanup();

            // If still at capacity after cleanup, remove oldest nonces
            if self.nonces.len() >= self.max_nonces {
                self.remove_oldest(self.max_nonces / 10); // Remove 10% of capacity
            }
        }

        let nonce = Nonce::new(self.ttl);
        self.nonces.insert(nonce.value.clone(), nonce.clone());
        nonce
    }

    /// Verifies nonce exists and is valid, and validates nonce-count with request hash for replay protection.
    /// Returns true if nonce is valid and request is legitimate (not a replay).
    pub fn verify_with_nc(
        &self,
        value: &str,
        nc: u32,
        method: &Method,
        uri: &str,
        body: &[u8],
    ) -> bool {
        if let Some(mut entry) = self.nonces.get_mut(value) {
            if !entry.is_valid() {
                return false;
            }
            // Validate nc and request hash (replay protection + retransmission support)
            entry.validate_nc_with_request(nc, method, uri, body, self.max_request_age)
        } else {
            false
        }
    }

    /// Basic verification without nonce-count tracking (for backwards compatibility).
    /// Use verify_with_nc() for proper replay protection.
    pub fn verify(&self, value: &str) -> bool {
        if let Some(entry) = self.nonces.get(value) {
            entry.is_valid()
        } else {
            false
        }
    }

    /// Removes expired nonces from the map.
    pub fn cleanup(&self) {
        self.nonces.retain(|_, nonce| nonce.is_valid());
    }

    fn is_nc_jump_reasonable(&self, value: &str, nc: u32) -> bool {
        if let Some(entry) = self.nonces.get(value) {
            if nc > entry.last_nc.saturating_add(MAX_NC_JUMP) {
                return false;
            }
        }
        true
    }

    /// Removes the oldest nonces up to the specified count.
    fn remove_oldest(&self, count: usize) {
        let mut entries: Vec<_> = self
            .nonces
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().created_at))
            .collect();

        // Sort by creation time (oldest first)
        entries.sort_by_key(|(_, created_at)| *created_at);

        // Remove oldest entries
        for (key, _) in entries.iter().take(count) {
            self.nonces.remove(key);
        }
    }

    pub fn count(&self) -> usize {
        self.nonces.len()
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

/// Extract rate-limiting key from the top Via header.
///
/// Prefer the `received` parameter if present (added by the receiving server),
/// falling back to the host portion of the Via header.
fn extract_rate_limit_key(headers: &Headers) -> Option<String> {
    let via = headers.get("Via")?;

    // Via format: SIP/2.0/TRANSPORT host[:port];params
    // Skip "SIP/2.0/TRANSPORT " part
    let parts: Vec<&str> = via.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    // Extract host[:port] and params
    let mut host_part = parts[1];
    if host_part.is_empty() || host_part.len() > MAX_VIA_HOST_LEN {
        return None;
    }
    let mut params = "";
    if let Some((host, params_part)) = host_part.split_once(';') {
        host_part = host;
        params = params_part;
    }

    if !params.is_empty() {
        for param in params.split(';') {
            if let Some(value) = param.strip_prefix("received=") {
                return Some(extract_via_host(value)?.to_string());
            }
        }
    }

    // Remove port from host part.
    let host = extract_via_host(host_part)?;

    Some(host.to_string())
}

fn extract_via_host(host_part: &str) -> Option<&str> {
    if host_part.is_empty() || host_part.len() > MAX_VIA_HOST_LEN {
        return None;
    }

    if host_part.starts_with('[') {
        let end = host_part.find(']')?;
        if end <= 1 {
            return None;
        }
        return Some(&host_part[1..end]);
    }

    let colon_count = host_part.matches(':').count();
    if colon_count == 1 {
        return host_part.split_once(':').map(|(host, _)| host);
    }

    Some(host_part)
}

struct DigestParams {
    username: SmolStr,
    realm: SmolStr,
    nonce: SmolStr,
    uri: SmolStr,
    response: SmolStr,
    nc_raw: Option<SmolStr>,
    cnonce: Option<SmolStr>,
    qop: Option<Qop>,
}

/// Digest authenticator implementing RFC 7616 (MD5, SHA-256, SHA-512).
pub struct DigestAuthenticator<S> {
    pub realm: SmolStr,
    pub algorithm: DigestAlgorithm,
    pub qop: Qop,
    pub store: S,
    pub nonce_manager: NonceManager,
    pub proxy_auth: bool,
    pub opaque: SmolStr, // Opaque session token for additional security
    pub rate_limiter: Option<RateLimiter>, // Optional rate limiting
}

impl<S> DigestAuthenticator<S> {
    fn prepare_digest(&self, request: &Request, headers: &Headers) -> Result<Option<DigestParams>> {
        if request.body.len() > MAX_BODY_SIZE {
            return Err(anyhow!("request body too large"));
        }

        if let Some(ref limiter) = self.rate_limiter {
            if let Some(key) = extract_rate_limit_key(headers) {
                if !limiter.check_rate_limit(&key) {
                    warn!(key = %key, "authentication rate limit exceeded");
                    return Err(anyhow!("rate limit exceeded"));
                }
            }
        }

        let header_name = if self.proxy_auth {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };

        let auth_header = match headers.get(header_name) {
            Some(h) => h,
            None => return Ok(None),
        };

        let parsed = match parse_authorization_header(auth_header) {
            Some(p) => p,
            None => return Ok(None),
        };

        if !parsed.scheme.eq_ignore_ascii_case("Digest") {
            return Ok(None);
        }

        let username = parsed
            .param("username")
            .ok_or_else(|| anyhow!("missing username"))?;
        let realm = parsed
            .param("realm")
            .ok_or_else(|| anyhow!("missing realm"))?;
        let nonce = parsed
            .param("nonce")
            .ok_or_else(|| anyhow!("missing nonce"))?;
        let uri = parsed.param("uri").ok_or_else(|| anyhow!("missing uri"))?;
        let response = parsed
            .param("response")
            .ok_or_else(|| anyhow!("missing response"))?;

        validate_param("username", username.as_str(), MAX_PARAM_USERNAME_LEN)?;
        validate_param("realm", realm.as_str(), MAX_PARAM_REALM_LEN)?;
        validate_param("nonce", nonce.as_str(), MAX_PARAM_NONCE_LEN)?;
        validate_param("uri", uri.as_str(), MAX_PARAM_URI_LEN)?;
        validate_param("response", response.as_str(), MAX_PARAM_RESPONSE_LEN)?;

        let algorithm = match parsed.param("algorithm") {
            Some(alg_str) => match DigestAlgorithm::parse(alg_str.as_str()) {
                Some(alg) => alg,
                None => return Ok(None),
            },
            None => self.algorithm,
        };

        if algorithm != self.algorithm {
            info!("digest algorithm mismatch");
            return Ok(None);
        }

        let nc = parsed.param("nc");
        let cnonce = parsed.param("cnonce");
        let qop = parsed.param("qop").and_then(|q| Qop::parse(q.as_str()));
        let opaque = parsed.param("opaque");

        if let Some(nc_str) = nc {
            validate_param("nc", nc_str.as_str(), MAX_PARAM_NC_LEN)?;
        }
        if let Some(cnonce_str) = cnonce {
            validate_param("cnonce", cnonce_str.as_str(), MAX_PARAM_CNONCE_LEN)?;
        }
        if let Some(opaque_str) = opaque {
            validate_param("opaque", opaque_str.as_str(), MAX_PARAM_OPAQUE_LEN)?;
        }

        if realm.as_str() != self.realm.as_str() {
            info!("digest realm mismatch");
            return Ok(None);
        }

        if uri.as_str() != request.start.uri.as_str() {
            info!("digest uri mismatch");
            return Ok(None);
        }

        if let Some(client_opaque) = opaque {
            if client_opaque.as_str() != self.opaque.as_str() {
                info!("digest opaque mismatch");
                return Ok(None);
            }
        } else {
            info!("digest missing opaque parameter");
            return Ok(None);
        }

        if qop != Some(self.qop) {
            info!("digest qop missing or mismatch");
            return Ok(None);
        }

        if nc.is_none() || cnonce.is_none() {
            info!("digest missing nc/cnonce with qop");
            return Ok(None);
        }

        let _validated_nc = if let Some(nc_str) = nc {
            let nc_value = u32::from_str_radix(nc_str.as_str(), 16)
                .map_err(|_| anyhow!("invalid nc format"))?;

            if nc_value > MAX_NC_VALUE {
                info!("digest nc value too large");
                return Ok(None);
            }

            if !self.nonce_manager.is_nc_jump_reasonable(nonce.as_str(), nc_value) {
                info!("digest nc jump too large");
                return Ok(None);
            }

            if !self.nonce_manager.verify_with_nc(
                nonce,
                nc_value,
                &request.start.method,
                request.start.uri.as_str(),
                &request.body,
            ) {
                info!("digest nonce invalid/expired, nc decreasing (replay), or request hash mismatch (different request with same nc)");
                return Ok(None);
            }
            Some(nc_value)
        } else {
            if !self.nonce_manager.verify(nonce) {
                info!("digest nonce invalid/expired");
                return Ok(None);
            }
            None
        };

        Ok(Some(DigestParams {
            username: username.clone(),
            realm: realm.clone(),
            nonce: nonce.clone(),
            uri: uri.clone(),
            response: response.clone(),
            nc_raw: nc.cloned(),
            cnonce: cnonce.cloned(),
            qop,
        }))
    }
}

impl<S> DigestAuthenticator<S> {
    pub fn new(realm: &str, store: S) -> Self {
        // Generate a random opaque value for this authenticator instance
        let opaque: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        Self {
            realm: SmolStr::new(realm),
            algorithm: DigestAlgorithm::Sha256,
            qop: Qop::Auth,
            store,
            nonce_manager: NonceManager::default(),
            proxy_auth: false,
            opaque: SmolStr::new(opaque),
            rate_limiter: None,
        }
    }

    pub fn with_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_qop(mut self, qop: Qop) -> Self {
        self.qop = qop;
        self
    }

    pub fn with_proxy_auth(mut self, proxy_auth: bool) -> Self {
        self.proxy_auth = proxy_auth;
        self
    }

    pub fn with_nonce_ttl(mut self, ttl: Duration) -> Self {
        let max_request_age = self.nonce_manager.max_request_age;
        self.nonce_manager = NonceManager::new(ttl).with_max_request_age(max_request_age);
        self
    }

    pub fn with_max_request_age(mut self, max_request_age: Duration) -> Self {
        self.nonce_manager = self.nonce_manager.with_max_request_age(max_request_age);
        self
    }

    /// Configure rate limiting for authentication attempts
    ///
    /// Rate limiting is applied per IP address extracted from the Via header.
    /// This helps prevent brute force authentication attacks.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_auth::{DigestAuthenticator, MemoryCredentialStore};
    /// use sip_ratelimit::{RateLimiter, RateLimitConfig};
    ///
    /// let store = MemoryCredentialStore::new();
    /// let config = RateLimitConfig::auth_preset(); // 10 attempts per 5 minutes
    /// let auth = DigestAuthenticator::new("example.com", store)
    ///     .with_rate_limiter(RateLimiter::new(config));
    /// ```
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    fn build_challenge(&self) -> Headers {
        let mut hdrs = Headers::new();
        let nonce = self.nonce_manager.generate();
        let mut value = String::new();
        let _ = write!(
            value,
            "Digest realm=\"{}\", nonce=\"{}\", algorithm={}, qop=\"{}\", opaque=\"{}\"",
            self.realm,
            nonce.value,
            self.algorithm.as_str(),
            self.qop.as_str(),
            self.opaque
        );

        let header_name = if self.proxy_auth {
            "Proxy-Authenticate"
        } else {
            "WWW-Authenticate"
        };

        hdrs.push(SmolStr::new(header_name), SmolStr::new(value));
        hdrs
    }

    fn compute_ha1(&self, username: &str, password: &str) -> String {
        let ha1_input = format!("{}:{}:{}", username, self.realm, password);
        Self::hash(&self.algorithm, ha1_input.as_bytes())
    }

    fn compute_ha2(&self, method: &Method, uri: &str, body: &[u8]) -> String {
        let ha2_input = match self.qop {
            Qop::Auth => format!("{}:{}", method.as_str(), uri),
            Qop::AuthInt => {
                let body_hash = Self::hash(&self.algorithm, body);
                format!("{}:{}:{}", method.as_str(), uri, body_hash)
            }
        };
        Self::hash(&self.algorithm, ha2_input.as_bytes())
    }

    fn hash(algorithm: &DigestAlgorithm, data: &[u8]) -> String {
        match algorithm {
            DigestAlgorithm::Md5 => format!("{:x}", md5::compute(data)),
            DigestAlgorithm::Sha256 => hex::encode(Sha256::digest(data)),
            DigestAlgorithm::Sha512 => hex::encode(Sha512::digest(data)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_response(
        &self,
        username: &str,
        password: &str,
        method: &Method,
        uri: &str,
        nonce: &str,
        nc: Option<&str>,
        cnonce: Option<&str>,
        qop: Option<Qop>,
        body: &[u8],
    ) -> String {
        let ha1 = self.compute_ha1(username, password);
        let ha2 = self.compute_ha2(method, uri, body);

        let final_input = if let (Some(qop), Some(nc), Some(cnonce)) = (qop, nc, cnonce) {
            format!(
                "{}:{}:{}:{}:{}:{}",
                ha1,
                nonce,
                nc,
                cnonce,
                qop.as_str(),
                ha2
            )
        } else {
            format!("{}:{}:{}", ha1, nonce, ha2)
        };

        Self::hash(&self.algorithm, final_input.as_bytes())
    }
}

impl<S: CredentialStore> Authenticator for DigestAuthenticator<S> {
    fn challenge(&self, request: &Request) -> Result<Response> {
        let mut headers = self.build_challenge();

        // RFC 3261: Copy required headers from request to response
        if let Some(via) = request.headers.get("Via") {
            headers.push(SmolStr::new("Via"), via.clone());
        }
        if let Some(from) = request.headers.get("From") {
            headers.push(SmolStr::new("From"), from.clone());
        }
        // RFC 3261 §8.2.6.2: UAS MUST add tag to To header if not present
        if let Some(to) = request.headers.get("To") {
            headers.push(SmolStr::new("To"), ensure_to_tag(to.as_str()));
        }
        if let Some(call_id) = request.headers.get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id.clone());
        }
        if let Some(cseq) = request.headers.get("CSeq") {
            headers.push(SmolStr::new("CSeq"), cseq.clone());
        }

        info!(realm = %self.realm, proxy = self.proxy_auth, "issuing digest challenge");
        Ok(Response::new(
            StatusLine::new(
                if self.proxy_auth { 407 } else { 401 },
                SmolStr::new(if self.proxy_auth {
                    "Proxy Authentication Required"
                } else {
                    "Unauthorized"
                }),
            ),
            headers,
            Bytes::new(),
        ))
    }

    fn verify(&self, request: &Request, headers: &Headers) -> Result<bool> {
        let params = match self.prepare_digest(request, headers)? {
            Some(p) => p,
            None => return Ok(false),
        };

        let creds = self
            .store
            .fetch(params.username.as_str(), params.realm.as_str())
            .ok_or_else(|| anyhow!("unknown user"))?;

        let response_calc = self.compute_response(
            params.username.as_str(),
            creds.password.as_str(),
            &request.start.method,
            params.uri.as_str(),
            params.nonce.as_str(),
            params.nc_raw.as_deref(),
            params.cnonce.as_deref(),
            params.qop,
            request.body.as_ref(),
        );

        Ok(constant_time_eq(response_calc.as_bytes(), params.response.as_bytes()))
    }

    fn credentials_for(&self, _method: &Method, _uri: &str) -> Option<Credentials> {
        None
    }
}

impl<S: AsyncCredentialStore> DigestAuthenticator<S> {
    /// Asynchronous verification using an async credential store.
    pub async fn verify_async(&self, request: &Request, headers: &Headers) -> Result<bool> {
        let params = match self.prepare_digest(request, headers)? {
            Some(p) => p,
            None => return Ok(false),
        };

        let creds = self
            .store
            .fetch(params.username.as_str(), params.realm.as_str())
            .await
            .ok_or_else(|| anyhow!("unknown user"))?;

        let response_calc = self.compute_response(
            params.username.as_str(),
            creds.password.as_str(),
            &request.start.method,
            params.uri.as_str(),
            params.nonce.as_str(),
            params.nc_raw.as_deref(),
            params.cnonce.as_deref(),
            params.qop,
            request.body.as_ref(),
        );

        Ok(constant_time_eq(response_calc.as_bytes(), params.response.as_bytes()))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Client-side authentication helper for generating Authorization headers.
pub struct DigestClient {
    pub username: SmolStr,
    pub password: SmolStr,
    pub nc: u32,
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

impl DigestClient {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: SmolStr::new(username),
            password: SmolStr::new(password),
            nc: 0,
        }
    }

    /// Generates Authorization header value from a 401/407 challenge.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_authorization(
        &mut self,
        method: &Method,
        uri: &str,
        realm: &str,
        nonce: &str,
        algorithm: DigestAlgorithm,
        qop: Option<Qop>,
        opaque: Option<&str>,
        body: &[u8],
    ) -> String {
        self.nc += 1;
        let nc_str = format!("{:08x}", self.nc);
        let cnonce: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        let ha1_input = format!("{}:{}:{}", self.username, realm, self.password);
        let ha1 = Self::hash(&algorithm, ha1_input.as_bytes());

        let ha2_input = match qop {
            Some(Qop::AuthInt) => {
                let body_hash = Self::hash(&algorithm, body);
                format!("{}:{}:{}", method.as_str(), uri, body_hash)
            }
            _ => format!("{}:{}", method.as_str(), uri),
        };
        let ha2 = Self::hash(&algorithm, ha2_input.as_bytes());

        let response = if let Some(qop) = qop {
            let final_input = format!(
                "{}:{}:{}:{}:{}:{}",
                ha1,
                nonce,
                nc_str,
                cnonce,
                qop.as_str(),
                ha2
            );
            Self::hash(&algorithm, final_input.as_bytes())
        } else {
            let final_input = format!("{}:{}:{}", ha1, nonce, ha2);
            Self::hash(&algorithm, final_input.as_bytes())
        };

        let mut auth = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm={}",
            self.username, realm, nonce, uri, response, algorithm.as_str()
        );

        if let Some(qop) = qop {
            auth.push_str(&format!(
                ", qop={}, nc={}, cnonce=\"{}\"",
                qop.as_str(),
                nc_str,
                cnonce
            ));
        }

        if let Some(opaque_val) = opaque {
            auth.push_str(&format!(", opaque=\"{}\"", opaque_val));
        }

        auth
    }

    fn hash(algorithm: &DigestAlgorithm, data: &[u8]) -> String {
        match algorithm {
            DigestAlgorithm::Md5 => format!("{:x}", md5::compute(data)),
            DigestAlgorithm::Sha256 => hex::encode(Sha256::digest(data)),
            DigestAlgorithm::Sha512 => hex::encode(Sha512::digest(data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, RequestLine, SipUri};

    #[test]
    fn digest_algorithm_from_str() {
        assert_eq!(DigestAlgorithm::parse("MD5"), Some(DigestAlgorithm::Md5));
        assert_eq!(
            DigestAlgorithm::parse("SHA-256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            DigestAlgorithm::parse("SHA-512"),
            Some(DigestAlgorithm::Sha512)
        );
        assert_eq!(
            DigestAlgorithm::parse("sha-256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(DigestAlgorithm::parse("INVALID"), None);
    }

    #[test]
    fn qop_from_str() {
        assert_eq!(Qop::parse("auth"), Some(Qop::Auth));
        assert_eq!(Qop::parse("auth-int"), Some(Qop::AuthInt));
        assert_eq!(Qop::parse("AUTH"), Some(Qop::Auth));
        assert_eq!(Qop::parse("invalid"), None);
    }

    #[test]
    fn nonce_expiry() {
        let nonce = Nonce::new(Duration::from_millis(10));
        assert!(nonce.is_valid());
        std::thread::sleep(Duration::from_millis(15));
        assert!(!nonce.is_valid());
    }

    #[test]
    fn nonce_manager_generate_and_verify() {
        let manager = NonceManager::new(Duration::from_secs(60));
        let nonce = manager.generate();
        assert!(manager.verify(&nonce.value));
        assert!(!manager.verify("invalid-nonce"));
    }

    #[test]
    fn nonce_manager_cleanup() {
        let manager = NonceManager::new(Duration::from_millis(10));
        let _nonce1 = manager.generate();
        let _nonce2 = manager.generate();
        assert_eq!(manager.count(), 2);

        std::thread::sleep(Duration::from_millis(15));
        manager.cleanup();
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn memory_store_fetch() {
        let mut store = MemoryCredentialStore::new();
        store.add(Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        });

        assert!(store.fetch("alice", "example.com").is_some());
        assert!(store.fetch("bob", "example.com").is_none());
        assert!(store.fetch("alice", "other.com").is_none());
    }

    #[test]
    fn digest_auth_challenge_returns_401() {
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store);

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            Headers::new(),
            Bytes::new(),
        );

        let response = auth.challenge(&request).expect("challenge");
        assert_eq!(response.start.code, 401);
        assert!(response.headers.get("WWW-Authenticate").is_some());
    }

    #[test]
    fn digest_auth_proxy_challenge_returns_407() {
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store).with_proxy_auth(true);

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            Headers::new(),
            Bytes::new(),
        );

        let response = auth.challenge(&request).expect("challenge");
        assert_eq!(response.start.code, 407);
        assert!(response.headers.get("Proxy-Authenticate").is_some());
    }

    #[test]
    fn digest_auth_verifies_md5() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_verifies_sha256() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Sha256);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Register;
        let uri = "sip:example.com";
        let nc = "00000001";
        let cnonce = "xyz";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-256, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_verifies_sha512() {
        let creds = Credentials {
            username: SmolStr::new("bob"),
            password: SmolStr::new("password123"),
            realm: SmolStr::new("test.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("test.com", store).with_algorithm(DigestAlgorithm::Sha512);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:alice@test.com";
        let nc = "00000001";
        let cnonce = "nonce123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-512, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_rejects_invalid_nonce() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"invalid\", uri=\"sip:bob@example.com\", response=\"abcd\""
            ),
        );

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_rejects_wrong_realm() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"alice\", realm=\"wrong.com\", nonce=\"{}\", uri=\"sip:bob@example.com\", response=\"abcd\"",
                nonce.value
            )),
        );

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_rejects_mismatched_uri() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let auth_uri = "sip:alice@example.com";
        let request_uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            auth_uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, auth_uri, response, cnonce, nc, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(request_uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_rejects_missing_qop() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            None,
            None,
            None,
            b"",
        );

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_client_generates_authorization() {
        let mut client = DigestClient::new("alice", "secret");
        let auth = client.generate_authorization(
            &Method::Register,
            "sip:example.com",
            "example.com",
            "testnonce123",
            DigestAlgorithm::Md5,
            Some(Qop::Auth),
            Some("opaque123"),
            b"",
        );

        assert!(auth.starts_with("Digest"));
        assert!(auth.contains("username=\"alice\""));
        assert!(auth.contains("realm=\"example.com\""));
        assert!(auth.contains("nonce=\"testnonce123\""));
        assert!(auth.contains("uri=\"sip:example.com\""));
        assert!(auth.contains("algorithm=MD5"));
        assert!(auth.contains("qop=auth"));
        assert!(auth.contains("nc=00000001"));
        assert!(auth.contains("cnonce="));
        assert!(auth.contains("opaque=\"opaque123\""));
    }

    #[test]
    fn digest_client_increments_nc() {
        let mut client = DigestClient::new("alice", "secret");

        let auth1 = client.generate_authorization(
            &Method::Register,
            "sip:example.com",
            "example.com",
            "nonce1",
            DigestAlgorithm::Md5,
            Some(Qop::Auth),
            None,
            b"",
        );
        assert!(auth1.contains("nc=00000001"));

        let auth2 = client.generate_authorization(
            &Method::Register,
            "sip:example.com",
            "example.com",
            "nonce1",
            DigestAlgorithm::Md5,
            Some(Qop::Auth),
            None,
            b"",
        );
        assert!(auth2.contains("nc=00000002"));
    }

    #[test]
    fn digest_client_server_roundtrip() {
        // Setup server
        let creds = Credentials {
            username: SmolStr::new("testuser"),
            password: SmolStr::new("testpass"),
            realm: SmolStr::new("sip.example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let server_auth = DigestAuthenticator::new("sip.example.com", store)
            .with_algorithm(DigestAlgorithm::Sha256);

        // Generate nonce from server
        let nonce = server_auth.nonce_manager.generate();

        // Client generates authorization
        let mut client = DigestClient::new("testuser", "testpass");
        let uri = "sip:bob@example.com";
        let auth_header = client.generate_authorization(
            &Method::Invite,
            uri,
            "sip.example.com",
            &nonce.value,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            Some(&server_auth.opaque),
            b"",
        );

        // Create request with authorization
        let mut headers = Headers::new();
        headers.push(SmolStr::new("Authorization"), SmolStr::new(auth_header));

        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        // Server verifies
        assert!(server_auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_with_auth_int_qop() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5)
            .with_qop(Qop::AuthInt);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let body = b"v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\n";
        let nc = "00000001";
        let cnonce = "xyz";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::AuthInt),
            body,
        );

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth-int, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::from_static(body),
        );

        assert!(auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_accepts_retransmission() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        // First request with nc=00000001 should succeed
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers.clone(),
            Bytes::new(),
        );

        assert!(auth.verify(&request, &request.headers).unwrap());

        // Retransmission with same nc=00000001 should be accepted (legitimate retransmit over UDP)
        let retransmit = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(
            auth.verify(&retransmit, &retransmit.headers).unwrap(),
            "Retransmission with same nc should be accepted"
        );
    }

    #[test]
    fn digest_auth_rejects_replay_with_decreasing_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";

        // First request with nc=00000002
        let nc2 = "00000002";
        let cnonce = "abc123";

        let response2 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc2),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers2 = Headers::new();
        headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response2, cnonce, nc2, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::new(),
        );

        assert!(
            auth.verify(&request2, &request2.headers).unwrap(),
            "Request with nc=2 should succeed"
        );

        // Replay attack with nc=00000001 (going backwards) should be rejected
        let nc1 = "00000001";
        let response1 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc1),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers1 = Headers::new();
        headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response1, cnonce, nc1, auth.opaque
            )),
        );

        let replay_request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::new(),
        );

        assert!(
            !auth
                .verify(&replay_request, &replay_request.headers)
                .unwrap(),
            "Replay attack with decreasing nc should be rejected"
        );
    }

    #[test]
    fn digest_auth_rejects_different_request_same_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri1 = "sip:bob@example.com";
        let uri2 = "sip:charlie@example.com"; // Different URI
        let nc = "00000001";
        let cnonce = "abc123";

        // First request to uri1
        let response1 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri1,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers1 = Headers::new();
        headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri1, response1, cnonce, nc, auth.opaque
            )),
        );

        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri1).unwrap()),
            headers1,
            Bytes::new(),
        );

        assert!(
            auth.verify(&request1, &request1.headers).unwrap(),
            "First request should succeed"
        );

        // Second request to uri2 with same nc (replay attack with different request)
        let response2 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri2,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers2 = Headers::new();
        headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri2, response2, cnonce, nc, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method, SipUri::parse(uri2).unwrap()),
            headers2,
            Bytes::new(),
        );

        assert!(
            !auth.verify(&request2, &request2.headers).unwrap(),
            "Different request with same nc should be rejected (request hash mismatch)"
        );
    }

    #[test]
    fn digest_auth_rejects_different_body_same_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";
        let body1 = b"SDP offer 1";
        let body2 = b"SDP offer 2 - different";

        // First request with body1
        let response1 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            body1,
        );

        let mut headers1 = Headers::new();
        headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response1, cnonce, nc, auth.opaque
            )),
        );

        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::from_static(body1),
        );

        assert!(
            auth.verify(&request1, &request1.headers).unwrap(),
            "First request should succeed"
        );

        // Second request with body2 and same nc (replay attack with different body)
        let response2 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            body2,
        );

        let mut headers2 = Headers::new();
        headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response2, cnonce, nc, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::from_static(body2),
        );

        assert!(
            !auth.verify(&request2, &request2.headers).unwrap(),
            "Different body with same nc should be rejected (request hash mismatch)"
        );
    }

    #[test]
    fn digest_auth_rejects_same_length_different_body_same_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";
        let body1 = b"SDP body A"; // length 10
        let body2 = b"SDP body B"; // same length, different content

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            body1,
        );

        let auth_header = SmolStr::new(format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
            creds.username, creds.realm, nonce.value, uri, response, cnonce, nc, auth.opaque
        ));

        // First request with body1
        let mut headers1 = Headers::new();
        headers1.push(SmolStr::new("Authorization"), auth_header.clone());
        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::from_static(body1),
        );
        assert!(
            auth.verify(&request1, &request1.headers).unwrap(),
            "First request should succeed"
        );

        // Same nc but different body with identical length should be rejected
        let mut headers2 = Headers::new();
        headers2.push(SmolStr::new("Authorization"), auth_header);
        let request2 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::from_static(body2),
        );
        assert!(
            !auth.verify(&request2, &request2.headers).unwrap(),
            "Different body of same length with same nc should be rejected"
        );
    }

    #[test]
    fn digest_auth_rejects_missing_opaque() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        // Authorization without opaque parameter
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_auth_rejects_wrong_opaque() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        // Authorization with wrong opaque parameter
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"wrong-opaque\"",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn reject_oversized_username() {
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store);

        let long_username = "a".repeat(300);
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"example.com\", nonce=\"abc\", uri=\"sip:test\", response=\"xyz\", algorithm=SHA-256, cnonce=\"abc\", nc=00000001, qop=auth, opaque=\"test\"",
                long_username
            )),
        );

        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:test").unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(auth.verify(&request, &request.headers).is_err());
    }

    #[test]
    fn reject_large_nc_value() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds]);
        let auth = DigestAuthenticator::new("example.com", store);
        let nonce = auth.nonce_manager.generate();

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"{}\", uri=\"sip:test\", response=\"xyz\", nc=F0000000, cnonce=\"abc\", qop=auth, opaque=\"{}\"",
                nonce.value, auth.opaque
            )),
        );

        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:test").unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn reject_oversized_body() {
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store);

        let large_body = vec![0u8; 11 * 1024 * 1024];
        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:test").unwrap()),
            Headers::new(),
            Bytes::from(large_body),
        );

        assert!(auth.verify(&request, &request.headers).is_err());
    }

    #[test]
    fn reject_suspicious_nc_jump() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: SmolStr::new("secret"),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store);
        let nonce = auth.nonce_manager.generate();

        let method = Method::Invite;
        let uri = "sip:test";

        let response1 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some("00000001"),
            Some("abc"),
            Some(Qop::Auth),
            b"",
        );

        let mut headers1 = Headers::new();
        headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-256, cnonce=\"abc\", nc=00000001, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response1, auth.opaque
            )),
        );

        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::new(),
        );

        assert!(auth.verify(&request1, &request1.headers).unwrap());

        let response2 = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            &method,
            uri,
            &nonce.value,
            Some("00005000"),
            Some("def"),
            Some(Qop::Auth),
            b"",
        );

        let mut headers2 = Headers::new();
        headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-256, cnonce=\"def\", nc=00005000, qop=auth, opaque=\"{}\"",
                creds.username, creds.realm, nonce.value, uri, response2, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::new(),
        );

        assert!(!auth.verify(&request2, &request2.headers).unwrap());
    }

    #[test]
    fn reject_control_characters_in_username() {
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store);

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(
                "Digest username=\"alice\x00evil\", realm=\"example.com\", nonce=\"abc\", uri=\"sip:test\", response=\"xyz\", algorithm=SHA-256, cnonce=\"abc\", nc=00000001, qop=auth, opaque=\"test\"",
            ),
        );

        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:test").unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(auth.verify(&request, &request.headers).is_err());
    }

    #[test]
    fn nonce_manager_enforces_max_limit() {
        let manager = NonceManager::new(Duration::from_secs(60)).with_max_nonces(100);

        // Generate 100 nonces (at limit)
        for _ in 0..100 {
            manager.generate();
        }
        assert_eq!(manager.count(), 100);

        // Generate one more - should trigger cleanup or removal of oldest
        manager.generate();
        assert!(manager.count() <= 100, "Should not exceed max nonce count");
    }

    #[test]
    fn nonce_manager_removes_oldest_when_full() {
        let manager = NonceManager::new(Duration::from_secs(60)).with_max_nonces(10);

        // Generate 10 nonces
        let mut nonce_values = Vec::new();
        for _ in 0..10 {
            let nonce = manager.generate();
            nonce_values.push(nonce.value.clone());
            std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure different timestamps
        }

        // Generate one more - should remove oldest
        let new_nonce = manager.generate();
        assert_eq!(manager.count(), 10);

        // First nonce should be removed (oldest)
        assert!(!manager.verify(&nonce_values[0]));
        // Last nonces should still be valid
        assert!(manager.verify(&nonce_values[9]));
        assert!(manager.verify(&new_nonce.value));
    }
}
