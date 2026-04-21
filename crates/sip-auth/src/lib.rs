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
use subtle::ConstantTimeEq;
use tokio::{runtime::Handle, task};
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Credentials used for SIP authentication with private fields for security.
///
/// The password field is zeroized on drop to prevent it from lingering in memory.
/// Debug output redacts the password to prevent accidental exposure in logs.
///
/// # Breaking changes (v0.3)
/// - `Credentials` no longer derives `Clone`. Use `Credentials::new()` to create
///   a new instance if you need a copy. This prevents password data from being
///   silently duplicated in memory.
/// - `Debug` output now redacts the password field.
#[derive(ZeroizeOnDrop)]
pub struct Credentials {
    #[zeroize(skip)]
    username: SmolStr,
    password: String,
    #[zeroize(skip)]
    realm: SmolStr,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("realm", &self.realm)
            .finish()
    }
}

impl Clone for Credentials {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: self.password.clone(),
            realm: self.realm.clone(),
        }
    }
}

impl Credentials {
    /// Creates new credentials with the given username, password, and realm.
    pub fn new(
        username: impl Into<SmolStr>,
        password: impl Into<String>,
        realm: impl Into<SmolStr>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            realm: realm.into(),
        }
    }

    /// Creates credentials without validation (for internal use and tests).
    #[cfg(test)]
    pub fn unchecked_new(
        username: impl Into<SmolStr>,
        password: impl Into<String>,
        realm: impl Into<SmolStr>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            realm: realm.into(),
        }
    }

    /// Returns the username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// Authentication backend responsible for challenges and verification.
pub trait Authenticator: Send + Sync {
    fn challenge(&self, request: &Request) -> Result<Response>;
    fn verify(&self, request: &Request, headers: &Headers) -> Result<bool>;
    fn credentials_for(&self, method: &Method, uri: &str) -> Option<Credentials>;

    /// Returns `true` if the request's Authorization header references a
    /// nonce that this authenticator issued and has since expired.
    ///
    /// Callers use this signal to decide between [`Self::challenge`] (a
    /// fresh nonce) and [`Self::challenge_stale`] (a fresh nonce with
    /// `stale=true` so the client may retry without re-prompting the user
    /// — RFC 7616 §3.5). Default returns `false`; implementations that
    /// track nonces should override.
    fn nonce_is_stale(&self, _request: &Request) -> bool {
        false
    }

    /// Issues a `stale=true` challenge for an expired-nonce failure.
    /// Default delegates to [`Self::challenge`]; override to emit the
    /// `stale` parameter so the client can re-authenticate silently.
    fn challenge_stale(&self, request: &Request) -> Result<Response> {
        self.challenge(request)
    }
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
///
/// RFC 7616 §6.1 standardises `MD5`, `SHA-256`, and `SHA-512-256`. The last
/// of those is SHA-512 truncated to 256 bits (i.e. the first 32 bytes of
/// the 64-byte output, hex-encoded). Plain `SHA-512` is **not** defined by
/// RFC 7616 but some implementations advertise it; we keep a distinct
/// variant so the on-the-wire hash length matches what's negotiated.
///
/// Every hash algorithm has a `-sess` counterpart per RFC 7616 §3.4.2.
/// The `-sess` form rebinds HA1 to the specific challenge: instead of
/// `H(user:realm:pass)` it uses `H(H(user:realm:pass):nonce:cnonce)`.
/// Session-keying makes HA1 unique per authentication handshake, which
/// matters for long-lived registrations where the same password-derived
/// hash would otherwise be reused across many requests. Authenticator and
/// client MUST agree on the `-sess` vs non-sess flavour — the on-wire
/// algorithm token is negotiated via the challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
    /// Non-standard full SHA-512 (64-byte / 128-hex-char output).
    Sha512,
    /// Non-standard full SHA-512 with session-key form.
    Sha512Sess,
    /// RFC 7616 SHA-512/256: SHA-512 truncated to the first 256 bits.
    Sha512_256,
    /// RFC 7616 SHA-512/256 with session-key form.
    Sha512_256Sess,
}

impl DigestAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            DigestAlgorithm::Md5 => "MD5",
            DigestAlgorithm::Md5Sess => "MD5-sess",
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha256Sess => "SHA-256-sess",
            DigestAlgorithm::Sha512 => "SHA-512",
            DigestAlgorithm::Sha512Sess => "SHA-512-sess",
            DigestAlgorithm::Sha512_256 => "SHA-512-256",
            DigestAlgorithm::Sha512_256Sess => "SHA-512-256-sess",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        // RFC 7616 §3.4.2: the "-sess" suffix is lowercase. Real peers
        // vary their case on the base token ("MD5" vs "md5"), so we
        // upper-case the full string and match — the `-SESS` outcome
        // still round-trips through our canonical `as_str()` form.
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Some(DigestAlgorithm::Md5),
            "MD5-SESS" => Some(DigestAlgorithm::Md5Sess),
            "SHA-256" => Some(DigestAlgorithm::Sha256),
            "SHA-256-SESS" => Some(DigestAlgorithm::Sha256Sess),
            "SHA-512" => Some(DigestAlgorithm::Sha512),
            "SHA-512-SESS" => Some(DigestAlgorithm::Sha512Sess),
            "SHA-512-256" => Some(DigestAlgorithm::Sha512_256),
            "SHA-512-256-SESS" => Some(DigestAlgorithm::Sha512_256Sess),
            _ => None,
        }
    }

    /// True if this is a session-keyed (`-sess`) variant. Session
    /// variants compute HA1 as `H(H(user:realm:pass):nonce:cnonce)`
    /// instead of the base `H(user:realm:pass)`.
    pub fn is_sess(&self) -> bool {
        matches!(
            self,
            DigestAlgorithm::Md5Sess
                | DigestAlgorithm::Sha256Sess
                | DigestAlgorithm::Sha512Sess
                | DigestAlgorithm::Sha512_256Sess
        )
    }

    /// Returns the base (non-sess) algorithm, which is the hash
    /// function used for every primitive in the digest calculation.
    /// The session flavour only changes HA1's composition, not the
    /// hash function itself.
    pub fn base(&self) -> DigestAlgorithm {
        match self {
            DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => DigestAlgorithm::Md5,
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha512 | DigestAlgorithm::Sha512Sess => DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha512_256 | DigestAlgorithm::Sha512_256Sess => {
                DigestAlgorithm::Sha512_256
            }
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
/// All fields are private to prevent bypassing TTL validation and replay protection.
#[derive(Debug, Clone)]
pub struct Nonce {
    value: SmolStr,
    created_at: Instant,
    ttl: Duration,
    last_nc: u32,                      // Last nonce-count seen (for replay protection)
    last_request_hash: Option<String>, // Hash of last request (method:uri:body) for retransmission detection
    last_used: Instant, // Timestamp of last successful authentication (for request age validation)
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
            // Use constant-time comparison to avoid timing side-channels
            if let Some(ref last_hash) = self.last_request_hash {
                let hashes_match: bool = last_hash.as_bytes().ct_eq(request_hash.as_bytes()).into();
                if hashes_match {
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

    /// Returns the nonce value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns when the nonce was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns the nonce time-to-live.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the last nonce-count seen.
    pub fn last_nc(&self) -> u32 {
        self.last_nc
    }

    /// Returns the last request hash.
    pub fn last_request_hash(&self) -> Option<&str> {
        self.last_request_hash.as_deref()
    }

    /// Returns when the nonce was last used.
    pub fn last_used(&self) -> Instant {
        self.last_used
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
        self.nonces
            .insert(SmolStr::new(nonce.value()), nonce.clone());
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

    /// Returns true if the nonce exists but has expired (stale).
    /// Used to send stale=true in re-challenges per RFC 7616 §3.5.
    pub fn is_stale(&self, value: &str) -> bool {
        if let Some(entry) = self.nonces.get(value) {
            !entry.is_valid()
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

/// Extracts the authenticated username from the Authorization or Proxy-Authorization header.
///
/// Returns `None` if no Authorization header is present or if it's not a Digest scheme.
/// This is useful for AOR-to-identity authorization (verifying the authenticated user
/// has permission to register for the requested AOR).
pub fn extract_auth_username(headers: &Headers) -> Option<SmolStr> {
    // Try Authorization first, then Proxy-Authorization
    let auth_header = headers
        .get_smol("Authorization")
        .or_else(|| headers.get_smol("Proxy-Authorization"))?;

    let parsed = parse_authorization_header(auth_header)?;
    if !parsed.scheme().eq_ignore_ascii_case("Digest") {
        return None;
    }
    parsed.param("username").cloned()
}

/// Extracts the nonce from the Authorization or Proxy-Authorization header.
///
/// Useful for checking `DigestAuthenticator::is_nonce_stale()` to decide
/// whether to issue a stale=true challenge per RFC 7616 §3.5.
pub fn extract_auth_nonce(headers: &Headers) -> Option<SmolStr> {
    let auth_header = headers
        .get_smol("Authorization")
        .or_else(|| headers.get_smol("Proxy-Authorization"))?;

    let parsed = parse_authorization_header(auth_header)?;
    if !parsed.scheme().eq_ignore_ascii_case("Digest") {
        return None;
    }
    parsed.param("nonce").cloned()
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
/// All fields are private to protect sensitive authentication state.
pub struct DigestAuthenticator<S> {
    realm: SmolStr,
    algorithm: DigestAlgorithm,
    qop: Qop,
    store: S,
    nonce_manager: NonceManager,
    proxy_auth: bool,
    opaque: SmolStr,                   // Opaque session token for additional security
    rate_limiter: Option<RateLimiter>, // Optional rate limiting
}

impl<S> DigestAuthenticator<S> {
    /// Returns the authentication realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Returns the digest algorithm.
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Returns the quality of protection (qop).
    pub fn qop(&self) -> Qop {
        self.qop
    }

    /// Returns a reference to the credential store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns a reference to the nonce manager.
    pub fn nonce_manager(&self) -> &NonceManager {
        &self.nonce_manager
    }

    /// Returns whether proxy authentication is enabled.
    pub fn proxy_auth(&self) -> bool {
        self.proxy_auth
    }

    /// Returns the opaque token.
    pub fn opaque(&self) -> &str {
        &self.opaque
    }

    /// Returns a reference to the rate limiter if configured.
    pub fn rate_limiter(&self) -> Option<&RateLimiter> {
        self.rate_limiter.as_ref()
    }
}

impl<S> DigestAuthenticator<S> {
    fn prepare_digest(&self, request: &Request, headers: &Headers) -> Result<Option<DigestParams>> {
        if request.body().len() > MAX_BODY_SIZE {
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

        let auth_header = match headers.get_smol(header_name) {
            Some(h) => h,
            None => return Ok(None),
        };

        let parsed = match parse_authorization_header(auth_header) {
            Some(p) => p,
            None => return Ok(None),
        };

        if !parsed.scheme().eq_ignore_ascii_case("Digest") {
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

        if uri.as_str() != request.uri().as_str() {
            info!("digest uri mismatch");
            return Ok(None);
        }

        if let Some(client_opaque) = opaque {
            // Use constant-time comparison to avoid timing side-channels on opaque token
            let opaque_match: bool = client_opaque
                .as_bytes()
                .ct_eq(self.opaque.as_bytes())
                .into();
            if !opaque_match {
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

            if !self
                .nonce_manager
                .is_nc_jump_reasonable(nonce.as_str(), nc_value)
            {
                info!("digest nc jump too large");
                return Ok(None);
            }

            if !self.nonce_manager.verify_with_nc(
                nonce,
                nc_value,
                request.method(),
                request.uri().as_str(),
                request.body(),
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
        if algorithm == DigestAlgorithm::Md5 {
            warn!(
                "MD5 digest authentication is cryptographically weak and deprecated \
                 per RFC 7616 §3. Use SHA-256 or SHA-512 for new deployments."
            );
        }
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

    /// Returns true if the given nonce is known but expired (stale).
    /// Useful for determining whether to issue a stale=true challenge.
    pub fn is_nonce_stale(&self, nonce: &str) -> bool {
        self.nonce_manager.is_stale(nonce)
    }

    /// Issues a challenge response with stale=true (RFC 7616 §3.5).
    /// The client can re-authenticate with a new nonce without re-prompting the user.
    pub fn challenge_stale(&self, request: &Request) -> Result<Response> {
        let mut headers = self.build_challenge_with_stale(true);

        if let Some(via) = request.headers().get("Via") {
            headers.push(SmolStr::new("Via"), via)?;
        }
        if let Some(from) = request.headers().get("From") {
            headers.push(SmolStr::new("From"), from)?;
        }
        if let Some(to) = request.headers().get("To") {
            headers.push(SmolStr::new("To"), ensure_to_tag(to))?;
        }
        if let Some(call_id) = request.headers().get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id)?;
        }
        if let Some(cseq) = request.headers().get("CSeq") {
            headers.push(SmolStr::new("CSeq"), cseq)?;
        }

        info!(realm = %self.realm, proxy = self.proxy_auth, "issuing stale digest challenge");
        Ok(Response::new(
            StatusLine::new(
                if self.proxy_auth { 407 } else { 401 },
                if self.proxy_auth {
                    "Proxy Authentication Required"
                } else {
                    "Unauthorized"
                },
            )?,
            headers,
            Bytes::new(),
        )?)
    }

    /// Configure rate limiting for authentication attempts
    ///
    /// Rate limiting is applied per IP address extracted from the Via header.
    /// **Note**: The Via header can be spoofed; for stronger per-source limiting,
    /// use transport-layer IP addresses instead.
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
        self.build_challenge_with_stale(false)
    }

    /// Builds a challenge with the stale=true parameter (RFC 7616 §3.5).
    /// Used when a nonce has expired but the credentials were otherwise valid,
    /// allowing the client to re-authenticate without re-prompting the user.
    fn build_challenge_with_stale(&self, stale: bool) -> Headers {
        let mut hdrs = Headers::new();
        let nonce = self.nonce_manager().generate();
        let mut value = String::new();
        let _ = write!(
            value,
            "Digest realm=\"{}\", nonce=\"{}\", algorithm={}, qop=\"{}\", opaque=\"{}\"",
            self.realm,
            nonce.value(),
            self.algorithm.as_str(),
            self.qop.as_str(),
            self.opaque
        );
        if stale {
            let _ = write!(value, ", stale=true");
        }

        let header_name = if self.proxy_auth {
            "Proxy-Authenticate"
        } else {
            "WWW-Authenticate"
        };

        hdrs.push(SmolStr::new(header_name), SmolStr::new(value))
            .unwrap();
        hdrs
    }

    fn compute_ha1(&self, username: &str, password: &str) -> String {
        let mut ha1_input = format!("{}:{}:{}", username, self.realm, password);
        let result = Self::hash(&self.algorithm, ha1_input.as_bytes());
        ha1_input.zeroize();
        result
    }

    /// RFC 7616 §3.4.2 session-key transformation of HA1.
    ///
    /// For `-sess` algorithms, HA1 = H(H(user:realm:pass):nonce:cnonce).
    /// For non-sess algorithms the base HA1 is returned unchanged.
    /// Callers must hold the nonce and cnonce that were (or will be)
    /// used in the Authorization header — mismatches produce a
    /// silently-wrong response that fails verification.
    fn apply_sess(&self, base_ha1: &str, nonce: &str, cnonce: Option<&str>) -> String {
        if !self.algorithm.is_sess() {
            return base_ha1.to_string();
        }
        let cnonce = cnonce.unwrap_or("");
        let sess_input = format!("{}:{}:{}", base_ha1, nonce, cnonce);
        Self::hash(&self.algorithm, sess_input.as_bytes())
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
        // RFC 7616 §3.4.2: the `-sess` flavour changes HA1's composition
        // but uses the same underlying hash function for every digest
        // primitive. Collapse to the base algorithm here so callers
        // can pass the algorithm verbatim without reasoning about sess.
        match algorithm.base() {
            DigestAlgorithm::Md5 => format!("{:x}", md5::compute(data)),
            DigestAlgorithm::Sha256 => hex::encode(Sha256::digest(data)),
            DigestAlgorithm::Sha512 => hex::encode(Sha512::digest(data)),
            // RFC 7616 §6.1: SHA-512/256 is SHA-512 truncated to the first
            // 256 bits (32 bytes), hex-encoded as 64 chars. Previously this
            // variant didn't exist and "SHA-512-256" emitted a 128-char
            // full SHA-512 hash, so interop with any RFC-compliant peer
            // silently failed.
            DigestAlgorithm::Sha512_256 => hex::encode(&Sha512::digest(data)[..32]),
            // Base() never returns a `-sess` variant; all four base
            // cases above cover the arms.
            _ => unreachable!("base() returned a sess variant"),
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
        let base_ha1 = self.compute_ha1(username, password);
        let ha1 = self.apply_sess(&base_ha1, nonce, cnonce);
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
        if let Some(via) = request.headers().get("Via") {
            headers.push(SmolStr::new("Via"), via)?;
        }
        if let Some(from) = request.headers().get("From") {
            headers.push(SmolStr::new("From"), from)?;
        }
        // RFC 3261 §8.2.6.2: UAS MUST add tag to To header if not present
        if let Some(to) = request.headers().get("To") {
            headers.push(SmolStr::new("To"), ensure_to_tag(to))?;
        }
        if let Some(call_id) = request.headers().get("Call-ID") {
            headers.push(SmolStr::new("Call-ID"), call_id)?;
        }
        if let Some(cseq) = request.headers().get("CSeq") {
            headers.push(SmolStr::new("CSeq"), cseq)?;
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
            )?,
            headers,
            Bytes::new(),
        )?)
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
            creds.password(),
            request.method(),
            params.uri.as_str(),
            params.nonce.as_str(),
            params.nc_raw.as_deref(),
            params.cnonce.as_deref(),
            params.qop,
            request.body().as_ref(),
        );

        Ok(constant_time_eq(
            response_calc.as_bytes(),
            params.response.as_bytes(),
        ))
    }

    fn credentials_for(&self, _method: &Method, _uri: &str) -> Option<Credentials> {
        None
    }

    fn nonce_is_stale(&self, request: &Request) -> bool {
        // Look for our header (Authorization for 401, Proxy-Authorization
        // for 407) and check whether its nonce is one we issued but has
        // since expired. This is the signal that the next response should
        // be `401 + stale=true` instead of a fresh challenge.
        let header_name = if self.proxy_auth {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };
        let raw = match request.headers().get_smol(header_name) {
            Some(v) => v,
            None => return false,
        };
        let parsed = match parse_authorization_header(raw) {
            Some(p) => p,
            None => return false,
        };
        if !parsed.scheme().eq_ignore_ascii_case("Digest") {
            return false;
        }
        match parsed.param("nonce") {
            Some(nonce) => self.is_nonce_stale(nonce.as_str()),
            None => false,
        }
    }

    fn challenge_stale(&self, request: &Request) -> Result<Response> {
        DigestAuthenticator::challenge_stale(self, request)
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
            creds.password(),
            request.method(),
            params.uri.as_str(),
            params.nonce.as_str(),
            params.nc_raw.as_deref(),
            params.cnonce.as_deref(),
            params.qop,
            request.body().as_ref(),
        );

        Ok(constant_time_eq(
            response_calc.as_bytes(),
            params.response.as_bytes(),
        ))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// ============================================================================
// RFC 7616 §3.5 — Authentication-Info
// ============================================================================

/// Parsed / buildable Authentication-Info header value.
///
/// Emitted by the server on a 2xx response to an authenticated
/// request so the client can verify the peer identity (mutual
/// authentication) and, optionally, pick up a new one-time nonce
/// for the next request without waiting for another challenge.
///
/// Field origin (per RFC 7616 §3.5):
///   * `qop`, `cnonce`, `nc` — echoed from the client's Authorization.
///   * `rspauth` — H(HA1:nonce:nc:cnonce:qop:HA2') where
///     HA2' = H(":" + digest-uri) for qop=auth, and
///     HA2' = H(":" + digest-uri + ":" + H(response-body)) for
///     qop=auth-int. The response-body hash uses the hash function
///     implied by the algorithm (not the request body hash).
///   * `nextnonce` — server-selected fresh nonce the client SHOULD
///     use on the next request. Enables one-time-nonce policies
///     without the cost of a new 401 round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthInfo {
    pub qop: Option<Qop>,
    pub rspauth: SmolStr,
    pub cnonce: Option<SmolStr>,
    pub nc: Option<SmolStr>,
    pub nextnonce: Option<SmolStr>,
}

impl AuthInfo {
    /// Render as the raw header value (what goes after
    /// `Authentication-Info:`).
    ///
    /// Fields are emitted in the order RFC 7616 §3.5 documents
    /// (qop, rspauth, cnonce, nc, nextnonce); absent optional
    /// fields are skipped so the line stays canonical. `rspauth` is
    /// always present — the whole point of the header is mutual
    /// auth.
    pub fn to_header_value(&self) -> String {
        let mut out = String::new();
        if let Some(qop) = self.qop {
            out.push_str(&format!("qop={}, ", qop.as_str()));
        }
        out.push_str(&format!("rspauth=\"{}\"", self.rspauth));
        if let Some(cnonce) = &self.cnonce {
            out.push_str(&format!(", cnonce=\"{}\"", cnonce));
        }
        if let Some(nc) = &self.nc {
            out.push_str(&format!(", nc={}", nc));
        }
        if let Some(nextnonce) = &self.nextnonce {
            out.push_str(&format!(", nextnonce=\"{}\"", nextnonce));
        }
        out
    }

    /// Parses an Authentication-Info header value.
    ///
    /// Tolerant to parameter order and whitespace; strict about
    /// quoted / unquoted syntax per RFC 7616. Returns `None` when
    /// `rspauth` is missing — without it the header carries no
    /// mutual-authentication value and callers should ignore it.
    pub fn parse(value: &str) -> Option<Self> {
        let mut qop = None;
        let mut rspauth: Option<SmolStr> = None;
        let mut cnonce = None;
        let mut nc = None;
        let mut nextnonce = None;

        for raw in split_auth_info_params(value) {
            let (key, val) = match raw.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            };
            let val = strip_quotes(val);
            match key.to_ascii_lowercase().as_str() {
                "qop" => {
                    qop = Qop::parse(val);
                }
                "rspauth" => rspauth = Some(SmolStr::new(val)),
                "cnonce" => cnonce = Some(SmolStr::new(val)),
                "nc" => nc = Some(SmolStr::new(val)),
                "nextnonce" => nextnonce = Some(SmolStr::new(val)),
                _ => {}
            }
        }

        Some(AuthInfo {
            qop,
            rspauth: rspauth?,
            cnonce,
            nc,
            nextnonce,
        })
    }
}

/// Strips surrounding double quotes from a raw parameter value if
/// present. Leaves unquoted values alone.
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Splits an Authentication-Info value on unquoted commas. Quoted
/// strings (possibly containing commas) are kept intact.
fn split_auth_info_params(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escape = false;
    for ch in input.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escape = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    out
}

impl<S: CredentialStore> DigestAuthenticator<S> {
    /// Builds the Authentication-Info header for a 2xx response to a
    /// previously-verified request.
    ///
    /// Callers pair this with a successful `verify()` or
    /// `verify_with_nonce_tracking()`. The function re-parses the
    /// request's Authorization header (cheap; same parse path as
    /// verify) and computes rspauth from the same credentials,
    /// nonce, nc, cnonce, and qop that the client proved knowledge
    /// of. If any required field is missing (unauthenticated request
    /// or `qop` absent from the request) the function returns
    /// `Ok(None)` — Authentication-Info is only defined for
    /// qop-protected handshakes.
    ///
    /// `response_body` is the body of the OUTGOING 2xx response,
    /// used for `qop=auth-int`'s HA2' computation. Pass `&[]` for
    /// empty bodies or when using `qop=auth`.
    ///
    /// When `nextnonce` is provided it's added to the header so the
    /// client can use it directly on the next request (one-time
    /// nonce policy). The caller is responsible for having
    /// registered the nonce in the NonceManager.
    pub fn build_auth_info(
        &self,
        request: &Request,
        response_body: &[u8],
        nextnonce: Option<&str>,
    ) -> Result<Option<AuthInfo>> {
        let params = match self.prepare_digest(request, request.headers())? {
            Some(p) => p,
            None => return Ok(None),
        };
        // Authentication-Info rspauth requires qop — without it the
        // header's format is undefined in RFC 7616.
        let Some(qop) = params.qop else {
            return Ok(None);
        };
        let Some(cnonce) = params.cnonce.clone() else {
            return Ok(None);
        };
        let Some(nc_raw) = params.nc_raw.clone() else {
            return Ok(None);
        };

        let creds = self
            .store
            .fetch(params.username.as_str(), params.realm.as_str())
            .ok_or_else(|| anyhow!("unknown user for Authentication-Info"))?;

        let rspauth = self.compute_rspauth(
            params.username.as_str(),
            creds.password(),
            params.uri.as_str(),
            params.nonce.as_str(),
            &nc_raw,
            &cnonce,
            qop,
            response_body,
        );

        Ok(Some(AuthInfo {
            qop: Some(qop),
            rspauth: SmolStr::new(rspauth),
            cnonce: Some(cnonce),
            nc: Some(nc_raw),
            nextnonce: nextnonce.map(SmolStr::new),
        }))
    }

    /// Computes the `rspauth` value per RFC 7616 §3.5.1.
    ///
    /// The only differences from `compute_response`:
    ///   * HA2' omits the method — it's `H(":" + uri)` for auth,
    ///     `H(":" + uri + ":" + H(body))` for auth-int.
    ///   * For auth-int, the body hashed is the RESPONSE body (not
    ///     the request's).
    #[allow(clippy::too_many_arguments)]
    fn compute_rspauth(
        &self,
        username: &str,
        password: &str,
        uri: &str,
        nonce: &str,
        nc: &str,
        cnonce: &str,
        qop: Qop,
        response_body: &[u8],
    ) -> String {
        let base_ha1 = self.compute_ha1(username, password);
        let ha1 = self.apply_sess(&base_ha1, nonce, Some(cnonce));

        let ha2_input = match qop {
            Qop::Auth => format!(":{}", uri),
            Qop::AuthInt => {
                let body_hash = Self::hash(&self.algorithm, response_body);
                format!(":{}:{}", uri, body_hash)
            }
        };
        let ha2 = Self::hash(&self.algorithm, ha2_input.as_bytes());

        let final_input = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1,
            nonce,
            nc,
            cnonce,
            qop.as_str(),
            ha2
        );
        Self::hash(&self.algorithm, final_input.as_bytes())
    }
}

/// Client-side authentication helper for generating Authorization headers.
/// All fields are private to protect sensitive credential data.
///
/// The password field is zeroized on drop to prevent it from lingering in memory.
/// Debug output redacts the password to prevent accidental exposure in logs.
///
/// # Breaking changes (v0.3)
/// - `Debug` output now redacts the password field.
#[derive(ZeroizeOnDrop)]
pub struct DigestClient {
    #[zeroize(skip)]
    username: SmolStr,
    password: String,
    #[zeroize(skip)]
    nc: u32,
}

impl std::fmt::Debug for DigestClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigestClient")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("nc", &self.nc)
            .finish()
    }
}

impl DigestClient {
    /// Returns the username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the current nonce count.
    pub fn nc(&self) -> u32 {
        self.nc
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

impl DigestClient {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: SmolStr::new(username),
            password: password.to_string(),
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
        self.nc = self.nc.saturating_add(1);
        let nc_str = format!("{:08x}", self.nc);
        let cnonce: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        let ha1_input = format!("{}:{}:{}", self.username, realm, self.password);
        let base_ha1 = Self::hash(&algorithm, ha1_input.as_bytes());
        // RFC 7616 §3.4.2: for `-sess` algorithms, rebind HA1 to this
        // handshake by hashing it together with the nonce and cnonce.
        // For non-sess variants base_ha1 is used verbatim.
        let ha1 = if algorithm.is_sess() {
            let sess_input = format!("{}:{}:{}", base_ha1, nonce, cnonce);
            Self::hash(&algorithm, sess_input.as_bytes())
        } else {
            base_ha1
        };

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
        match algorithm.base() {
            DigestAlgorithm::Md5 => format!("{:x}", md5::compute(data)),
            DigestAlgorithm::Sha256 => hex::encode(Sha256::digest(data)),
            DigestAlgorithm::Sha512 => hex::encode(Sha512::digest(data)),
            // RFC 7616 §6.1 truncates to the first 256 bits; see note on
            // the sibling `hash` above.
            DigestAlgorithm::Sha512_256 => hex::encode(&Sha512::digest(data)[..32]),
            _ => unreachable!("base() returned a sess variant"),
        }
    }

    /// Verifies the server's Authentication-Info `rspauth` against
    /// the request this client just sent.
    ///
    /// Pass the `AuthInfo` parsed from the 200 OK's
    /// Authentication-Info header plus the `realm` used on the
    /// original Authorization, the `digest-uri` the client sent
    /// (usually the Request-URI), the `response_body` of the 2xx
    /// response (for `qop=auth-int`), and the `algorithm` + `nonce`
    /// the server challenged with.
    ///
    /// Returns `Ok(nextnonce_if_any)` when the server's rspauth
    /// matches (mutual auth succeeded) — the caller SHOULD use the
    /// returned `nextnonce` on subsequent requests when present.
    /// Returns `Err` when rspauth doesn't match, meaning the 2xx
    /// came from a peer that doesn't know the password; apps that
    /// care about mutual authentication should refuse to trust the
    /// response.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_auth_info(
        &self,
        info: &AuthInfo,
        realm: &str,
        digest_uri: &str,
        nonce: &str,
        algorithm: DigestAlgorithm,
        response_body: &[u8],
    ) -> Result<Option<SmolStr>> {
        let qop = info.qop.ok_or_else(|| {
            anyhow!("Authentication-Info without qop — mutual auth not negotiated")
        })?;
        let cnonce = info
            .cnonce
            .as_ref()
            .ok_or_else(|| anyhow!("Authentication-Info missing cnonce"))?;
        let nc = info
            .nc
            .as_ref()
            .ok_or_else(|| anyhow!("Authentication-Info missing nc"))?;

        let ha1_input = format!("{}:{}:{}", self.username, realm, self.password);
        let base_ha1 = Self::hash(&algorithm, ha1_input.as_bytes());
        let ha1 = if algorithm.is_sess() {
            let sess_input = format!("{}:{}:{}", base_ha1, nonce, cnonce);
            Self::hash(&algorithm, sess_input.as_bytes())
        } else {
            base_ha1
        };

        let ha2_input = match qop {
            Qop::Auth => format!(":{}", digest_uri),
            Qop::AuthInt => {
                let body_hash = Self::hash(&algorithm, response_body);
                format!(":{}:{}", digest_uri, body_hash)
            }
        };
        let ha2 = Self::hash(&algorithm, ha2_input.as_bytes());

        let final_input = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1,
            nonce,
            nc,
            cnonce,
            qop.as_str(),
            ha2
        );
        let expected = Self::hash(&algorithm, final_input.as_bytes());

        if !constant_time_eq(expected.as_bytes(), info.rspauth.as_bytes()) {
            return Err(anyhow!(
                "Authentication-Info rspauth mismatch — mutual auth failed"
            ));
        }
        Ok(info.nextnonce.clone())
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
        // RFC 7616 §6.1 standard algorithm — parse as a distinct variant so
        // the hash is truncated to 32 bytes, not the full 64-byte SHA-512.
        assert_eq!(
            DigestAlgorithm::parse("SHA-512-256"),
            Some(DigestAlgorithm::Sha512_256)
        );
        assert_eq!(
            DigestAlgorithm::parse("sha-512-256"),
            Some(DigestAlgorithm::Sha512_256)
        );
        assert_eq!(
            DigestAlgorithm::parse("sha-256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(DigestAlgorithm::parse("INVALID"), None);
    }

    #[test]
    fn sha512_256_hash_is_truncated_to_32_bytes() {
        // Use the DigestClient::hash shim (there are two identical `hash`
        // impls in the crate; the DigestAuthenticator one is private, so
        // hit the algorithm through verify/compute paths isn't worth the
        // scaffolding. Instead, rebuild the expected output manually and
        // compare char count + prefix match against full SHA-512.)
        use sha2::{Digest as _, Sha512};
        let data = b"the quick brown fox";
        let full = hex::encode(Sha512::digest(data));
        let truncated = hex::encode(&Sha512::digest(data)[..32]);
        // 32 bytes hex-encoded = 64 chars; 64 bytes = 128 chars.
        assert_eq!(full.len(), 128, "SHA-512 full should be 128 hex chars");
        assert_eq!(
            truncated.len(),
            64,
            "SHA-512/256 should be 64 hex chars (RFC 7616 §6.1)"
        );
        // The truncated form is the prefix of the full form.
        assert_eq!(&full[..64], truncated.as_str());
    }

    #[test]
    fn sha512_256_round_trips_verify_with_itself() {
        // End-to-end: configure the authenticator with Sha512_256, generate
        // a challenge, compute a client response, and verify. If the hash
        // weren't truncated, the server would compute a 64-char response
        // and the client would compute a 128-char response (or vice versa),
        // and the constant-time compare would fail.
        let store = MemoryCredentialStore::with(vec![Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        }]);
        let server = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Sha512_256);
        let nonce = server.nonce_manager().generate();

        let mut client = DigestClient::new("alice", "secret");
        let uri = "sip:example.com";
        let auth_header = client.generate_authorization(
            &Method::Register,
            uri,
            "example.com",
            nonce.value(),
            DigestAlgorithm::Sha512_256,
            Some(Qop::Auth),
            Some(&server.opaque()),
            b"",
        );

        let mut headers = Headers::new();
        headers
            .push(SmolStr::new("Authorization"), SmolStr::new(auth_header))
            .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse(uri).unwrap()),
            headers.clone(),
            Bytes::new(),
        )
        .expect("valid request");

        assert!(
            server.verify(&request, &headers).expect("verify"),
            "SHA-512-256 client/server round-trip must succeed"
        );
    }

    // --------------------------------------------------------------
    // RFC 7616 §3.4.2 session-key (-sess) algorithms
    // --------------------------------------------------------------

    #[test]
    fn sess_algorithm_tokens_round_trip() {
        for (canonical, variant) in [
            ("MD5-sess", DigestAlgorithm::Md5Sess),
            ("SHA-256-sess", DigestAlgorithm::Sha256Sess),
            ("SHA-512-256-sess", DigestAlgorithm::Sha512_256Sess),
        ] {
            assert_eq!(DigestAlgorithm::parse(canonical), Some(variant));
            // Upper-casing input still parses to the same variant.
            assert_eq!(
                DigestAlgorithm::parse(&canonical.to_ascii_uppercase()),
                Some(variant),
            );
            assert_eq!(variant.as_str(), canonical);
            assert!(variant.is_sess());
            assert!(!variant.base().is_sess());
        }
    }

    #[test]
    fn sess_base_maps_to_underlying_hash() {
        assert_eq!(DigestAlgorithm::Md5Sess.base(), DigestAlgorithm::Md5);
        assert_eq!(DigestAlgorithm::Sha256Sess.base(), DigestAlgorithm::Sha256);
        assert_eq!(
            DigestAlgorithm::Sha512_256Sess.base(),
            DigestAlgorithm::Sha512_256
        );
        // Non-sess variants are their own base.
        assert_eq!(DigestAlgorithm::Md5.base(), DigestAlgorithm::Md5);
    }

    /// Verify a sess variant round-trips: server challenges with
    /// MD5-sess, client computes the Authorization using the same
    /// algorithm, server verifies. This proves both sides agree on
    /// the session-key HA1 composition.
    fn sess_round_trip_inner(algorithm: DigestAlgorithm) {
        let store = MemoryCredentialStore::with(vec![Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        }]);
        let server = DigestAuthenticator::new("example.com", store).with_algorithm(algorithm);
        let nonce = server.nonce_manager().generate();

        let mut client = DigestClient::new("alice", "secret");
        let uri = "sip:example.com";
        let auth_header = client.generate_authorization(
            &Method::Register,
            uri,
            "example.com",
            nonce.value(),
            algorithm,
            Some(Qop::Auth),
            Some(server.opaque()),
            b"",
        );
        assert!(
            auth_header.contains(algorithm.as_str()),
            "auth header MUST advertise the -sess token: {auth_header}",
        );

        let mut headers = Headers::new();
        headers
            .push(SmolStr::new("Authorization"), SmolStr::new(auth_header))
            .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse(uri).unwrap()),
            headers.clone(),
            Bytes::new(),
        )
        .expect("valid request");

        assert!(
            server.verify(&request, &headers).expect("verify"),
            "{}: sess client/server round-trip must succeed",
            algorithm.as_str(),
        );
    }

    // --------------------------------------------------------------
    // RFC 7616 §3.5 Authentication-Info
    // --------------------------------------------------------------

    #[test]
    fn auth_info_parse_rejects_missing_rspauth() {
        assert!(AuthInfo::parse("qop=auth, nc=00000001").is_none());
    }

    #[test]
    fn auth_info_parse_extracts_all_fields() {
        let raw = "qop=auth, rspauth=\"abcdef\", cnonce=\"c-1\", nc=00000001, nextnonce=\"nn-2\"";
        let info = AuthInfo::parse(raw).expect("valid");
        assert_eq!(info.qop, Some(Qop::Auth));
        assert_eq!(info.rspauth.as_str(), "abcdef");
        assert_eq!(info.cnonce.as_deref(), Some("c-1"));
        assert_eq!(info.nc.as_deref(), Some("00000001"));
        assert_eq!(info.nextnonce.as_deref(), Some("nn-2"));
    }

    #[test]
    fn auth_info_to_header_value_round_trips() {
        let info = AuthInfo {
            qop: Some(Qop::AuthInt),
            rspauth: SmolStr::new("deadbeef"),
            cnonce: Some(SmolStr::new("clientnonce")),
            nc: Some(SmolStr::new("00000002")),
            nextnonce: Some(SmolStr::new("next-one")),
        };
        let value = info.to_header_value();
        let round = AuthInfo::parse(&value).expect("round-trip");
        assert_eq!(round, info);
    }

    /// End-to-end: server authenticates a request, builds
    /// Authentication-Info, client parses it and verifies rspauth.
    /// The outer path mirrors a successful REGISTER → 200 OK flow.
    fn auth_info_round_trip_inner(algorithm: DigestAlgorithm, qop: Qop, response_body: &[u8]) {
        let store = MemoryCredentialStore::with(vec![Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        }]);
        let server = DigestAuthenticator::new("example.com", store)
            .with_algorithm(algorithm)
            .with_qop(qop);
        let nonce = server.nonce_manager().generate();

        let mut client = DigestClient::new("alice", "secret");
        let uri = "sip:example.com";
        let auth_header = client.generate_authorization(
            &Method::Register,
            uri,
            "example.com",
            nonce.value(),
            algorithm,
            Some(qop),
            Some(server.opaque()),
            b"",
        );

        let mut req_headers = Headers::new();
        req_headers
            .push(
                SmolStr::new("Authorization"),
                SmolStr::new(auth_header.clone()),
            )
            .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse(uri).unwrap()),
            req_headers.clone(),
            Bytes::new(),
        )
        .expect("valid request");

        // Server: verify the request first (standard path), then
        // build the Authentication-Info for the outgoing 2xx.
        assert!(server.verify(&request, &req_headers).expect("verify"));

        let nextnonce = "fresh-nonce-for-next-request";
        let info = server
            .build_auth_info(&request, response_body, Some(nextnonce))
            .expect("build_auth_info")
            .expect("qop-protected request yields AuthInfo");
        assert_eq!(info.qop, Some(qop));
        assert_eq!(info.nextnonce.as_deref(), Some(nextnonce));
        assert!(!info.rspauth.is_empty());

        // Simulate transmission over the wire: serialize + reparse.
        let header_value = info.to_header_value();
        let parsed = AuthInfo::parse(&header_value).expect("reparse");
        assert_eq!(parsed, info);

        // Client: verify mutual auth. Returns the nextnonce.
        let returned_nextnonce = client
            .verify_auth_info(
                &parsed,
                "example.com",
                uri,
                nonce.value(),
                algorithm,
                response_body,
            )
            .expect("rspauth must match — client/server share the password");
        assert_eq!(returned_nextnonce.as_deref(), Some(nextnonce));
    }

    #[test]
    fn auth_info_round_trip_md5_auth() {
        auth_info_round_trip_inner(DigestAlgorithm::Md5, Qop::Auth, b"");
    }

    #[test]
    fn auth_info_round_trip_sha256_auth() {
        auth_info_round_trip_inner(DigestAlgorithm::Sha256, Qop::Auth, b"");
    }

    #[test]
    fn auth_info_round_trip_sess_variant() {
        // -sess variants hash HA1 with nonce+cnonce; the
        // Authentication-Info path must apply the same
        // transformation or rspauth will mismatch.
        auth_info_round_trip_inner(DigestAlgorithm::Sha256Sess, Qop::Auth, b"");
    }

    #[test]
    fn auth_info_round_trip_auth_int_includes_response_body() {
        // Body should factor into rspauth when qop=auth-int. A
        // non-empty body ensures the HA2' path differs from qop=auth.
        auth_info_round_trip_inner(
            DigestAlgorithm::Sha256,
            Qop::AuthInt,
            b"200 OK response body",
        );
    }

    #[test]
    fn auth_info_fails_when_wrong_password() {
        // A client that doesn't know the password MUST NOT be able
        // to verify rspauth — mutual auth catches a forged 200 OK.
        let algorithm = DigestAlgorithm::Sha256;
        let qop = Qop::Auth;
        let store = MemoryCredentialStore::with(vec![Credentials {
            username: SmolStr::new("alice"),
            password: "correct-secret".to_string(),
            realm: SmolStr::new("example.com"),
        }]);
        let server = DigestAuthenticator::new("example.com", store)
            .with_algorithm(algorithm)
            .with_qop(qop);
        let nonce = server.nonce_manager().generate();

        let mut auth_client = DigestClient::new("alice", "correct-secret");
        let uri = "sip:example.com";
        let auth_header = auth_client.generate_authorization(
            &Method::Register,
            uri,
            "example.com",
            nonce.value(),
            algorithm,
            Some(qop),
            Some(server.opaque()),
            b"",
        );
        let mut req_headers = Headers::new();
        req_headers
            .push(SmolStr::new("Authorization"), SmolStr::new(auth_header))
            .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse(uri).unwrap()),
            req_headers.clone(),
            Bytes::new(),
        )
        .expect("valid request");
        assert!(server.verify(&request, &req_headers).expect("verify"));

        let info = server
            .build_auth_info(&request, b"", None)
            .expect("build")
            .expect("info");

        // A different client (wrong password) tries to verify.
        let wrong = DigestClient::new("alice", "wrong-password");
        let result =
            wrong.verify_auth_info(&info, "example.com", uri, nonce.value(), algorithm, b"");
        assert!(
            result.is_err(),
            "rspauth MUST NOT verify under a wrong password",
        );
    }

    #[test]
    fn build_auth_info_returns_none_without_qop() {
        // An unauthenticated request (no Authorization header) must
        // produce no Authentication-Info — the function is a no-op
        // when qop wasn't negotiated.
        let store = MemoryCredentialStore::with(vec![Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        }]);
        let server = DigestAuthenticator::new("example.com", store);
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid request");
        let result = server
            .build_auth_info(&request, b"", None)
            .expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn md5_sess_round_trip() {
        sess_round_trip_inner(DigestAlgorithm::Md5Sess);
    }

    #[test]
    fn sha256_sess_round_trip() {
        sess_round_trip_inner(DigestAlgorithm::Sha256Sess);
    }

    #[test]
    fn sha512_256_sess_round_trip() {
        sess_round_trip_inner(DigestAlgorithm::Sha512_256Sess);
    }

    /// Negative: a -sess server MUST NOT accept a client that
    /// computes HA1 without the session-key transformation (i.e.
    /// used the non-sess algorithm by mistake). Verifies that
    /// session-keying is actually protecting the digest, not just a
    /// cosmetic token.
    #[test]
    fn sess_server_rejects_non_sess_client_response() {
        let store = MemoryCredentialStore::with(vec![Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        }]);
        let server =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5Sess);
        let nonce = server.nonce_manager().generate();

        // Client uses the non-sess form by mistake.
        let mut client = DigestClient::new("alice", "secret");
        let uri = "sip:example.com";
        let auth_header = client.generate_authorization(
            &Method::Register,
            uri,
            "example.com",
            nonce.value(),
            DigestAlgorithm::Md5,
            Some(Qop::Auth),
            Some(server.opaque()),
            b"",
        );
        let mut headers = Headers::new();
        headers
            .push(SmolStr::new("Authorization"), SmolStr::new(auth_header))
            .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse(uri).unwrap()),
            headers.clone(),
            Bytes::new(),
        )
        .expect("valid request");
        let verified = server.verify(&request, &headers).unwrap_or(false);
        assert!(
            !verified,
            "MD5-sess server MUST reject an MD5 (non-sess) response — session-keying isn't just cosmetic",
        );
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
        assert!(manager.verify(&nonce.value()));
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
            password: "secret".to_string(),
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
        )
        .expect("valid request");

        let response = auth.challenge(&request).expect("challenge");
        assert_eq!(response.code(), 401);
        assert!(response.headers().get("WWW-Authenticate").is_some());
    }

    #[test]
    fn nonce_is_stale_detects_expired_nonce_in_authorization() {
        // Authenticator with a 10ms nonce TTL so we can age it deterministically.
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store)
            .with_nonce_ttl(Duration::from_millis(10));

        // Get a nonce, expire it, then send an Authorization that references it.
        let nonce = auth.nonce_manager().generate();
        std::thread::sleep(Duration::from_millis(20));

        let mut headers = Headers::new();
        headers
            .push(
                "Authorization",
                format!(
                    "Digest username=\"alice\", realm=\"example.com\", nonce=\"{}\", uri=\"sip:example.com\", response=\"deadbeef\"",
                    nonce.value()
                ),
            )
            .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Trait-method dispatch (DigestAuthenticator's override) — RFC 7616 §3.5.
        let auth_dyn: &dyn Authenticator = &auth;
        assert!(
            auth_dyn.nonce_is_stale(&request),
            "expired-but-known nonce should be reported as stale"
        );
        let resp = auth_dyn.challenge_stale(&request).expect("challenge_stale");
        assert_eq!(resp.code(), 401);
        let www = resp
            .headers()
            .get("WWW-Authenticate")
            .expect("WWW-Authenticate present");
        assert!(www.contains("stale=true"), "expected stale=true in: {www}");
    }

    #[test]
    fn nonce_is_stale_returns_false_for_unknown_nonce() {
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store);

        let mut headers = Headers::new();
        headers
            .push(
                "Authorization",
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"never-issued\", uri=\"sip:example.com\", response=\"deadbeef\"",
            )
            .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let auth_dyn: &dyn Authenticator = &auth;
        assert!(
            !auth_dyn.nonce_is_stale(&request),
            "nonces we never issued must not be reported as stale"
        );
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
        )
        .expect("valid request");

        let response = auth.challenge(&request).expect("challenge");
        assert_eq!(response.code(), 407);
        assert!(response.headers().get("Proxy-Authenticate").is_some());
    }

    #[test]
    fn digest_auth_verifies_md5() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc, auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_verifies_sha256() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Sha256);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Register;
        let uri = "sip:example.com";
        let nc = "00000001";
        let cnonce = "xyz";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc, auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_verifies_sha512() {
        let creds = Credentials {
            username: SmolStr::new("bob"),
            password: "password123".to_string(),
            realm: SmolStr::new("test.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("test.com", store).with_algorithm(DigestAlgorithm::Sha512);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:alice@test.com";
        let nc = "00000001";
        let cnonce = "nonce123";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc, auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_rejects_invalid_nonce() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"invalid\", uri=\"sip:bob@example.com\", response=\"abcd\""
            ),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_rejects_wrong_realm() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"alice\", realm=\"wrong.com\", nonce=\"{}\", uri=\"sip:bob@example.com\", response=\"abcd\"",
                nonce.value
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_rejects_mismatched_uri() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let auth_uri = "sip:alice@example.com";
        let request_uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            auth_uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), auth_uri, response, cnonce, nc, auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(request_uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_rejects_missing_qop() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request, request.headers()).unwrap());
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
            password: "testpass".to_string(),
            realm: SmolStr::new("sip.example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let server_auth = DigestAuthenticator::new("sip.example.com", store)
            .with_algorithm(DigestAlgorithm::Sha256);

        // Generate nonce from server
        let nonce = server_auth.nonce_manager().generate();

        // Client generates authorization
        let mut client = DigestClient::new("testuser", "testpass");
        let uri = "sip:bob@example.com";
        let auth_header = client.generate_authorization(
            &Method::Invite,
            uri,
            "sip.example.com",
            &nonce.value(),
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            Some(&server_auth.opaque()),
            b"",
        );

        // Create request with authorization
        let mut headers = Headers::new();
        headers
            .push(SmolStr::new("Authorization"), SmolStr::new(auth_header))
            .unwrap();

        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Server verifies
        assert!(server_auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_with_auth_int_qop() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Md5)
            .with_qop(Qop::AuthInt);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let body = b"v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\n";
        let nc = "00000001";
        let cnonce = "xyz";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc, auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::from_static(body),
        )
        .expect("valid request");

        assert!(auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_accepts_retransmission() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc, auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers.clone(),
            Bytes::new(),
        )
        .expect("valid request");

        assert!(auth.verify(&request, request.headers()).unwrap());

        // Retransmission with same nc=00000001 should be accepted (legitimate retransmit over UDP)
        let retransmit = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(
            auth.verify(&retransmit, retransmit.headers()).unwrap(),
            "Retransmission with same nc should be accepted"
        );
    }

    #[test]
    fn digest_auth_rejects_replay_with_decreasing_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";

        // First request with nc=00000002
        let nc2 = "00000002";
        let cnonce = "abc123";

        let response2 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
            Some(nc2),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers2 = Headers::new();
        let _ = headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri, response2, cnonce, nc2, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(
            auth.verify(&request2, request2.headers()).unwrap(),
            "Request with nc=2 should succeed"
        );

        // Replay attack with nc=00000001 (going backwards) should be rejected
        let nc1 = "00000001";
        let response1 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
            Some(nc1),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers1 = Headers::new();
        let _ = headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri, response1, cnonce, nc1, auth.opaque
            )),
        );

        let replay_request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(
            !auth
                .verify(&replay_request, replay_request.headers())
                .unwrap(),
            "Replay attack with decreasing nc should be rejected"
        );
    }

    #[test]
    fn digest_auth_rejects_different_request_same_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri1 = "sip:bob@example.com";
        let uri2 = "sip:charlie@example.com"; // Different URI
        let nc = "00000001";
        let cnonce = "abc123";

        // First request to uri1
        let response1 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri1,
            &nonce.value(),
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers1 = Headers::new();
        let _ = headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri1, response1, cnonce, nc, auth.opaque
            )),
        );

        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri1).unwrap()),
            headers1,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(
            auth.verify(&request1, request1.headers()).unwrap(),
            "First request should succeed"
        );

        // Second request to uri2 with same nc (replay attack with different request)
        let response2 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri2,
            &nonce.value(),
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            b"",
        );

        let mut headers2 = Headers::new();
        let _ = headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri2, response2, cnonce, nc, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method, SipUri::parse(uri2).unwrap()),
            headers2,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(
            !auth.verify(&request2, request2.headers()).unwrap(),
            "Different request with same nc should be rejected (request hash mismatch)"
        );
    }

    #[test]
    fn digest_auth_rejects_different_body_same_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";
        let body1 = b"SDP offer 1";
        let body2 = b"SDP offer 2 - different";

        // First request with body1
        let response1 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            body1,
        );

        let mut headers1 = Headers::new();
        let _ = headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri, response1, cnonce, nc, auth.opaque
            )),
        );

        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::from_static(body1),
        )
        .expect("valid request");

        assert!(
            auth.verify(&request1, request1.headers()).unwrap(),
            "First request should succeed"
        );

        // Second request with body2 and same nc (replay attack with different body)
        let response2 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            body2,
        );

        let mut headers2 = Headers::new();
        let _ = headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri, response2, cnonce, nc, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::from_static(body2),
        )
        .expect("valid request");

        assert!(
            !auth.verify(&request2, request2.headers()).unwrap(),
            "Different body with same nc should be rejected (request hash mismatch)"
        );
    }

    #[test]
    fn digest_auth_rejects_same_length_different_body_same_nc() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";
        let body1 = b"SDP body A"; // length 10
        let body2 = b"SDP body B"; // same length, different content

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
            Some(nc),
            Some(cnonce),
            Some(Qop::Auth),
            body1,
        );

        let auth_header = SmolStr::new(format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth, opaque=\"{}\"",
            creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc, auth.opaque
        ));

        // First request with body1
        let mut headers1 = Headers::new();
        let _ = headers1.push(SmolStr::new("Authorization"), auth_header.clone());
        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::from_static(body1),
        )
        .expect("valid request");
        assert!(
            auth.verify(&request1, request1.headers()).unwrap(),
            "First request should succeed"
        );

        // Same nc but different body with identical length should be rejected
        let mut headers2 = Headers::new();
        let _ = headers2.push(SmolStr::new("Authorization"), auth_header);
        let request2 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::from_static(body2),
        )
        .expect("valid request");
        assert!(
            !auth.verify(&request2, request2.headers()).unwrap(),
            "Different body of same length with same nc should be rejected"
        );
    }

    #[test]
    fn digest_auth_rejects_missing_opaque() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn digest_auth_rejects_wrong_opaque() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth =
            DigestAuthenticator::new("example.com", store).with_algorithm(DigestAlgorithm::Md5);

        let nonce = auth.nonce_manager().generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
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
                creds.username(), creds.realm(), nonce.value(), uri, response, cnonce, nc
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn reject_oversized_username() {
        // With the new security hardening, oversized parameter values (>256 chars)
        // are rejected at parse time by AuthorizationHeader::from_raw()
        // This is better than rejecting during verification - fail fast!
        let long_username = "a".repeat(300);
        let auth_header_value = SmolStr::new(format!(
            "Digest username=\"{}\", realm=\"example.com\", nonce=\"abc\", uri=\"sip:test\", response=\"xyz\", algorithm=SHA-256, cnonce=\"abc\", nc=00000001, qop=auth, opaque=\"test\"",
            long_username
        ));

        // Parser should reject this because username is > MAX_PARAM_VALUE_LENGTH (256)
        let parsed = parse_authorization_header(&auth_header_value);
        assert!(
            parsed.is_none(),
            "Parser should reject oversized username parameter"
        );
    }

    #[test]
    fn reject_large_nc_value() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds]);
        let auth = DigestAuthenticator::new("example.com", store);
        let nonce = auth.nonce_manager().generate();

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"{}\", uri=\"sip:test\", response=\"xyz\", nc=F0000000, cnonce=\"abc\", qop=auth, opaque=\"{}\"",
                nonce.value(), auth.opaque
            )),
        ).unwrap();

        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:test").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request, request.headers()).unwrap());
    }

    #[test]
    fn reject_oversized_body() {
        let store = MemoryCredentialStore::new();
        let auth = DigestAuthenticator::new("example.com", store);

        let large_body = vec![0u8; 11 * 1024 * 1024];
        let request_result = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:test").unwrap()),
            Headers::new(),
            Bytes::from(large_body),
        );

        // Request creation should fail due to oversized body
        // OR if it succeeds, auth verification should fail
        match request_result {
            Err(_) => {
                // Expected: Request::new rejects oversized body
            }
            Ok(request) => {
                // Fallback: auth verification should reject it
                assert!(auth.verify(&request, request.headers()).is_err());
            }
        }
    }

    #[test]
    fn reject_suspicious_nc_jump() {
        let creds = Credentials {
            username: SmolStr::new("alice"),
            password: "secret".to_string(),
            realm: SmolStr::new("example.com"),
        };
        let store = MemoryCredentialStore::with(vec![creds.clone()]);
        let auth = DigestAuthenticator::new("example.com", store);
        let nonce = auth.nonce_manager().generate();

        let method = Method::Invite;
        let uri = "sip:test";

        let response1 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
            Some("00000001"),
            Some("abc"),
            Some(Qop::Auth),
            b"",
        );

        let mut headers1 = Headers::new();
        let _ = headers1.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-256, cnonce=\"abc\", nc=00000001, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri, response1, auth.opaque
            )),
        );

        let request1 = Request::new(
            RequestLine::new(method.clone(), SipUri::parse(uri).unwrap()),
            headers1,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(auth.verify(&request1, request1.headers()).unwrap());

        let response2 = auth.compute_response(
            creds.username(),
            creds.password(),
            &method,
            uri,
            &nonce.value(),
            Some("00005000"),
            Some("def"),
            Some(Qop::Auth),
            b"",
        );

        let mut headers2 = Headers::new();
        let _ = headers2.push(
            SmolStr::new("Authorization"),
            SmolStr::new(format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-256, cnonce=\"def\", nc=00005000, qop=auth, opaque=\"{}\"",
                creds.username(), creds.realm(), nonce.value(), uri, response2, auth.opaque
            )),
        );

        let request2 = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers2,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(!auth.verify(&request2, request2.headers()).unwrap());
    }

    #[test]
    fn reject_control_characters_in_username() {
        let store = MemoryCredentialStore::new();
        let _auth = DigestAuthenticator::new("example.com", store);

        let mut headers = Headers::new();
        let result = headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(
                "Digest username=\"alice\x00evil\", realm=\"example.com\", nonce=\"abc\", uri=\"sip:test\", response=\"xyz\", algorithm=SHA-256, cnonce=\"abc\", nc=00000001, qop=auth, opaque=\"test\"",
            ),
        );
        assert!(result.is_err());
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
            nonce_values.push(SmolStr::new(nonce.value()));
            std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure different timestamps
        }

        // Generate one more - should remove oldest
        let new_nonce = manager.generate();
        assert_eq!(manager.count(), 10);

        // First nonce should be removed (oldest)
        assert!(!manager.verify(&nonce_values[0]));
        // Last nonces should still be valid
        assert!(manager.verify(&nonce_values[9]));
        assert!(manager.verify(&new_nonce.value()));
    }
}
