use anyhow::{anyhow, Result};
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sip_auth::Authenticator;
use sip_core::{Headers, Request, Response, StatusLine};
use sip_parse::{header, parse_to_header};
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

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
}

impl LocationStore for MemoryLocationStore {
    fn upsert(&self, binding: Binding) -> Result<()> {
        let expires_at = Instant::now() + binding.expires;
        let aor_key = binding.aor.clone();

        let mut list = self
            .inner
            .entry(aor_key)
            .or_insert_with(Vec::new);

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
        if let Some(mut entry) = self.inner.get_mut(&SmolStr::new(aor.to_owned())) {
            entry.retain(|b| b.contact.as_str() != contact);
        }
        Ok(())
    }

    fn remove_all(&self, aor: &str) -> Result<()> {
        self.inner.remove(&SmolStr::new(aor.to_owned()));
        Ok(())
    }

    fn lookup(&self, aor: &str) -> Result<Vec<Binding>> {
        let aor_key = SmolStr::new(aor.to_owned());
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

/// Trait describing registrar behaviour for inbound REGISTER requests.
pub trait Registrar: Send + Sync {
    fn handle_register(&self, request: &Request) -> Result<Response>;
}

/// Basic registrar that stores contacts in a provided store and optionally enforces authentication.
pub struct BasicRegistrar<S: LocationStore, A: Authenticator> {
    store: S,
    authenticator: Option<A>,
    default_expires: Duration,
    min_expires: Duration,
    max_expires: Duration,
}

impl<S: LocationStore, A: Authenticator> BasicRegistrar<S, A> {
    pub fn new(store: S, authenticator: Option<A>) -> Self {
        Self {
            store,
            authenticator,
            default_expires: Duration::from_secs(3600),
            min_expires: Duration::from_secs(60),
            max_expires: Duration::from_secs(86400),
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

    fn parse_expires(&self, request: &Request, contact_value: &str) -> Duration {
        // Check Contact parameter first
        let contact_expires = contact_value
            .split(';')
            .find_map(|p| {
                let trimmed = p.trim();
                if trimmed.starts_with("expires=") {
                    trimmed[8..].parse::<u64>().ok()
                } else {
                    None
                }
            });

        // Fall back to Expires header
        let header_expires = request
            .headers
            .get("Expires")
            .and_then(|v| v.parse::<u64>().ok());

        let seconds = contact_expires
            .or(header_expires)
            .unwrap_or(self.default_expires.as_secs());

        if seconds == 0 {
            Duration::from_secs(0)
        } else {
            // Clamp between min and max
            let clamped = seconds.max(self.min_expires.as_secs()).min(self.max_expires.as_secs());
            Duration::from_secs(clamped)
        }
    }

    fn parse_q_value(&self, contact_value: &str) -> f32 {
        contact_value
            .split(';')
            .find_map(|p| {
                let trimmed = p.trim();
                if trimmed.starts_with("q=") {
                    trimmed[2..].parse::<f32>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(1.0)
            .clamp(0.0, 1.0)
    }

    fn extract_contact_uri(&self, contact_header: &str) -> SmolStr {
        let trimmed = contact_header.trim();

        // Handle <uri> format
        if let Some(start) = trimmed.find('<') {
            if let Some(end) = trimmed[start + 1..].find('>') {
                return SmolStr::new(trimmed[start + 1..start + 1 + end].to_owned());
            }
        }

        // Handle uri without brackets (stop at first semicolon)
        if let Some(pos) = trimmed.find(';') {
            SmolStr::new(trimmed[..pos].trim().to_owned())
        } else {
            SmolStr::new(trimmed.to_owned())
        }
    }
}

impl<S: LocationStore, A: Authenticator> Registrar for BasicRegistrar<S, A> {
    fn handle_register(&self, request: &Request) -> Result<Response> {
        // Authenticate if authenticator is configured
        if let Some(auth) = &self.authenticator {
            if !auth.verify(request, &request.headers)? {
                return auth.challenge(request);
            }
        }

        // Extract AOR from To header
        let to_uri = header(&request.headers, "To").ok_or_else(|| anyhow!("missing To"))?;
        let to_parsed = parse_to_header(to_uri).ok_or_else(|| anyhow!("invalid To"))?;
        let aor = to_parsed.inner().uri().as_str().to_owned();

        // Extract Call-ID and CSeq
        let call_id = header(&request.headers, "Call-ID")
            .cloned()
            .unwrap_or_else(|| SmolStr::new(""));

        let cseq = header(&request.headers, "CSeq")
            .and_then(|v| {
                v.split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u32>().ok())
            })
            .unwrap_or(0);

        // Get all Contact headers
        let contacts = contact_headers(&request.headers);
        if contacts.is_empty() {
            warn!("REGISTER missing Contact header");
            return Err(anyhow!("REGISTER missing Contact"));
        }

        // Check for wildcard Contact (*)
        if contacts.len() == 1 && contacts[0].trim() == "*" {
            // Remove all bindings for this AOR
            self.store.remove_all(&aor)?;
            info!(aor = %aor, "REGISTER removed all bindings (wildcard)");

            let mut headers = Headers::new();

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

            headers.push(SmolStr::new("Contact"), SmolStr::new("*"));
            headers.push(SmolStr::new("Date"), SmolStr::new(Utc::now().to_rfc2822()));
            headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

            return Ok(Response::new(
                StatusLine::new(200, SmolStr::new("OK")),
                headers,
                Bytes::new(),
            ));
        }

        // Process each contact
        let mut processed_contacts = Vec::new();

        for contact in &contacts {
            let expires = self.parse_expires(request, contact.as_str());
            let q_value = self.parse_q_value(contact.as_str());
            let contact_uri = self.extract_contact_uri(contact.as_str());

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

            // Build response contact with expires parameter
            let response_contact = if expires.as_secs() == 0 {
                contact.clone()
            } else {
                SmolStr::new(format!("{};expires={}", contact, expires.as_secs()))
            };
            processed_contacts.push(response_contact);
        }

        // Build response
        let mut headers = Headers::new();

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

        // Add all processed contacts
        for contact in &processed_contacts {
            headers.push(SmolStr::new("Contact"), contact.clone());
        }

        headers.push(SmolStr::new("Date"), SmolStr::new(Utc::now().to_rfc2822()));
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("0".to_owned()));

        Ok(Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        ))
    }
}

/// Collects all Contact header values from the provided headers.
pub fn contact_headers(headers: &Headers) -> Vec<SmolStr> {
    headers.get_all("Contact").map(|v| v.clone()).collect()
}

/// Ensures To header has a tag parameter (RFC 3261 §8.2.6.2)
/// If the To header doesn't have a tag, generates and adds one
fn ensure_to_tag(to_header: &str) -> SmolStr {
    // Check if tag already exists
    if to_header.contains(";tag=") {
        return SmolStr::new(to_header.to_owned());
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_auth::{Credentials, DigestAuthenticator, MemoryCredentialStore};
    use sip_core::{Headers, Method, RequestLine, SipUri};

    #[test]
    fn collects_contact_headers() {
        let mut headers = Headers::new();
        headers.push("Contact".into(), "<sip:a@example.com>".into());
        headers.push("Contact".into(), "<sip:b@example.com>".into());
        let contacts = contact_headers(&headers);
        assert_eq!(contacts.len(), 2);
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
            .remove("sip:alice@example.com", "sip:ua.example.com")
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

        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua.example.com>;expires=60".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.start.code, 200);

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

        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua1.example.com>;expires=60".into());
        headers.push("Contact".into(), "<sip:ua2.example.com>;expires=120".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.start.code, 200);

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 2);
    }

    #[test]
    fn basic_registrar_handles_deregistration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        // First register
        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua.example.com>;expires=60".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        registrar.handle_register(&request).expect("response");
        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 1);

        // Now deregister with expires=0
        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua.example.com>;expires=0".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "2 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.start.code, 200);
        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn basic_registrar_handles_wildcard_deregistration() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        // Register multiple contacts
        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua1.example.com>;expires=60".into());
        headers.push("Contact".into(), "<sip:ua2.example.com>;expires=60".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        registrar.handle_register(&request).expect("response");
        assert_eq!(store.lookup("sip:alice@example.com").unwrap().len(), 2);

        // Deregister all with wildcard
        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "*".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "2 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.start.code, 200);
        assert!(store.lookup("sip:alice@example.com").unwrap().is_empty());
    }

    #[test]
    fn basic_registrar_parses_q_value() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None);

        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua.example.com>;q=0.5;expires=60".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

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

        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua.example.com>;expires=10".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        registrar.handle_register(&request).expect("response");

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        // Should be close to 100 (accounting for small processing delay)
        assert!(bindings[0].expires.as_secs() >= 95);
    }

    #[test]
    fn basic_registrar_respects_max_expires() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store.clone(), None).with_max_expires(Duration::from_secs(1000));

        let mut headers = Headers::new();
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Contact".into(), "<sip:ua.example.com>;expires=99999".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        registrar.handle_register(&request).expect("response");

        let bindings = store.lookup("sip:alice@example.com").unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].expires.as_secs() <= 1000);
    }

    #[test]
    fn registrar_challenges_when_auth_configured() {
        let store = MemoryLocationStore::new();
        let creds = Credentials {
            username: "alice".into(),
            password: "secret".into(),
            realm: "example.com".into(),
        };
        let auth = DigestAuthenticator::new("example.com", MemoryCredentialStore::with(vec![creds]));
        let registrar = BasicRegistrar::new(store, Some(auth));

        let mut headers = Headers::new();
        headers.push("Via".into(), "SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8".into());
        headers.push("From".into(), "<sip:alice@example.com>;tag=1234".into());
        headers.push("To".into(), "<sip:alice@example.com>".into());
        headers.push("Call-ID".into(), "call123".into());
        headers.push("CSeq".into(), "1 REGISTER".into());
        headers.push("Contact".into(), "<sip:ua.example.com>".into());

        let request = Request::new(
            RequestLine::new(Method::Register, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        let response = registrar.handle_register(&request).expect("response");
        assert_eq!(response.start.code, 401);

        // Verify WWW-Authenticate header is present
        assert!(response.headers.get("WWW-Authenticate").is_some());

        // RFC 3261: Verify required headers are copied from request
        assert_eq!(
            response.headers.get("Via").map(|v| v.as_str()),
            Some("SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8")
        );
        assert_eq!(
            response.headers.get("From").map(|v| v.as_str()),
            Some("<sip:alice@example.com>;tag=1234")
        );
        // RFC 3261 §8.2.6.2: Verify To header has tag added
        let to_header = response.headers.get("To").map(|v| v.as_str()).unwrap();
        assert!(to_header.starts_with("<sip:alice@example.com>"));
        assert!(to_header.contains(";tag="));  // Tag should be added
        assert_eq!(
            response.headers.get("Call-ID").map(|v| v.as_str()),
            Some("call123")
        );
        assert_eq!(
            response.headers.get("CSeq").map(|v| v.as_str()),
            Some("1 REGISTER")
        );
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

        let uri = registrar.extract_contact_uri("<sip:alice@example.com>;expires=3600");
        assert_eq!(uri.as_str(), "sip:alice@example.com");
    }

    #[test]
    fn extract_contact_uri_without_brackets() {
        let store = MemoryLocationStore::new();
        let registrar: BasicRegistrar<_, DigestAuthenticator<MemoryCredentialStore>> =
            BasicRegistrar::new(store, None);

        let uri = registrar.extract_contact_uri("sip:alice@example.com;expires=3600");
        assert_eq!(uri.as_str(), "sip:alice@example.com");
    }
}
