use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sha2::{Digest, Sha256, Sha512};
use sip_core::{Headers, Method, Request, Response, StatusLine};
use sip_parse::parse_authorization_header;
use smol_str::SmolStr;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

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
    fn credentials_for(&self, method: Method, uri: &str) -> Option<Credentials>;
}

/// Credential store abstraction for server-side verification.
pub trait CredentialStore: Send + Sync {
    fn fetch(&self, username: &str, realm: &str) -> Option<Credentials>;
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
}

impl CredentialStore for MemoryCredentialStore {
    fn fetch(&self, username: &str, realm: &str) -> Option<Credentials> {
        self.creds
            .iter()
            .find(|c| c.username == username && c.realm == realm)
            .cloned()
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

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Some(DigestAlgorithm::Md5),
            "SHA-256" => Some(DigestAlgorithm::Sha256),
            "SHA-512" | "SHA-512-256" => Some(DigestAlgorithm::Sha512),
            _ => None,
        }
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

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auth" => Some(Qop::Auth),
            "auth-int" => Some(Qop::AuthInt),
            _ => None,
        }
    }
}

/// Nonce with expiry tracking.
#[derive(Debug, Clone)]
pub struct Nonce {
    pub value: SmolStr,
    pub created_at: Instant,
    pub ttl: Duration,
}

impl Nonce {
    pub fn new(ttl: Duration) -> Self {
        let token: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        Self {
            value: SmolStr::new(token),
            created_at: Instant::now(),
            ttl,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.created_at.elapsed() <= self.ttl
    }
}

/// Nonce manager with automatic cleanup.
#[derive(Debug)]
pub struct NonceManager {
    nonces: Arc<DashMap<SmolStr, Nonce>>,
    ttl: Duration,
}

impl NonceManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            nonces: Arc::new(DashMap::new()),
            ttl,
        }
    }

    pub fn generate(&self) -> Nonce {
        let nonce = Nonce::new(self.ttl);
        self.nonces.insert(nonce.value.clone(), nonce.clone());
        nonce
    }

    pub fn verify(&self, value: &str) -> bool {
        if let Some(entry) = self.nonces.get(value) {
            entry.is_valid()
        } else {
            false
        }
    }

    pub fn cleanup(&self) {
        self.nonces.retain(|_, nonce| nonce.is_valid());
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

/// Digest authenticator implementing RFC 7616 (MD5, SHA-256, SHA-512).
pub struct DigestAuthenticator<S: CredentialStore> {
    pub realm: SmolStr,
    pub algorithm: DigestAlgorithm,
    pub qop: Qop,
    pub store: S,
    pub nonce_manager: NonceManager,
    pub proxy_auth: bool,
}

impl<S: CredentialStore> DigestAuthenticator<S> {
    pub fn new(realm: &str, store: S) -> Self {
        Self {
            realm: SmolStr::new(realm.to_owned()),
            algorithm: DigestAlgorithm::Md5,
            qop: Qop::Auth,
            store,
            nonce_manager: NonceManager::default(),
            proxy_auth: false,
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
        self.nonce_manager = NonceManager::new(ttl);
        self
    }

    fn build_challenge(&self) -> Headers {
        let mut hdrs = Headers::new();
        let nonce = self.nonce_manager.generate();
        let mut value = String::new();
        let _ = write!(
            value,
            "Digest realm=\"{}\", nonce=\"{}\", algorithm={}, qop=\"{}\"",
            self.realm,
            nonce.value,
            self.algorithm.as_str(),
            self.qop.as_str()
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

    fn compute_ha2(&self, method: Method, uri: &str, body: &[u8]) -> String {
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

    fn compute_response(
        &self,
        username: &str,
        password: &str,
        method: Method,
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
            format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop.as_str(), ha2)
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
        if let Some(to) = request.headers.get("To") {
            headers.push(SmolStr::new("To"), to.clone());
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
        let header_name = if self.proxy_auth {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };

        let auth_header = match headers.get(header_name) {
            Some(h) => h,
            None => return Ok(false),
        };

        let parsed = match parse_authorization_header(auth_header) {
            Some(p) => p,
            None => return Ok(false),
        };

        if !parsed.scheme.eq_ignore_ascii_case("Digest") {
            return Ok(false);
        }

        let username = parsed
            .param("username")
            .ok_or_else(|| anyhow!("missing username"))?;
        let realm = parsed.param("realm").ok_or_else(|| anyhow!("missing realm"))?;
        let nonce = parsed.param("nonce").ok_or_else(|| anyhow!("missing nonce"))?;
        let uri = parsed.param("uri").ok_or_else(|| anyhow!("missing uri"))?;
        let response = parsed
            .param("response")
            .ok_or_else(|| anyhow!("missing response"))?;

        let _algorithm = parsed
            .param("algorithm")
            .and_then(|a| DigestAlgorithm::from_str(a.as_str()))
            .unwrap_or(self.algorithm);

        let nc = parsed.param("nc");
        let cnonce = parsed.param("cnonce");
        let qop = parsed.param("qop").and_then(|q| Qop::from_str(q.as_str()));

        if realm.as_str() != self.realm.as_str() {
            info!(realm = %realm, "digest realm mismatch");
            return Ok(false);
        }

        if !self.nonce_manager.verify(nonce) {
            info!("digest nonce invalid/expired");
            return Ok(false);
        }

        let creds = self
            .store
            .fetch(username, &self.realm)
            .ok_or_else(|| anyhow!("unknown user"))?;

        let response_calc = self.compute_response(
            username,
            creds.password.as_str(),
            request.start.method,
            uri,
            nonce,
            nc.map(|s| s.as_str()),
            cnonce.map(|s| s.as_str()),
            qop,
            request.body.as_ref(),
        );

        Ok(response_calc == response.as_str())
    }

    fn credentials_for(&self, _method: Method, _uri: &str) -> Option<Credentials> {
        None
    }
}

/// Client-side authentication helper for generating Authorization headers.
pub struct DigestClient {
    pub username: SmolStr,
    pub password: SmolStr,
    pub nc: u32,
}

impl DigestClient {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: SmolStr::new(username.to_owned()),
            password: SmolStr::new(password.to_owned()),
            nc: 0,
        }
    }

    /// Generates Authorization header value from a 401/407 challenge.
    pub fn generate_authorization(
        &mut self,
        method: Method,
        uri: &str,
        realm: &str,
        nonce: &str,
        algorithm: DigestAlgorithm,
        qop: Option<Qop>,
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
            let final_input = format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc_str, cnonce, qop.as_str(), ha2);
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
            auth.push_str(&format!(", qop={}, nc={}, cnonce=\"{}\"", qop.as_str(), nc_str, cnonce));
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
        assert_eq!(DigestAlgorithm::from_str("MD5"), Some(DigestAlgorithm::Md5));
        assert_eq!(DigestAlgorithm::from_str("SHA-256"), Some(DigestAlgorithm::Sha256));
        assert_eq!(DigestAlgorithm::from_str("SHA-512"), Some(DigestAlgorithm::Sha512));
        assert_eq!(DigestAlgorithm::from_str("sha-256"), Some(DigestAlgorithm::Sha256));
        assert_eq!(DigestAlgorithm::from_str("INVALID"), None);
    }

    #[test]
    fn qop_from_str() {
        assert_eq!(Qop::from_str("auth"), Some(Qop::Auth));
        assert_eq!(Qop::from_str("auth-int"), Some(Qop::AuthInt));
        assert_eq!(Qop::from_str("AUTH"), Some(Qop::Auth));
        assert_eq!(Qop::from_str("invalid"), None);
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
            RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()),
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
            RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()),
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
        let auth = DigestAuthenticator::new("example.com", store);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:bob@example.com";
        let nc = "00000001";
        let cnonce = "abc123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            method,
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
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc
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
        let auth = DigestAuthenticator::new("example.com", store)
            .with_algorithm(DigestAlgorithm::Sha256);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Register;
        let uri = "sip:example.com";
        let nc = "00000001";
        let cnonce = "xyz";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            method,
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
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-256, cnonce=\"{}\", nc={}, qop=auth",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc
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
        let auth = DigestAuthenticator::new("test.com", store)
            .with_algorithm(DigestAlgorithm::Sha512);

        let nonce = auth.nonce_manager.generate();
        let method = Method::Invite;
        let uri = "sip:alice@test.com";
        let nc = "00000001";
        let cnonce = "nonce123";

        let response = auth.compute_response(
            creds.username.as_str(),
            creds.password.as_str(),
            method,
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
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=SHA-512, cnonce=\"{}\", nc={}, qop=auth",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc
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
        let auth = DigestAuthenticator::new("example.com", store);

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("Authorization"),
            SmolStr::new(
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"invalid\", uri=\"sip:bob@example.com\", response=\"abcd\""
            ),
        );

        let request = Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()),
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
        let auth = DigestAuthenticator::new("example.com", store);

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
            RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(!auth.verify(&request, &request.headers).unwrap());
    }

    #[test]
    fn digest_client_generates_authorization() {
        let mut client = DigestClient::new("alice", "secret");
        let auth = client.generate_authorization(
            Method::Register,
            "sip:example.com",
            "example.com",
            "testnonce123",
            DigestAlgorithm::Md5,
            Some(Qop::Auth),
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
    }

    #[test]
    fn digest_client_increments_nc() {
        let mut client = DigestClient::new("alice", "secret");

        let auth1 = client.generate_authorization(
            Method::Register,
            "sip:example.com",
            "example.com",
            "nonce1",
            DigestAlgorithm::Md5,
            Some(Qop::Auth),
            b"",
        );
        assert!(auth1.contains("nc=00000001"));

        let auth2 = client.generate_authorization(
            Method::Register,
            "sip:example.com",
            "example.com",
            "nonce1",
            DigestAlgorithm::Md5,
            Some(Qop::Auth),
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
            Method::Invite,
            uri,
            "sip.example.com",
            &nonce.value,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
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
            method,
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
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"{}\", nc={}, qop=auth-int",
                creds.username, creds.realm, nonce.value, uri, response, cnonce, nc
            )),
        );

        let request = Request::new(
            RequestLine::new(method, SipUri::parse(uri).unwrap()),
            headers,
            Bytes::from_static(body),
        );

        assert!(auth.verify(&request, &request.headers).unwrap());
    }
}
