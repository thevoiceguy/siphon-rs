/// Configuration and operational modes for siphond daemon.

use std::path::PathBuf;

/// Operational mode determines which SIP methods are handled and how.
#[derive(Debug, Clone, PartialEq)]
pub enum DaemonMode {
    /// Minimal mode: Only respond to OPTIONS with 200 OK
    Minimal,

    /// Full UAS: Accept all incoming requests (INVITE, REGISTER, SUBSCRIBE, etc.)
    /// Automatically accepts calls, registrations, and subscriptions.
    FullUas,

    /// Registrar mode: Acts as a registration server with authentication
    Registrar,

    /// Proxy mode: Forward INVITE requests to registered users
    /// Combines registrar functionality with call forwarding
    Proxy,

    /// B2BUA mode: Back-to-Back User Agent - bridges calls between registered users
    /// Acts as both UAC and UAS, creating two separate call legs
    B2bua,

    /// Call server mode: Accept INVITE requests but not registrations
    /// Useful for testing call flows without registration complexity
    CallServer,

    /// Subscription server: Handle SUBSCRIBE/NOTIFY for event packages
    SubscriptionServer,

    /// Interactive mode: Requires user input for accept/reject decisions
    /// (Future: could integrate with web UI or CLI prompts)
    Interactive,
}

impl Default for DaemonMode {
    fn default() -> Self {
        Self::Minimal
    }
}

/// Feature flags for enabling/disabling specific capabilities
#[derive(Debug, Clone)]
pub struct FeatureFlags {
    /// Enable Digest authentication for protected methods
    pub authentication: bool,

    /// Automatically accept INVITE requests (vs reject with 486 Busy)
    pub auto_accept_calls: bool,

    /// Automatically accept REGISTER requests
    pub auto_accept_registrations: bool,

    /// Automatically accept SUBSCRIBE requests
    pub auto_accept_subscriptions: bool,

    /// Enable PRACK (reliable provisional responses)
    pub enable_prack: bool,

    /// Enable call transfer (REFER method)
    pub enable_refer: bool,

    /// Send Session-Timers (RFC 4028)
    pub enable_session_timers: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            authentication: false,
            auto_accept_calls: true,
            auto_accept_registrations: true,
            auto_accept_subscriptions: true,
            enable_prack: true,
            enable_refer: true,
            enable_session_timers: false,
        }
    }
}

/// SDP profile configuration for media handling
#[derive(Debug, Clone)]
pub enum SdpProfile {
    /// No SDP - reject calls requiring media
    None,

    /// Audio-only (PCMU/PCMA)
    AudioOnly,

    /// Audio and video
    AudioVideo,

    /// Custom SDP from file
    Custom(PathBuf),
}

impl Default for SdpProfile {
    fn default() -> Self {
        Self::AudioOnly
    }
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Authentication realm (e.g., "example.com")
    pub realm: String,

    /// Algorithm: MD5, SHA-256, SHA-512
    #[allow(dead_code)]
    pub algorithm: String,

    /// Quality of protection: auth, auth-int
    #[allow(dead_code)]
    pub qop: String,

    /// Nonce TTL in seconds
    #[allow(dead_code)]
    pub nonce_ttl_secs: u64,

    /// Path to users file (JSON: {"username": "password"})
    pub users_file: Option<PathBuf>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            realm: "siphond.local".to_string(),
            algorithm: "SHA-256".to_string(),
            qop: "auth".to_string(),
            nonce_ttl_secs: 3600,
            users_file: None,
        }
    }
}

/// Registrar configuration
#[derive(Debug, Clone)]
pub struct RegistrarConfig {
    /// Default expiry for registrations (seconds)
    pub default_expiry: u32,

    /// Minimum allowed expiry
    pub min_expiry: u32,

    /// Maximum allowed expiry
    pub max_expiry: u32,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            default_expiry: 3600,
            min_expiry: 60,
            max_expiry: 86400,
        }
    }
}

/// Complete daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Operational mode
    pub mode: DaemonMode,

    /// Feature flags
    pub features: FeatureFlags,

    /// SDP profile for calls
    pub sdp_profile: SdpProfile,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Registrar configuration
    pub registrar: RegistrarConfig,

    /// Local SIP URI for From/Contact headers
    pub local_uri: String,

    /// User-Agent header value
    pub user_agent: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            mode: DaemonMode::default(),
            features: FeatureFlags::default(),
            sdp_profile: SdpProfile::default(),
            auth: AuthConfig::default(),
            registrar: RegistrarConfig::default(),
            local_uri: "sip:siphond@localhost".to_string(),
            user_agent: "siphond/0.1".to_string(),
        }
    }
}

impl DaemonConfig {
    /// Check if authentication is required for this mode
    pub fn requires_auth(&self) -> bool {
        self.features.authentication && matches!(self.mode, DaemonMode::Registrar | DaemonMode::Proxy | DaemonMode::B2bua | DaemonMode::FullUas)
    }

    /// Check if registrar should be enabled
    pub fn enable_registrar(&self) -> bool {
        matches!(self.mode, DaemonMode::Registrar | DaemonMode::Proxy | DaemonMode::B2bua | DaemonMode::FullUas)
    }

    /// Check if call handling should be enabled (as UAS)
    pub fn enable_calls(&self) -> bool {
        matches!(
            self.mode,
            DaemonMode::FullUas | DaemonMode::CallServer | DaemonMode::Interactive | DaemonMode::Proxy | DaemonMode::B2bua
        )
    }

    /// Check if proxy mode is enabled (forward calls instead of accepting them)
    pub fn enable_proxy(&self) -> bool {
        matches!(self.mode, DaemonMode::Proxy)
    }

    /// Check if B2BUA mode is enabled (bridge calls between users)
    pub fn enable_b2bua(&self) -> bool {
        matches!(self.mode, DaemonMode::B2bua)
    }

    /// Check if subscription handling should be enabled
    pub fn enable_subscriptions(&self) -> bool {
        matches!(
            self.mode,
            DaemonMode::FullUas | DaemonMode::SubscriptionServer | DaemonMode::Interactive
        )
    }
}
