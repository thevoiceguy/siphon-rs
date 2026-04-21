// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Shared service registry for handlers.
///
/// Provides access to dialog management, subscriptions, registrar, authentication, etc.
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use sip_auth::{DigestAuthenticator, MemoryCredentialStore};
use sip_dialog::{
    prack_validator::PrackValidator, session_timer_manager::SessionTimerManager, DialogManager,
    RSeqManager, SubscriptionManager,
};
use sip_ratelimit::{RateLimitConfig, RateLimiter};
use sip_registrar::{BasicRegistrar, MemoryLocationStore};
use sip_transaction::{TransactionManager, TransportDispatcher};
use sip_transport::pool::TlsClientConfig;
use tokio::net::UdpSocket;

use crate::b2bua_state::B2BUAStateManager;
use crate::config::DaemonConfig;
use crate::invite_state::InviteStateManager;
use crate::proxy_state::ProxyStateManager;

/// Registry of shared services used by request handlers.
///
/// Services are created based on the daemon configuration mode.
/// Optional services (registrar, authenticator) are only created if enabled.
#[derive(Clone)]
pub struct ServiceRegistry {
    /// Dialog manager for tracking call state
    pub dialog_mgr: Arc<DialogManager>,

    /// Subscription manager for SUBSCRIBE/NOTIFY
    pub subscription_mgr: Arc<SubscriptionManager>,

    /// RSeq manager for reliable provisional responses (PRACK)
    #[allow(dead_code)]
    pub rseq_mgr: Arc<RSeqManager>,

    /// PRACK validator for reliable provisional responses
    #[allow(dead_code)]
    pub prack_validator: Arc<PrackValidator>,

    /// Session timer manager (RFC 4028)
    pub session_timer_mgr: Arc<SessionTimerManager>,

    /// Proxy state manager for tracking forwarded transactions
    pub proxy_state: Arc<ProxyStateManager>,

    /// B2BUA state manager for tracking call leg pairs
    pub b2bua_state: Arc<B2BUAStateManager>,

    /// Invite state manager for tracking pending INVITE transactions (for CANCEL)
    pub invite_state: Arc<InviteStateManager>,

    /// Optional authenticator for non-REGISTER requests (INVITE, SUBSCRIBE, etc.)
    /// When authentication is enabled, all methods are challenged, not just REGISTER.
    pub authenticator: Option<Arc<DigestAuthenticator<MemoryCredentialStore>>>,

    /// Optional registrar for REGISTER handling
    pub registrar: Option<
        Arc<BasicRegistrar<MemoryLocationStore, DigestAuthenticator<MemoryCredentialStore>>>,
    >,

    /// Transaction manager for sending requests (set after initialization)
    pub transaction_mgr: OnceLock<Arc<TransactionManager>>,

    /// Transport dispatcher for sending responses (set after initialization)
    pub transport_dispatcher: OnceLock<Arc<dyn TransportDispatcher>>,

    /// UDP socket for sending ACKs and other messages over UDP (set after initialization)
    pub udp_socket: OnceLock<Arc<UdpSocket>>,

    /// TLS client config for outbound TLS connections (set after initialization)
    pub tls_client_config: OnceLock<Arc<TlsClientConfig>>,

    /// Daemon configuration (immutable)
    pub config: Arc<DaemonConfig>,

    /// Per-source-IP rate limiter for authentication attempts. Keyed by
    /// peer IP. Used to throttle Digest brute-force across REGISTER and
    /// other authenticated methods. Always present; may be `disabled()`.
    pub auth_rate_limiter: Arc<RateLimiter>,

    /// Per-source-IP rate limiter for REGISTER. Default: 60/h burst 10.
    pub register_rate_limiter: Arc<RateLimiter>,

    /// Per-source-IP rate limiter for INVITE. Default: 30/min burst 10.
    pub invite_rate_limiter: Arc<RateLimiter>,
}

impl ServiceRegistry {
    /// Create a new service registry from configuration.
    pub fn new(config: DaemonConfig) -> Self {
        let config = Arc::new(config);

        // Always create dialog, subscription, and proxy state managers
        let dialog_mgr = Arc::new(DialogManager::new());
        let subscription_mgr = Arc::new(SubscriptionManager::new());
        let rseq_mgr = Arc::new(RSeqManager::new());
        let prack_validator = Arc::new(PrackValidator::new());
        let session_timer_mgr = Arc::new(SessionTimerManager::new());
        let proxy_state = Arc::new(ProxyStateManager::new());
        let b2bua_state = Arc::new(B2BUAStateManager::new());
        let invite_state = Arc::new(InviteStateManager::new());

        // Create authenticator if authentication is enabled (for any mode)
        let authenticator = if config.features.authentication {
            let mut cred_store = MemoryCredentialStore::new();

            // Load users from file if provided
            if let Some(ref users_file) = config.auth.users_file {
                match load_users_file(users_file) {
                    Ok(users) => {
                        let count = users.len();
                        for (username, password) in users {
                            cred_store.add(sip_auth::Credentials::new(
                                username,
                                password,
                                &config.auth.realm,
                            ));
                        }
                        tracing::info!(
                            file = %users_file.display(),
                            count = count,
                            "Loaded authentication users from file"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            file = %users_file.display(),
                            error = %e,
                            "Failed to load users file, starting with empty credential store"
                        );
                    }
                }
            }

            Some(Arc::new(DigestAuthenticator::new(
                &config.auth.realm,
                cred_store,
            )))
        } else {
            None
        };

        // Create registrar if enabled (uses its own authenticator instance for REGISTER auth)
        let registrar = if config.enable_registrar() {
            let store = MemoryLocationStore::new();

            // Create a separate authenticator for the registrar
            let reg_auth = if config.features.authentication {
                let mut cred_store = MemoryCredentialStore::new();
                if let Some(ref users_file) = config.auth.users_file {
                    if let Ok(users) = load_users_file(users_file) {
                        for (username, password) in users {
                            cred_store.add(sip_auth::Credentials::new(
                                username,
                                password,
                                &config.auth.realm,
                            ));
                        }
                    }
                }
                Some(DigestAuthenticator::new(&config.auth.realm, cred_store))
            } else {
                None
            };

            let reg = BasicRegistrar::new(store, reg_auth)
                .with_default_expires(std::time::Duration::from_secs(
                    config.registrar.default_expiry as u64,
                ))
                .with_min_expires(std::time::Duration::from_secs(
                    config.registrar.min_expiry as u64,
                ))
                .with_max_expires(std::time::Duration::from_secs(
                    config.registrar.max_expiry as u64,
                ));

            Some(Arc::new(reg))
        } else {
            None
        };

        // Per-source rate limiters. We instantiate three pools so each
        // method type has its own bucket — overrunning REGISTER doesn't
        // starve INVITE, etc. Keyed by peer IP at the call site (handled
        // in the dispatcher / handlers, since the rate-limiter API is
        // string-keyed).
        let auth_rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::auth_preset()));
        let register_rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::register_preset()));
        let invite_rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::invite_preset()));

        Self {
            dialog_mgr,
            subscription_mgr,
            rseq_mgr,
            prack_validator,
            session_timer_mgr,
            proxy_state,
            b2bua_state,
            invite_state,
            authenticator,
            registrar,
            transaction_mgr: OnceLock::new(),
            transport_dispatcher: OnceLock::new(),
            udp_socket: OnceLock::new(),
            tls_client_config: OnceLock::new(),
            config,
            auth_rate_limiter,
            register_rate_limiter,
            invite_rate_limiter,
        }
    }

    /// Set the transaction manager (can only be called once)
    pub fn set_transaction_manager(
        &self,
        mgr: Arc<TransactionManager>,
    ) -> Result<(), Arc<TransactionManager>> {
        self.transaction_mgr.set(mgr)
    }

    /// Set the transport dispatcher (can only be called once)
    pub fn set_transport_dispatcher(
        &self,
        dispatcher: Arc<dyn TransportDispatcher>,
    ) -> Result<(), Arc<dyn TransportDispatcher>> {
        self.transport_dispatcher.set(dispatcher)
    }

    /// Set the UDP socket (can only be called once)
    pub fn set_udp_socket(&self, socket: Arc<UdpSocket>) -> Result<(), Arc<UdpSocket>> {
        self.udp_socket.set(socket)
    }

    /// Set the TLS client config (can only be called once)
    pub fn set_tls_client_config(
        &self,
        config: Arc<TlsClientConfig>,
    ) -> Result<(), Arc<TlsClientConfig>> {
        self.tls_client_config.set(config)
    }

    /// Check if authentication is required
    #[allow(dead_code)]
    pub fn requires_auth(&self) -> bool {
        self.config.requires_auth()
    }

    /// Check if registrar is available
    #[allow(dead_code)]
    pub fn has_registrar(&self) -> bool {
        self.registrar.is_some()
    }
}

/// Load users from JSON file.
///
/// Expected format: `{"username": "password", ...}`. Passwords are stored in
/// plaintext, so on Unix we refuse to load the file unless its mode is no
/// more permissive than `0600` (owner read/write only). World- or
/// group-readable credentials are an immediate disclosure to any local user.
fn load_users_file(path: &std::path::Path) -> anyhow::Result<HashMap<String, String>> {
    use std::fs;

    enforce_secure_users_file_perms(path)?;

    let contents = fs::read_to_string(path)?;
    let users: HashMap<String, String> = serde_json::from_str(&contents)?;

    Ok(users)
}

/// Reject a users-file path whose permissions allow access beyond the owner.
///
/// On Unix this checks the mode bits and refuses anything more permissive
/// than `0600`. On other platforms this is a warning since portable
/// permission semantics aren't easily expressible.
#[cfg(unix)]
fn enforce_secure_users_file_perms(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(path)?;
    // Mask off file-type bits; we only care about the permission bits.
    let mode = meta.mode() & 0o777;
    // Any group/world bits set → reject.
    if mode & 0o077 != 0 {
        return Err(anyhow::anyhow!(
            "auth users file {} has insecure permissions {:o}; \
             plaintext credentials must be readable only by the owner \
             (chmod 0600 {} to fix)",
            path.display(),
            mode,
            path.display(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_secure_users_file_perms(path: &std::path::Path) -> anyhow::Result<()> {
    tracing::warn!(
        path = %path.display(),
        "cannot enforce auth-users file permissions on this platform; \
         ensure the file is readable only by the daemon's user"
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod users_file_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn write_users_file(mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "{{\"alice\": \"secret\"}}").expect("write");
        let mut perms = f.as_file().metadata().unwrap().permissions();
        perms.set_mode(mode);
        f.as_file().set_permissions(perms).unwrap();
        f
    }

    #[test]
    fn rejects_world_readable_users_file() {
        let f = write_users_file(0o644);
        let err = load_users_file(f.path()).expect_err("should refuse 0644");
        let msg = format!("{err}");
        assert!(
            msg.contains("insecure permissions"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn rejects_group_readable_users_file() {
        let f = write_users_file(0o640);
        assert!(load_users_file(f.path()).is_err(), "should refuse 0640");
    }

    #[test]
    fn accepts_owner_only_users_file() {
        let f = write_users_file(0o600);
        let users = load_users_file(f.path()).expect("0600 should be accepted");
        assert_eq!(users.get("alice").map(String::as_str), Some("secret"));
    }
}
