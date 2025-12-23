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

        // Create registrar if enabled (it includes authenticator)
        let registrar = if config.enable_registrar() {
            let store = MemoryLocationStore::new();

            // Create authenticator if authentication is enabled
            let authenticator = if config.requires_auth() {
                let mut cred_store = MemoryCredentialStore::new();

                // Load users from file if provided
                if let Some(ref users_file) = config.auth.users_file {
                    match load_users_file(users_file) {
                        Ok(users) => {
                            let count = users.len();
                            for (username, password) in users {
                                cred_store.add(sip_auth::Credentials {
                                    username: smol_str::SmolStr::new(username),
                                    password: smol_str::SmolStr::new(password),
                                    realm: smol_str::SmolStr::new(&config.auth.realm),
                                });
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

                Some(DigestAuthenticator::new(&config.auth.realm, cred_store))
            } else {
                None
            };

            let reg = BasicRegistrar::new(store, authenticator)
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

        Self {
            dialog_mgr,
            subscription_mgr,
            rseq_mgr,
            prack_validator,
            session_timer_mgr,
            proxy_state,
            b2bua_state,
            invite_state,
            registrar,
            transaction_mgr: OnceLock::new(),
            transport_dispatcher: OnceLock::new(),
            udp_socket: OnceLock::new(),
            tls_client_config: OnceLock::new(),
            config,
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

/// Load users from JSON file
///
/// Expected format: `{"username": "password", ...}`
fn load_users_file(path: &std::path::Path) -> anyhow::Result<HashMap<String, String>> {
    use std::fs;

    let contents = fs::read_to_string(path)?;
    let users: HashMap<String, String> = serde_json::from_str(&contents)?;

    Ok(users)
}
