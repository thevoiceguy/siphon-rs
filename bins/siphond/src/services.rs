/// Shared service registry for handlers.
///
/// Provides access to dialog management, subscriptions, registrar, authentication, etc.

use std::sync::Arc;

use sip_auth::{DigestAuthenticator, MemoryCredentialStore};
use sip_dialog::{DialogManager, RSeqManager, SubscriptionManager};
use sip_registrar::{BasicRegistrar, MemoryLocationStore};

use crate::config::DaemonConfig;

/// Registry of shared services used by request handlers.
///
/// Services are created based on the daemon configuration mode.
/// Optional services (registrar, authenticator) are only created if enabled.
pub struct ServiceRegistry {
    /// Dialog manager for tracking call state
    pub dialog_mgr: Arc<DialogManager>,

    /// Subscription manager for SUBSCRIBE/NOTIFY
    pub subscription_mgr: Arc<SubscriptionManager>,

    /// RSeq manager for reliable provisional responses (PRACK)
    pub rseq_mgr: Arc<RSeqManager>,

    /// Optional registrar for REGISTER handling
    pub registrar: Option<Arc<BasicRegistrar<MemoryLocationStore, DigestAuthenticator<MemoryCredentialStore>>>>,

    /// Daemon configuration (immutable)
    pub config: Arc<DaemonConfig>,
}

impl ServiceRegistry {
    /// Create a new service registry from configuration.
    pub fn new(config: DaemonConfig) -> Self {
        let config = Arc::new(config);

        // Always create dialog and subscription managers
        let dialog_mgr = Arc::new(DialogManager::new());
        let subscription_mgr = Arc::new(SubscriptionManager::new());
        let rseq_mgr = Arc::new(RSeqManager::new());

        // Create registrar if enabled (it includes authenticator)
        let registrar = if config.enable_registrar() {
            let store = MemoryLocationStore::new();

            // Create authenticator if authentication is enabled
            let authenticator = if config.requires_auth() {
                let cred_store = MemoryCredentialStore::new();
                // TODO: Load users from config.auth.users_file if provided

                Some(DigestAuthenticator::new(
                    &config.auth.realm,
                    cred_store,
                ))
            } else {
                None
            };

            let reg = BasicRegistrar::new(store, authenticator)
                .with_default_expires(std::time::Duration::from_secs(config.registrar.default_expiry as u64))
                .with_min_expires(std::time::Duration::from_secs(config.registrar.min_expiry as u64))
                .with_max_expires(std::time::Duration::from_secs(config.registrar.max_expiry as u64));

            Some(Arc::new(reg))
        } else {
            None
        };

        Self {
            dialog_mgr,
            subscription_mgr,
            rseq_mgr,
            registrar,
            config,
        }
    }

    /// Check if authentication is required
    pub fn requires_auth(&self) -> bool {
        self.config.requires_auth()
    }

    /// Check if registrar is available
    pub fn has_registrar(&self) -> bool {
        self.registrar.is_some()
    }
}
