/// Request handler trait and method-specific handlers.

use anyhow::Result;
use async_trait::async_trait;
use sip_core::{Request, Response};
use sip_transaction::{ServerTransactionHandle, TransportContext};

use crate::services::ServiceRegistry;

pub mod bye;
pub mod invite;
pub mod options;
pub mod register;
pub mod refer;
pub mod subscribe;

/// Trait for handling SIP request methods.
///
/// Each handler is responsible for:
/// 1. Processing the request
/// 2. Managing any state (dialogs, subscriptions, etc.)
/// 3. Sending responses via the transaction handle
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle an incoming SIP request.
    ///
    /// The handler should:
    /// - Validate the request
    /// - Perform any business logic
    /// - Send appropriate responses (provisional, final)
    /// - Update shared state (dialogs, subscriptions, etc.)
    ///
    /// # Arguments
    /// * `request` - The incoming SIP request
    /// * `handle` - Transaction handle for sending responses
    /// * `ctx` - Transport context for the request
    /// * `services` - Shared service registry
    async fn handle(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        services: &ServiceRegistry,
    ) -> Result<()>;

    /// Returns the SIP method this handler is responsible for.
    fn method(&self) -> &str;
}
