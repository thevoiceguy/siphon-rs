use rand::{distributions::Alphanumeric, Rng};
use sip_core::{Headers, Method, Request};
use smol_str::SmolStr;

/// Provides convenient access to repeated header fields commonly needed by the
/// transaction layer.
pub struct HeaderValues<'a> {
    inner: Vec<&'a SmolStr>,
}

impl<'a> HeaderValues<'a> {
    /// Returns `true` if no values are stored.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of values observed.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns an iterator over the collected header values.
    pub fn iter(&self) -> impl Iterator<Item = &'a SmolStr> + '_ {
        self.inner.iter().copied()
    }
}

impl<'a> IntoIterator for HeaderValues<'a> {
    type Item = &'a SmolStr;
    type IntoIter = std::vec::IntoIter<&'a SmolStr>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

/// Returns all `Via` header values in the order received.
pub fn vias<'a>(headers: &'a Headers) -> HeaderValues<'a> {
    HeaderValues {
        inner: headers.get_all("Via").collect(),
    }
}

/// Returns all `Record-Route` header values in their original order.
pub fn record_routes<'a>(headers: &'a Headers) -> HeaderValues<'a> {
    HeaderValues {
        inner: headers.get_all("Record-Route").collect(),
    }
}

/// Returns all `Route` header values in their original order.
pub fn routes<'a>(headers: &'a Headers) -> HeaderValues<'a> {
    HeaderValues {
        inner: headers.get_all("Route").collect(),
    }
}

/// Convenience helper that extracts the incoming Via headers from a `Request`.
pub fn request_vias<'a>(req: &'a Request) -> HeaderValues<'a> {
    vias(&req.headers)
}

/// Returns the top-most Via header value, if present.
pub fn top_via<'a>(req: &'a Request) -> Option<&'a SmolStr> {
    request_vias(req).iter().next()
}

/// Extracts the `branch=` parameter from a Via header string.
pub fn branch_from_via(via: &str) -> Option<&str> {
    via.split(';').skip(1).find_map(|part| {
        let mut split = part.splitn(2, '=');
        let name = split.next()?.trim();
        let value = split.next()?.trim();
        if name.eq_ignore_ascii_case("branch") {
            Some(value)
        } else {
            None
        }
    })
}

/// Returns the branch ID for the given request, if one is present.
pub fn request_branch_id(req: &Request) -> Option<SmolStr> {
    let via = top_via(req)?;
    let branch = branch_from_via(via)?;
    Some(SmolStr::new(branch.to_owned()))
}

/// Generates a new RFC 3261 magic-cookie branch identifier.
pub fn generate_branch_id() -> SmolStr {
    let mut rng = rand::thread_rng();
    let suffix: String = (&mut rng)
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    SmolStr::new(format!("z9hG4bK{}", suffix))
}

/// Timers referenced by the SIP transaction state machines (RFC 3261 §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionTimer {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    T1,
    T2,
    T4,
}

/// Client INVITE transaction states (RFC 3261 Figure 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientInviteState {
    Calling,
    Proceeding,
    Completed,
    Confirmed,
    Terminated,
}

/// Server INVITE transaction states (RFC 3261 Figure 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerInviteState {
    Proceeding,
    Completed,
    Confirmed,
    Terminated,
}

/// Client non-INVITE transaction states (RFC 3261 Figure 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientNonInviteState {
    Trying,
    Proceeding,
    Completed,
    Terminated,
}

/// Server non-INVITE transaction states (RFC 3261 Figure 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerNonInviteState {
    Trying,
    Proceeding,
    Completed,
    Terminated,
}

/// Aggregate of client-side transaction states (INVITE or non-INVITE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientTransactionState {
    Invite(ClientInviteState),
    NonInvite(ClientNonInviteState),
}

/// Aggregate of server-side transaction states (INVITE or non-INVITE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerTransactionState {
    Invite(ServerInviteState),
    NonInvite(ServerNonInviteState),
}

/// Unique key identifying a transaction (branch + method + direction).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    pub branch: SmolStr,
    pub method: Method,
    pub is_server: bool,
}

impl TransactionKey {
    /// Builds a transaction key from a request, deriving the branch parameter.
    pub fn from_request(req: &Request, is_server: bool) -> Option<Self> {
        let branch = request_branch_id(req)?;
        Some(Self {
            branch,
            method: req.start.method,
            is_server,
        })
    }
}

/// Skeleton client transaction state container.
#[derive(Debug)]
pub struct ClientTransaction {
    pub key: TransactionKey,
    pub state: ClientTransactionState,
}

impl ClientTransaction {
    /// Creates a client transaction with the provided key and initial state.
    pub fn new(key: TransactionKey, state: ClientTransactionState) -> Self {
        Self { key, state }
    }
}

/// Skeleton server transaction state container.
#[derive(Debug)]
pub struct ServerTransaction {
    pub key: TransactionKey,
    pub state: ServerTransactionState,
}

impl ServerTransaction {
    /// Creates a server transaction with the provided key and initial state.
    pub fn new(key: TransactionKey, state: ServerTransactionState) -> Self {
        Self { key, state }
    }
}

pub mod fsm;
pub mod manager;
pub mod timers;

pub use fsm::{
    ClientAction, ClientInviteAction, ClientInviteEvent, ClientInviteFsm, ClientNonInviteEvent,
    ClientNonInviteFsm, ServerAction, ServerInviteAction, ServerInviteEvent, ServerInviteFsm,
    ServerNonInviteEvent, ServerNonInviteFsm, TransportKind,
};
pub use manager::{
    ClientTransactionUser, ServerTransactionHandle, TransactionManager, TransportContext,
    TransportDispatcher,
};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, Method, RequestLine, SipUri, SipVersion};

    fn build_request(headers: Vec<(&str, &str)>) -> Request {
        let mut hdrs = Headers::new();
        for (name, value) in headers {
            hdrs.push(name.into(), value.into());
        }

        Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:example.com").unwrap()),
            hdrs,
            Bytes::new(),
        )
    }

    #[test]
    fn collects_all_vias_in_order() {
        let req = build_request(vec![
            ("Via", "SIP/2.0/UDP host1"),
            ("Via", "SIP/2.0/UDP host2"),
            ("Max-Forwards", "70"),
        ]);

        let values: Vec<&SmolStr> = request_vias(&req).into_iter().collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].as_str(), "SIP/2.0/UDP host1");
        assert_eq!(values[1].as_str(), "SIP/2.0/UDP host2");
    }

    #[test]
    fn record_routes_preserve_order() {
        let headers = {
            let mut h = Headers::new();
            h.push("Record-Route".into(), "<sip:proxy1>".into());
            h.push("Record-Route".into(), "<sip:proxy2>".into());
            h
        };

        let values: Vec<&SmolStr> = record_routes(&headers).into_iter().collect();
        assert_eq!(
            values.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            vec!["<sip:proxy1>", "<sip:proxy2>"]
        );
    }

    #[test]
    fn extracts_branch_from_top_via() {
        let branch = "z9hG4bKabc123";
        let via_value = format!("SIP/2.0/UDP host;branch={branch};received=1");
        assert_eq!(branch_from_via(via_value.as_str()), Some(branch));

        let req = build_request(vec![
            ("Via", via_value.as_str()),
            ("Via", "SIP/2.0/TCP other;branch=z9hG4bKignored"),
        ]);
        let extracted = request_branch_id(&req).expect("branch");
        assert_eq!(extracted.as_str(), branch);
    }

    #[test]
    fn transaction_key_derives_from_request() {
        let branch = "z9hG4bKtest";
        let via_value = format!("SIP/2.0/UDP host;branch={branch}");
        let req = build_request(vec![("Via", via_value.as_str()), ("CSeq", "1 INVITE")]);

        let key = TransactionKey::from_request(&req, true).expect("key");
        assert_eq!(key.branch.as_str(), branch);
        assert_eq!(key.method, Method::Invite);
        assert!(key.is_server);
    }

    #[test]
    fn generated_branch_has_magic_cookie() {
        let branch = generate_branch_id();
        assert!(branch.starts_with("z9hG4bK"));
        assert!(branch.len() > "z9hG4bK".len());
    }
}
