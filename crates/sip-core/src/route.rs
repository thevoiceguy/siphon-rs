use smol_str::SmolStr;

use crate::{name_addr::NameAddr, SipUri};

/// Parsed Route/Record-Route header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHeader(pub NameAddr);

impl RouteHeader {
    pub fn uri(&self) -> &SipUri {
        self.0.uri()
    }

    pub fn params(&self) -> impl Iterator<Item = (&SmolStr, &Option<SmolStr>)> {
        self.0.params()
    }

    pub fn inner(&self) -> &NameAddr {
        &self.0
    }
}
