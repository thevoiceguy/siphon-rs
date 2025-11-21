use crate::name_addr::NameAddr;

/// Parsed representation of a Contact header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactHeader(pub NameAddr);

impl ContactHeader {
    /// Returns the contact URI.
    pub fn uri(&self) -> &crate::SipUri {
        self.0.uri()
    }

    pub fn params(&self) -> impl Iterator<Item = (&smol_str::SmolStr, &Option<smol_str::SmolStr>)> {
        self.0.params()
    }

    pub fn inner(&self) -> &NameAddr {
        &self.0
    }
}
