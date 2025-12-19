use crate::capabilities::CapabilitySet;
use crate::name_addr::NameAddr;

/// Parsed representation of a Contact header value.
///
/// Per RFC 3840, Contact headers can include capability feature tags
/// as parameters to indicate UA capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactHeader(pub NameAddr);

impl ContactHeader {
    /// Returns the contact URI.
    pub fn uri(&self) -> &crate::Uri {
        self.0.uri()
    }

    /// Returns an iterator over all Contact header parameters.
    pub fn params(&self) -> impl Iterator<Item = (&smol_str::SmolStr, &Option<smol_str::SmolStr>)> {
        self.0.params()
    }

    /// Returns the inner NameAddr.
    pub fn inner(&self) -> &NameAddr {
        &self.0
    }

    /// Extracts RFC 3840 capabilities from Contact header parameters.
    ///
    /// This parses capability feature tags (like audio, video, methods, etc.)
    /// from the Contact header parameters and returns them as a CapabilitySet.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{ContactHeader, NameAddr, SipUri, Uri, FeatureTag};
    /// use std::collections::BTreeMap;
    /// use smol_str::SmolStr;
    ///
    /// let mut params = BTreeMap::new();
    /// params.insert(SmolStr::new("audio"), None);
    /// params.insert(SmolStr::new("video"), None);
    ///
    /// let name_addr = NameAddr {
    ///     display_name: None,
    ///     uri: Uri::from(SipUri::parse("sip:alice@example.com").unwrap()),
    ///     params,
    /// };
    ///
    /// let contact = ContactHeader(name_addr);
    /// let capabilities = contact.capabilities();
    ///
    /// assert!(capabilities.has(FeatureTag::Audio));
    /// assert!(capabilities.has(FeatureTag::Video));
    /// ```
    pub fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::from_params(self.0.params_map())
    }
}
