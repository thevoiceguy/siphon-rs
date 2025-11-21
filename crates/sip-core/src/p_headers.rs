use std::collections::BTreeMap;
use std::fmt;
use smol_str::SmolStr;

use crate::uri::Uri;
use crate::SipUri;
use crate::TelUri;

/// Generic identity structure used by P-Asserted-Identity and P-Preferred-Identity.
///
/// Unlike `NameAddr`, this can hold both SIP URIs and Tel URIs, which is required
/// by RFC 3325 P-Asserted-Identity headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PIdentity {
    pub display_name: Option<SmolStr>,
    pub uri: Uri,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl PIdentity {
    /// Creates a PIdentity from a URI with no display name.
    pub fn from_uri(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: BTreeMap::new(),
        }
    }

    /// Creates a PIdentity with a display name.
    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = Some(SmolStr::new(name));
        self
    }
}

impl fmt::Display for PIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.display_name {
            write!(f, "\"{}\" <{}>", name, self.uri)?;
        } else {
            write!(f, "<{}>", self.uri)?;
        }

        for (key, value) in &self.params {
            if let Some(v) = value {
                write!(f, ";{}={}", key, v)?;
            } else {
                write!(f, ";{}", key)?;
            }
        }
        Ok(())
    }
}

/// P-Access-Network-Info header (access-type plus params).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PAccessNetworkInfo {
    pub access_type: SmolStr,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

/// P-Visited-Network-ID header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PVisitedNetworkIdHeader {
    pub values: Vec<SmolStr>,
}

/// RFC 3325 P-Asserted-Identity header.
///
/// The P-Asserted-Identity header is used by trusted proxies to assert
/// the identity of the originator of a request within a trust domain.
///
/// # Trust Domain
///
/// P-Asserted-Identity should only be inserted by trusted entities and
/// should only be trusted when received from trusted entities. At trust
/// domain boundaries, this header should be removed.
///
/// # Examples
///
/// ```
/// use sip_core::{PAssertedIdentityHeader, SipUri, Uri};
///
/// // Create with SIP URI
/// let sip_uri = SipUri::parse("sip:alice@example.com").unwrap();
/// let pai = PAssertedIdentityHeader::single_sip(sip_uri);
///
/// // Create with Tel URI
/// let pai = PAssertedIdentityHeader::single_tel("+15551234567");
///
/// // Multiple identities (SIP + Tel)
/// let sip = SipUri::parse("sip:alice@example.com").unwrap();
/// let pai = PAssertedIdentityHeader::sip_and_tel(sip, "+15551234567");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PAssertedIdentityHeader {
    pub identities: Vec<PIdentity>,
}

impl PAssertedIdentityHeader {
    /// Creates a P-Asserted-Identity header with a single SIP URI.
    pub fn single_sip(uri: SipUri) -> Self {
        Self {
            identities: vec![PIdentity::from_uri(Uri::Sip(uri))],
        }
    }

    /// Creates a P-Asserted-Identity header with a single Tel URI.
    pub fn single_tel(number: &str) -> Self {
        let tel_uri_str = if number.starts_with("tel:") {
            number.to_string()
        } else {
            format!("tel:{}", number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str).expect("Invalid tel URI");
        Self {
            identities: vec![PIdentity::from_uri(Uri::Tel(tel_uri))],
        }
    }

    /// Creates a P-Asserted-Identity header with both SIP and Tel URIs.
    ///
    /// This is common in enterprise scenarios where both a SIP identity
    /// and a telephone number are asserted.
    pub fn sip_and_tel(sip_uri: SipUri, tel_number: &str) -> Self {
        let tel_uri_str = if tel_number.starts_with("tel:") {
            tel_number.to_string()
        } else {
            format!("tel:{}", tel_number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str).expect("Invalid tel URI");
        Self {
            identities: vec![
                PIdentity::from_uri(Uri::Sip(sip_uri)),
                PIdentity::from_uri(Uri::Tel(tel_uri)),
            ],
        }
    }

    /// Creates a P-Asserted-Identity header with a list of identities.
    pub fn new(identities: Vec<PIdentity>) -> Self {
        Self { identities }
    }

    /// Returns true if this header contains at least one Tel URI identity.
    pub fn has_tel_identity(&self) -> bool {
        self.identities
            .iter()
            .any(|id| id.uri.is_tel())
    }

    /// Returns true if this header contains at least one SIP URI identity.
    pub fn has_sip_identity(&self) -> bool {
        self.identities
            .iter()
            .any(|id| id.uri.is_sip())
    }

    /// Returns the first SIP URI identity if present.
    pub fn sip_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_sip())
            .map(|id| id.uri.as_str())
    }

    /// Returns the first Tel URI identity if present.
    pub fn tel_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_tel())
            .map(|id| id.uri.as_str())
    }

    /// Returns true if the header is empty (no identities).
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Returns the number of identities.
    pub fn len(&self) -> usize {
        self.identities.len()
    }
}

impl fmt::Display for PAssertedIdentityHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, identity) in self.identities.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", identity)?;
        }
        Ok(())
    }
}

/// RFC 3325 P-Preferred-Identity header.
///
/// The P-Preferred-Identity header is used by a UAC to express a preference
/// about which identity should be asserted by a trusted proxy. This is useful
/// when a user has multiple identities.
///
/// # Examples
///
/// ```
/// use sip_core::{PPreferredIdentityHeader, SipUri};
///
/// // Prefer a specific SIP identity
/// let sip_uri = SipUri::parse("sip:alice.smith@company.com").unwrap();
/// let ppi = PPreferredIdentityHeader::single_sip(sip_uri);
///
/// // Prefer a telephone number
/// let ppi = PPreferredIdentityHeader::single_tel("+15551234567");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PPreferredIdentityHeader {
    pub identities: Vec<PIdentity>,
}

impl PPreferredIdentityHeader {
    /// Creates a P-Preferred-Identity header with a single SIP URI.
    pub fn single_sip(uri: SipUri) -> Self {
        Self {
            identities: vec![PIdentity::from_uri(Uri::Sip(uri))],
        }
    }

    /// Creates a P-Preferred-Identity header with a single Tel URI.
    pub fn single_tel(number: &str) -> Self {
        let tel_uri_str = if number.starts_with("tel:") {
            number.to_string()
        } else {
            format!("tel:{}", number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str).expect("Invalid tel URI");
        Self {
            identities: vec![PIdentity::from_uri(Uri::Tel(tel_uri))],
        }
    }

    /// Creates a P-Preferred-Identity header with both SIP and Tel URIs.
    pub fn sip_and_tel(sip_uri: SipUri, tel_number: &str) -> Self {
        let tel_uri_str = if tel_number.starts_with("tel:") {
            tel_number.to_string()
        } else {
            format!("tel:{}", tel_number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str).expect("Invalid tel URI");
        Self {
            identities: vec![
                PIdentity::from_uri(Uri::Sip(sip_uri)),
                PIdentity::from_uri(Uri::Tel(tel_uri)),
            ],
        }
    }

    /// Creates a P-Preferred-Identity header with a list of identities.
    pub fn new(identities: Vec<PIdentity>) -> Self {
        Self { identities }
    }

    /// Returns true if this header contains at least one Tel URI identity.
    pub fn has_tel_identity(&self) -> bool {
        self.identities
            .iter()
            .any(|id| id.uri.is_tel())
    }

    /// Returns true if this header contains at least one SIP URI identity.
    pub fn has_sip_identity(&self) -> bool {
        self.identities
            .iter()
            .any(|id| id.uri.is_sip())
    }

    /// Returns the first SIP URI identity if present.
    pub fn sip_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_sip())
            .map(|id| id.uri.as_str())
    }

    /// Returns the first Tel URI identity if present.
    pub fn tel_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_tel())
            .map(|id| id.uri.as_str())
    }

    /// Returns true if the header is empty (no identities).
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Returns the number of identities.
    pub fn len(&self) -> usize {
        self.identities.len()
    }
}

impl fmt::Display for PPreferredIdentityHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, identity) in self.identities.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", identity)?;
        }
        Ok(())
    }
}

/// Helper function to parse P-Asserted-Identity from headers.
pub fn parse_p_asserted_identity(headers: &crate::Headers) -> Option<PAssertedIdentityHeader> {
    let identities: Vec<PIdentity> = headers
        .get_all("P-Asserted-Identity")
        .filter_map(|value| parse_p_identity(value.as_str()))
        .collect();

    if identities.is_empty() {
        None
    } else {
        Some(PAssertedIdentityHeader { identities })
    }
}

/// Helper function to parse P-Preferred-Identity from headers.
pub fn parse_p_preferred_identity(headers: &crate::Headers) -> Option<PPreferredIdentityHeader> {
    let identities: Vec<PIdentity> = headers
        .get_all("P-Preferred-Identity")
        .filter_map(|value| parse_p_identity(value.as_str()))
        .collect();

    if identities.is_empty() {
        None
    } else {
        Some(PPreferredIdentityHeader { identities })
    }
}

/// Simple parser for P-Identity format: "Display Name" <uri>;params
fn parse_p_identity(value: &str) -> Option<PIdentity> {
    let input = value.trim();
    if input.is_empty() {
        return None;
    }

    // Try to parse as URI in brackets: <uri>
    if let Some(start) = input.find('<') {
        let end_rel = input[start + 1..].find('>')?;
        let end = start + 1 + end_rel;
        let display = input[..start].trim().trim_matches('"');
        let uri_str = input[start + 1..end].trim();

        let uri = Uri::parse(uri_str)?;

        Some(PIdentity {
            display_name: if display.is_empty() {
                None
            } else {
                Some(SmolStr::new(display))
            },
            uri,
            params: BTreeMap::new(),
        })
    } else {
        // Plain URI without brackets
        let uri = Uri::parse(input)?;
        Some(PIdentity {
            display_name: None,
            uri,
            params: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_asserted_identity_single_sip() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let pai = PAssertedIdentityHeader::single_sip(uri);

        assert_eq!(pai.identities.len(), 1);
        assert!(pai.has_sip_identity());
        assert!(!pai.has_tel_identity());
        assert_eq!(pai.sip_identity(), Some("sip:alice@example.com"));
    }

    #[test]
    fn p_asserted_identity_single_tel() {
        let pai = PAssertedIdentityHeader::single_tel("+15551234567");

        assert_eq!(pai.identities.len(), 1);
        assert!(!pai.has_sip_identity());
        assert!(pai.has_tel_identity());
        assert_eq!(pai.tel_identity(), Some("tel:+15551234567"));
    }

    #[test]
    fn p_asserted_identity_sip_and_tel() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let pai = PAssertedIdentityHeader::sip_and_tel(uri, "+15551234567");

        assert_eq!(pai.identities.len(), 2);
        assert!(pai.has_sip_identity());
        assert!(pai.has_tel_identity());
        assert_eq!(pai.sip_identity(), Some("sip:alice@example.com"));
        assert_eq!(pai.tel_identity(), Some("tel:+15551234567"));
    }

    #[test]
    fn p_asserted_identity_display() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let pai = PAssertedIdentityHeader::single_sip(uri);

        let display = pai.to_string();
        assert!(display.contains("sip:alice@example.com"));
    }

    #[test]
    fn p_asserted_identity_tel_format() {
        // Test with "tel:" prefix
        let pai1 = PAssertedIdentityHeader::single_tel("tel:+15551234567");
        assert_eq!(pai1.tel_identity(), Some("tel:+15551234567"));

        // Test without "tel:" prefix
        let pai2 = PAssertedIdentityHeader::single_tel("+15551234567");
        assert_eq!(pai2.tel_identity(), Some("tel:+15551234567"));
    }

    #[test]
    fn p_preferred_identity_single_sip() {
        let uri = SipUri::parse("sip:bob@company.com").unwrap();
        let ppi = PPreferredIdentityHeader::single_sip(uri);

        assert_eq!(ppi.identities.len(), 1);
        assert!(ppi.has_sip_identity());
        assert!(!ppi.has_tel_identity());
        assert_eq!(ppi.sip_identity(), Some("sip:bob@company.com"));
    }

    #[test]
    fn p_preferred_identity_single_tel() {
        let ppi = PPreferredIdentityHeader::single_tel("+15559876543");

        assert_eq!(ppi.identities.len(), 1);
        assert!(!ppi.has_sip_identity());
        assert!(ppi.has_tel_identity());
        assert_eq!(ppi.tel_identity(), Some("tel:+15559876543"));
    }

    #[test]
    fn p_preferred_identity_display() {
        let uri = SipUri::parse("sip:bob@company.com").unwrap();
        let ppi = PPreferredIdentityHeader::single_sip(uri);

        let display = ppi.to_string();
        assert!(display.contains("sip:bob@company.com"));
    }

    #[test]
    fn parse_p_identity_with_brackets() {
        let identity = parse_p_identity("<sip:alice@example.com>").unwrap();
        assert_eq!(identity.uri.as_str(), "sip:alice@example.com");
        assert_eq!(identity.display_name, None);
    }

    #[test]
    fn parse_p_identity_with_display() {
        let identity = parse_p_identity("\"Alice Smith\" <sip:alice@example.com>").unwrap();
        assert_eq!(identity.uri.as_str(), "sip:alice@example.com");
        assert_eq!(identity.display_name.as_ref().map(|s| s.as_str()), Some("Alice Smith"));
    }

    #[test]
    fn parse_p_identity_plain_uri() {
        let identity = parse_p_identity("sip:alice@example.com").unwrap();
        assert_eq!(identity.uri.as_str(), "sip:alice@example.com");
        assert_eq!(identity.display_name, None);
    }

    #[test]
    fn parse_p_identity_tel_uri() {
        let identity = parse_p_identity("<tel:+15551234567>").unwrap();
        assert_eq!(identity.uri.as_str(), "tel:+15551234567");
        assert!(identity.uri.is_tel());
    }

    #[test]
    fn p_asserted_identity_is_empty() {
        let pai = PAssertedIdentityHeader::new(vec![]);
        assert!(pai.is_empty());
        assert_eq!(pai.len(), 0);

        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let pai2 = PAssertedIdentityHeader::single_sip(uri);
        assert!(!pai2.is_empty());
        assert_eq!(pai2.len(), 1);
    }

    #[test]
    fn p_preferred_identity_is_empty() {
        let ppi = PPreferredIdentityHeader::new(vec![]);
        assert!(ppi.is_empty());
        assert_eq!(ppi.len(), 0);

        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let ppi2 = PPreferredIdentityHeader::single_sip(uri);
        assert!(!ppi2.is_empty());
        assert_eq!(ppi2.len(), 1);
    }

    #[test]
    fn p_identity_display_with_name() {
        let uri = Uri::parse("sip:alice@example.com").unwrap();
        let identity = PIdentity::from_uri(uri).with_display_name("Alice Smith");

        let display = identity.to_string();
        assert_eq!(display, "\"Alice Smith\" <sip:alice@example.com>");
    }

    #[test]
    fn p_identity_display_without_name() {
        let uri = Uri::parse("tel:+15551234567").unwrap();
        let identity = PIdentity::from_uri(uri);

        let display = identity.to_string();
        assert_eq!(display, "<tel:+15551234567>");
    }
}
