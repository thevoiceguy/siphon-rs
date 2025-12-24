// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

/// RFC 3329 Security Mechanism names.
///
/// Common security mechanisms used in SIP security agreement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityMechanism {
    /// Transport Layer Security (TLS)
    Tls,
    /// Digest Authentication
    Digest,
    /// IPsec with IKE key management
    IpsecIke,
    /// IPsec with manual key management
    IpsecMan,
    /// Other/custom security mechanism
    Other(SmolStr),
}

impl SecurityMechanism {
    /// Returns the mechanism name as a string.
    pub fn as_str(&self) -> &str {
        match self {
            SecurityMechanism::Tls => "tls",
            SecurityMechanism::Digest => "digest",
            SecurityMechanism::IpsecIke => "ipsec-ike",
            SecurityMechanism::IpsecMan => "ipsec-man",
            SecurityMechanism::Other(s) => s.as_str(),
        }
    }

    /// Parses a mechanism name from a string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tls" => SecurityMechanism::Tls,
            "digest" => SecurityMechanism::Digest,
            "ipsec-ike" => SecurityMechanism::IpsecIke,
            "ipsec-man" => SecurityMechanism::IpsecMan,
            _ => SecurityMechanism::Other(SmolStr::new(s)),
        }
    }
}

impl fmt::Display for SecurityMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// RFC 3329 Security Agreement entry.
///
/// Represents a single security mechanism with its parameters.
/// Used in Security-Client, Security-Server, and Security-Verify headers.
///
/// # Common Parameters
///
/// - `q` - Preference value (0.0-1.0, default 0.001)
/// - `d-alg` - Digest algorithm (MD5, SHA-1, SHA-256, etc.)
/// - `d-qop` - Digest quality of protection (auth, auth-int)
/// - `d-ver` - Digest version
/// - `algorithm` - Encryption algorithm
/// - `protocol` - IPsec protocol (esp, ah)
/// - `mode` - IPsec mode (trans, tunnel)
/// - `encrypt-algorithm` - Encryption algorithm for IPsec
/// - `spi-c` - SPI for client
/// - `spi-s` - SPI for server
/// - `port-c` - Port for client
/// - `port-s` - Port for server
///
/// # Examples
///
/// ```
/// use sip_core::{SecurityEntry, SecurityMechanism};
///
/// // TLS with preference
/// let mut tls = SecurityEntry::new(SecurityMechanism::Tls);
/// tls.set_param("q", Some("0.5"));
///
/// // Digest with algorithm
/// let mut digest = SecurityEntry::new(SecurityMechanism::Digest);
/// digest.set_param("d-alg", Some("SHA-256"));
/// digest.set_param("d-qop", Some("auth"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEntry {
    pub mechanism: SecurityMechanism,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl SecurityEntry {
    /// Creates a new security entry with the given mechanism.
    pub fn new(mechanism: SecurityMechanism) -> Self {
        Self {
            mechanism,
            params: BTreeMap::new(),
        }
    }

    /// Sets a parameter value.
    pub fn set_param(&mut self, name: &str, value: Option<&str>) {
        self.params
            .insert(SmolStr::new(name), value.map(SmolStr::new));
    }

    /// Gets a parameter value.
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name))
    }

    /// Sets the preference value (q parameter).
    ///
    /// The q value should be between 0.0 and 1.0.
    /// Default is 0.001 per RFC 3329.
    pub fn set_preference(&mut self, q: f32) {
        let q_str = if q == 1.0 {
            "1".to_string()
        } else {
            format!("{:.3}", q)
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string()
        };
        self.set_param("q", Some(&q_str));
    }

    /// Gets the preference value (q parameter).
    pub fn preference(&self) -> Option<f32> {
        self.get_param("q")
            .and_then(|v| v.as_ref())
            .and_then(|s| parse_q_value(s.as_str()))
    }

    /// Creates a TLS security entry with default parameters.
    pub fn tls() -> Self {
        Self::new(SecurityMechanism::Tls)
    }

    /// Creates a Digest security entry with algorithm.
    pub fn digest(algorithm: &str, qop: Option<&str>) -> Self {
        let mut entry = Self::new(SecurityMechanism::Digest);
        entry.set_param("d-alg", Some(algorithm));
        if let Some(q) = qop {
            entry.set_param("d-qop", Some(q));
        }
        entry
    }

    /// Creates an IPsec-IKE security entry.
    pub fn ipsec_ike(algorithm: &str, protocol: &str, mode: &str) -> Self {
        let mut entry = Self::new(SecurityMechanism::IpsecIke);
        entry.set_param("algorithm", Some(algorithm));
        entry.set_param("protocol", Some(protocol));
        entry.set_param("mode", Some(mode));
        entry
    }
}

impl fmt::Display for SecurityEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mechanism)?;
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

/// RFC 3329 Security-Client header.
///
/// Used by UACs to advertise supported security mechanisms in the initial
/// request. The UAC lists all security mechanisms it supports, with optional
/// preference values.
///
/// # Examples
///
/// ```
/// use sip_core::{SecurityClientHeader, SecurityEntry, SecurityMechanism};
///
/// // UAC supports TLS and Digest
/// let mut tls = SecurityEntry::tls();
/// tls.set_preference(0.5);
///
/// let mut digest = SecurityEntry::digest("SHA-256", Some("auth"));
/// digest.set_preference(0.3);
///
/// let header = SecurityClientHeader::new(vec![tls, digest]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityClientHeader {
    pub entries: Vec<SecurityEntry>,
}

impl SecurityClientHeader {
    /// Creates a new Security-Client header with the given entries.
    pub fn new(entries: Vec<SecurityEntry>) -> Self {
        Self { entries }
    }

    /// Creates a Security-Client header with a single mechanism.
    pub fn single(entry: SecurityEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Returns true if the header is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of security mechanisms.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns entries sorted by preference (highest first).
    pub fn sorted_by_preference(&self) -> Vec<&SecurityEntry> {
        let mut entries: Vec<&SecurityEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| {
            let qa = a.preference().unwrap_or(0.001);
            let qb = b.preference().unwrap_or(0.001);
            qb.total_cmp(&qa)
        });
        entries
    }
}

impl fmt::Display for SecurityClientHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

/// RFC 3329 Security-Server header.
///
/// Used by UASs (typically in 494 Security Agreement Required responses) to
/// advertise supported security mechanisms. The server lists all security
/// mechanisms it supports, with optional preference values.
///
/// # Examples
///
/// ```
/// use sip_core::{SecurityServerHeader, SecurityEntry};
///
/// // Server supports TLS and Digest
/// let mut tls = SecurityEntry::tls();
/// tls.set_preference(0.8);
///
/// let mut digest = SecurityEntry::digest("MD5", Some("auth"));
/// digest.set_preference(0.5);
///
/// let header = SecurityServerHeader::new(vec![tls, digest]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityServerHeader {
    pub entries: Vec<SecurityEntry>,
}

impl SecurityServerHeader {
    /// Creates a new Security-Server header with the given entries.
    pub fn new(entries: Vec<SecurityEntry>) -> Self {
        Self { entries }
    }

    /// Creates a Security-Server header with a single mechanism.
    pub fn single(entry: SecurityEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Returns true if the header is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of security mechanisms.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns entries sorted by preference (highest first).
    pub fn sorted_by_preference(&self) -> Vec<&SecurityEntry> {
        let mut entries: Vec<&SecurityEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| {
            let qa = a.preference().unwrap_or(0.001);
            let qb = b.preference().unwrap_or(0.001);
            qb.total_cmp(&qa)
        });
        entries
    }

    /// Finds the best matching mechanism supported by both client and server.
    ///
    /// Returns the entry with the highest combined preference that appears
    /// in both lists.
    pub fn find_best_match(&self, client: &SecurityClientHeader) -> Option<&SecurityEntry> {
        let mut best: Option<(&SecurityEntry, f32)> = None;

        for server_entry in &self.entries {
            if let Some(client_entry) = client
                .entries
                .iter()
                .find(|c| c.mechanism == server_entry.mechanism)
            {
                let server_q = server_entry.preference().unwrap_or(0.001);
                let client_q = client_entry.preference().unwrap_or(0.001);
                let combined = server_q * client_q;

                if best.map_or(true, |(_, score)| combined > score) {
                    best = Some((server_entry, combined));
                }
            }
        }

        best.map(|(entry, _)| entry)
    }
}

impl fmt::Display for SecurityServerHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

/// RFC 3329 Security-Verify header.
///
/// Used by UACs in subsequent requests (after receiving 494) to echo the
/// chosen security mechanism and its parameters. This allows the server
/// to verify that the correct security mechanism is being used and prevents
/// downgrade attacks.
///
/// # Examples
///
/// ```
/// use sip_core::{SecurityVerifyHeader, SecurityEntry};
///
/// // UAC chose TLS, echoes it in Security-Verify
/// let tls = SecurityEntry::tls();
/// let header = SecurityVerifyHeader::single(tls);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityVerifyHeader {
    pub entries: Vec<SecurityEntry>,
}

impl SecurityVerifyHeader {
    /// Creates a new Security-Verify header with the given entries.
    pub fn new(entries: Vec<SecurityEntry>) -> Self {
        Self { entries }
    }

    /// Creates a Security-Verify header with a single mechanism.
    pub fn single(entry: SecurityEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Returns true if the header is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of security mechanisms.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Verifies that this matches the expected server entry.
    ///
    /// Returns true if the mechanisms match. This is used by servers
    /// to verify that the client is using the agreed security mechanism.
    pub fn matches(&self, server_entry: &SecurityEntry) -> bool {
        self.entries.iter().any(|e| {
            e.mechanism == server_entry.mechanism
            // Could also check parameters here for stricter validation
        })
    }
}

impl fmt::Display for SecurityVerifyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

/// Parses a Security-Client header from a header value string.
pub fn parse_security_client(value: &str) -> Option<SecurityClientHeader> {
    let entries = parse_security_entries(value)?;
    Some(SecurityClientHeader { entries })
}

/// Parses a Security-Server header from a header value string.
pub fn parse_security_server(value: &str) -> Option<SecurityServerHeader> {
    let entries = parse_security_entries(value)?;
    Some(SecurityServerHeader { entries })
}

/// Parses a Security-Verify header from a header value string.
pub fn parse_security_verify(value: &str) -> Option<SecurityVerifyHeader> {
    let entries = parse_security_entries(value)?;
    Some(SecurityVerifyHeader { entries })
}

/// Parses security entries from a comma-separated list.
fn parse_security_entries(value: &str) -> Option<Vec<SecurityEntry>> {
    let mut entries = Vec::new();

    for part in value.split(',') {
        if let Some(entry) = parse_single_security_entry(part.trim()) {
            entries.push(entry);
        }
    }

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Parses a single security entry: mechanism-name;param1=value1;param2=value2
fn parse_single_security_entry(value: &str) -> Option<SecurityEntry> {
    let mut parts = value.split(';');
    let mechanism_name = parts.next()?.trim();

    if mechanism_name.is_empty() {
        return None;
    }

    let mechanism = SecurityMechanism::parse(mechanism_name);
    let mut entry = SecurityEntry::new(mechanism);

    for param in parts {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }

        if let Some((key, val)) = param.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            if key.eq_ignore_ascii_case("q") {
                if parse_q_value(val).is_some() {
                    entry.set_param(key, Some(val));
                }
            } else {
                entry.set_param(key, Some(val));
            }
        } else {
            entry.set_param(param, None);
        }
    }

    Some(entry)
}

fn parse_q_value(value: &str) -> Option<f32> {
    let q = value.parse::<f32>().ok()?;
    if q.is_finite() && (0.0..=1.0).contains(&q) {
        Some(q)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_mechanism_parse() {
        assert_eq!(SecurityMechanism::parse("tls"), SecurityMechanism::Tls);
        assert_eq!(SecurityMechanism::parse("TLS"), SecurityMechanism::Tls);
        assert_eq!(
            SecurityMechanism::parse("digest"),
            SecurityMechanism::Digest
        );
        assert_eq!(
            SecurityMechanism::parse("ipsec-ike"),
            SecurityMechanism::IpsecIke
        );
        assert_eq!(
            SecurityMechanism::parse("ipsec-man"),
            SecurityMechanism::IpsecMan
        );

        if let SecurityMechanism::Other(s) = SecurityMechanism::parse("custom") {
            assert_eq!(s.as_str(), "custom");
        } else {
            panic!("Expected Other variant");
        }
    }

    #[test]
    fn security_mechanism_display() {
        assert_eq!(SecurityMechanism::Tls.to_string(), "tls");
        assert_eq!(SecurityMechanism::Digest.to_string(), "digest");
        assert_eq!(SecurityMechanism::IpsecIke.to_string(), "ipsec-ike");
    }

    #[test]
    fn security_entry_basic() {
        let mut entry = SecurityEntry::new(SecurityMechanism::Tls);
        assert_eq!(entry.mechanism, SecurityMechanism::Tls);
        assert!(entry.params.is_empty());

        entry.set_param("q", Some("0.5"));
        assert_eq!(
            entry.get_param("q").unwrap().as_ref().unwrap().as_str(),
            "0.5"
        );
    }

    #[test]
    fn security_entry_preference() {
        let mut entry = SecurityEntry::tls();
        entry.set_preference(0.8);
        assert_eq!(entry.preference(), Some(0.8));

        entry.set_preference(1.0);
        assert_eq!(entry.preference(), Some(1.0));
    }

    #[test]
    fn security_entry_display() {
        let mut entry = SecurityEntry::tls();
        entry.set_preference(0.5);
        assert_eq!(entry.to_string(), "tls;q=0.5");

        let mut digest = SecurityEntry::digest("SHA-256", Some("auth"));
        digest.set_preference(0.3);
        assert_eq!(digest.to_string(), "digest;d-alg=SHA-256;d-qop=auth;q=0.3");
    }

    #[test]
    fn security_client_header() {
        let tls = SecurityEntry::tls();
        let digest = SecurityEntry::digest("MD5", Some("auth"));

        let header = SecurityClientHeader::new(vec![tls, digest]);
        assert_eq!(header.len(), 2);
        assert!(!header.is_empty());
    }

    #[test]
    fn security_client_display() {
        let mut tls = SecurityEntry::tls();
        tls.set_preference(0.5);

        let mut digest = SecurityEntry::digest("SHA-256", None);
        digest.set_preference(0.3);

        let header = SecurityClientHeader::new(vec![tls, digest]);
        let display = header.to_string();
        assert!(display.contains("tls;q=0.5"));
        assert!(display.contains("digest;d-alg=SHA-256;q=0.3"));
        assert!(display.contains(", "));
    }

    #[test]
    fn security_server_find_best_match() {
        // Client supports TLS (q=0.5) and Digest (q=0.8)
        let mut client_tls = SecurityEntry::tls();
        client_tls.set_preference(0.5);

        let mut client_digest = SecurityEntry::digest("MD5", Some("auth"));
        client_digest.set_preference(0.8);

        let client = SecurityClientHeader::new(vec![client_tls, client_digest]);

        // Server supports TLS (q=0.9) and Digest (q=0.3)
        let mut server_tls = SecurityEntry::tls();
        server_tls.set_preference(0.9);

        let mut server_digest = SecurityEntry::digest("MD5", Some("auth"));
        server_digest.set_preference(0.3);

        let server = SecurityServerHeader::new(vec![server_tls.clone(), server_digest]);

        // Best match should be TLS (server's highest preference)
        let best = server.find_best_match(&client);
        assert!(best.is_some());
        assert_eq!(best.unwrap().mechanism, SecurityMechanism::Tls);
    }

    #[test]
    fn security_server_find_best_match_combines_preferences() {
        let mut client_tls = SecurityEntry::tls();
        client_tls.set_preference(0.2);

        let mut client_digest = SecurityEntry::digest("MD5", Some("auth"));
        client_digest.set_preference(0.9);

        let client = SecurityClientHeader::new(vec![client_tls, client_digest]);

        let mut server_tls = SecurityEntry::tls();
        server_tls.set_preference(0.9);

        let mut server_digest = SecurityEntry::digest("MD5", Some("auth"));
        server_digest.set_preference(0.4);

        let server = SecurityServerHeader::new(vec![server_tls, server_digest]);

        let best = server.find_best_match(&client);
        assert!(best.is_some());
        assert_eq!(best.unwrap().mechanism, SecurityMechanism::Digest);
    }

    #[test]
    fn security_verify_matches() {
        let tls = SecurityEntry::tls();
        let verify = SecurityVerifyHeader::single(tls.clone());

        assert!(verify.matches(&tls));

        let digest = SecurityEntry::digest("MD5", None);
        assert!(!verify.matches(&digest));
    }

    #[test]
    fn parse_security_client() {
        let value = "tls;q=0.5, digest;d-alg=SHA-256;d-qop=auth;q=0.3";
        let header = super::parse_security_client(value).unwrap();

        assert_eq!(header.len(), 2);
        assert_eq!(header.entries[0].mechanism, SecurityMechanism::Tls);
        assert_eq!(header.entries[0].preference(), Some(0.5));
        assert_eq!(header.entries[1].mechanism, SecurityMechanism::Digest);
        assert_eq!(header.entries[1].preference(), Some(0.3));
    }

    #[test]
    fn parse_security_server() {
        let value = "ipsec-ike;algorithm=des-ede3-cbc;protocol=esp;mode=trans";
        let header = super::parse_security_server(value).unwrap();

        assert_eq!(header.len(), 1);
        assert_eq!(header.entries[0].mechanism, SecurityMechanism::IpsecIke);
        assert_eq!(
            header.entries[0]
                .get_param("algorithm")
                .unwrap()
                .as_ref()
                .unwrap()
                .as_str(),
            "des-ede3-cbc"
        );
    }

    #[test]
    fn security_sorted_by_preference() {
        let mut tls = SecurityEntry::tls();
        tls.set_preference(0.3);

        let mut digest = SecurityEntry::digest("MD5", None);
        digest.set_preference(0.8);

        let mut ipsec = SecurityEntry::ipsec_ike("des", "esp", "trans");
        ipsec.set_preference(0.5);

        let header = SecurityClientHeader::new(vec![tls, digest, ipsec]);
        let sorted = header.sorted_by_preference();

        // Should be sorted: digest (0.8), ipsec (0.5), tls (0.3)
        assert_eq!(sorted[0].mechanism, SecurityMechanism::Digest);
        assert_eq!(sorted[1].mechanism, SecurityMechanism::IpsecIke);
        assert_eq!(sorted[2].mechanism, SecurityMechanism::Tls);
    }

    #[test]
    fn security_sorted_by_preference_ignores_invalid_q() {
        let mut tls = SecurityEntry::tls();
        tls.set_param("q", Some("NaN"));

        let mut digest = SecurityEntry::digest("MD5", None);
        digest.set_preference(0.8);

        let header = SecurityClientHeader::new(vec![tls, digest]);
        let sorted = header.sorted_by_preference();

        assert_eq!(sorted[0].mechanism, SecurityMechanism::Digest);
    }
}
