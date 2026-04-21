// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Typed accessors over the raw SDP attribute vector.
//!
//! Round-trip preservation is built on a simple contract: the raw
//! `Vec<Attribute>` on [`MediaDescription`](crate::MediaDescription) /
//! [`SessionDescription`](crate::SessionDescription) is the single source
//! of truth for serialization. All accessors in this module *parse on
//! demand* from that vector and all mutators update the vector in place,
//! so unknown attributes — the long tail SDP carries from real-world
//! peers — survive untouched across `parse → modify → serialize`.
//!
//! The strict typing helps applications that need to read or set a
//! known attribute without re-implementing the parser. The setter
//! pattern is consistent: any existing attribute(s) of the same kind
//! are removed first, then the new value is appended, so the vector
//! never accumulates stale duplicates.

use crate::{Attribute, MediaDescription, SessionDescription};
use smol_str::SmolStr;

// ---------------------------------------------------------------------------
// a=sendrecv / a=sendonly / a=recvonly / a=inactive  (RFC 4566 §6)
// ---------------------------------------------------------------------------

/// Direction attribute on a media stream (or whole session).
///
/// Per RFC 4566 §6, exactly one of these property attributes describes
/// the directionality. If no attribute is present, [`Direction::SendRecv`]
/// is the implicit default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    /// Canonical token used in the `a=` attribute name.
    pub fn as_token(&self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }

    /// Parse a direction token (case-sensitive per spec).
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "sendrecv" => Some(Self::SendRecv),
            "sendonly" => Some(Self::SendOnly),
            "recvonly" => Some(Self::RecvOnly),
            "inactive" => Some(Self::Inactive),
            _ => None,
        }
    }
}

fn direction_from_attrs(attrs: &[Attribute]) -> Option<Direction> {
    attrs.iter().find_map(|a| match a {
        Attribute::Property(name) => Direction::from_token(name.as_str()),
        _ => None,
    })
}

/// True for the IPv4/IPv6 unspecified address (`0.0.0.0` and `::`).
/// Per RFC 3264 §5.1 the legacy hold convention re-uses this value
/// in the `c=` line to mean the stream is on hold.
fn is_unspecified_address(addr: &str) -> bool {
    let host = addr.split('/').next().unwrap_or(addr).trim();
    host == "0.0.0.0" || host == "::"
}

fn set_direction(attrs: &mut Vec<Attribute>, direction: Direction) {
    attrs.retain(|a| !matches!(a, Attribute::Property(n) if Direction::from_token(n).is_some()));
    attrs.push(Attribute::Property(SmolStr::new(direction.as_token())));
}

fn clear_direction(attrs: &mut Vec<Attribute>) {
    attrs.retain(|a| !matches!(a, Attribute::Property(n) if Direction::from_token(n).is_some()));
}

// ---------------------------------------------------------------------------
// a=ptime / a=maxptime  (RFC 4566 §6)
// ---------------------------------------------------------------------------

fn parse_value_attr<'a>(attrs: &'a [Attribute], key: &str) -> Option<&'a str> {
    attrs.iter().find_map(|a| match a {
        Attribute::Value { name, value } if name.as_str() == key => Some(value.as_str()),
        _ => None,
    })
}

fn set_value_attr_unique(attrs: &mut Vec<Attribute>, key: &str, value: &str) {
    attrs.retain(|a| !matches!(a, Attribute::Value { name, .. } if name.as_str() == key));
    attrs.push(Attribute::Value {
        name: SmolStr::new(key),
        value: SmolStr::new(value),
    });
}

fn clear_value_attrs(attrs: &mut Vec<Attribute>, key: &str) {
    attrs.retain(|a| !matches!(a, Attribute::Value { name, .. } if name.as_str() == key));
}

// ---------------------------------------------------------------------------
// a=rtpmap:<pt> <encoding>/<clock>[/<params>]  (RFC 4566 §6)
//
// Stand-alone parser used by both the parse-time HashMap derivation
// (lib.rs) and the on-demand accessor here.
// ---------------------------------------------------------------------------

/// One rtpmap entry parsed straight from a raw attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRtpMap {
    pub payload_type: u8,
    pub encoding_name: SmolStr,
    pub clock_rate: u32,
    pub encoding_params: Option<SmolStr>,
}

/// Public re-export of [`parse_rtpmap_value`] for the in-crate
/// `MediaDescription::rebuild_rtpmaps` helper. Not part of the
/// stable surface — prefer [`MediaDescription::rtpmaps_iter`].
pub(crate) fn parse_rtpmap_value_pub(value: &str) -> Option<ParsedRtpMap> {
    parse_rtpmap_value(value)
}

fn parse_rtpmap_value(value: &str) -> Option<ParsedRtpMap> {
    let mut parts = value.splitn(2, ' ');
    let payload_type = parts.next()?.parse::<u8>().ok()?;
    let rest = parts.next()?;
    let mut bits = rest.split('/');
    let encoding_name = SmolStr::new(bits.next()?);
    let clock_rate = bits.next()?.parse::<u32>().ok()?;
    let encoding_params = bits.next().map(SmolStr::new);
    Some(ParsedRtpMap {
        payload_type,
        encoding_name,
        clock_rate,
        encoding_params,
    })
}

// ---------------------------------------------------------------------------
// a=fmtp:<pt> <params>  (RFC 4566 §6)
// ---------------------------------------------------------------------------

/// Format-specific parameters for a payload type.
///
/// `params` is the raw whitespace-separated parameter blob, preserved
/// verbatim — codec parameters often have ad-hoc syntax (key=val pairs
/// for opus, semicolon-separated for H.264, ranges for telephone-event)
/// and we deliberately avoid normalising it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fmtp {
    pub payload_type: u8,
    pub params: SmolStr,
}

fn parse_fmtp_value(value: &str) -> Option<Fmtp> {
    let mut parts = value.splitn(2, ' ');
    let payload_type = parts.next()?.parse::<u8>().ok()?;
    let params = SmolStr::new(parts.next()?.trim());
    Some(Fmtp {
        payload_type,
        params,
    })
}

// ---------------------------------------------------------------------------
// a=candidate:<foundation> <component> <transport> <priority>
//             <connection-address> <port> typ <type>
//             [raddr <address>] [rport <port>] [<extension>...]   (RFC 8839 §5.1)
// ---------------------------------------------------------------------------

/// ICE candidate transport (RFC 8839 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateTransport {
    Udp,
    Tcp,
    Other(SmolStr),
}

impl CandidateTransport {
    fn from_token(token: &str) -> Self {
        match token.to_ascii_lowercase().as_str() {
            "udp" => Self::Udp,
            "tcp" => Self::Tcp,
            _ => Self::Other(SmolStr::new(token)),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// ICE candidate type (RFC 8839 §5.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
    Other(SmolStr),
}

impl CandidateType {
    fn from_token(token: &str) -> Self {
        match token {
            "host" => Self::Host,
            "srflx" => Self::ServerReflexive,
            "prflx" => Self::PeerReflexive,
            "relay" => Self::Relay,
            other => Self::Other(SmolStr::new(other)),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Parsed ICE candidate. `extensions` carries any trailing `key value`
/// pairs verbatim (e.g. `generation 0`, `tcptype passive`, `network-id 1`)
/// so applications can preserve them on round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub foundation: SmolStr,
    pub component: u32,
    pub transport: CandidateTransport,
    pub priority: u32,
    pub connection_address: SmolStr,
    pub port: u16,
    pub typ: CandidateType,
    pub raddr: Option<SmolStr>,
    pub rport: Option<u16>,
    pub extensions: Vec<(SmolStr, SmolStr)>,
}

fn parse_candidate_value(value: &str) -> Option<Candidate> {
    let mut tokens = value.split_whitespace();
    let foundation = SmolStr::new(tokens.next()?);
    let component = tokens.next()?.parse::<u32>().ok()?;
    let transport = CandidateTransport::from_token(tokens.next()?);
    let priority = tokens.next()?.parse::<u32>().ok()?;
    let connection_address = SmolStr::new(tokens.next()?);
    let port = tokens.next()?.parse::<u16>().ok()?;
    if tokens.next()? != "typ" {
        return None;
    }
    let typ = CandidateType::from_token(tokens.next()?);

    let mut raddr = None;
    let mut rport = None;
    let mut extensions = Vec::new();

    while let Some(key) = tokens.next() {
        let val = tokens.next()?;
        match key {
            "raddr" => raddr = Some(SmolStr::new(val)),
            "rport" => rport = Some(val.parse::<u16>().ok()?),
            _ => extensions.push((SmolStr::new(key), SmolStr::new(val))),
        }
    }

    Some(Candidate {
        foundation,
        component,
        transport,
        priority,
        connection_address,
        port,
        typ,
        raddr,
        rport,
        extensions,
    })
}

impl Candidate {
    /// Render back to the canonical `a=candidate:` value form.
    pub fn to_attr_value(&self) -> String {
        let mut out = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport.as_str(),
            self.priority,
            self.connection_address,
            self.port,
            self.typ.as_str(),
        );
        if let Some(ref raddr) = self.raddr {
            out.push_str(&format!(" raddr {}", raddr));
        }
        if let Some(rport) = self.rport {
            out.push_str(&format!(" rport {}", rport));
        }
        for (k, v) in &self.extensions {
            out.push_str(&format!(" {} {}", k, v));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// a=fingerprint:<hash-func> <hex-bytes>            (RFC 8122 §5)
// a=setup:active|passive|actpass|holdconn          (RFC 4145 §4)
// ---------------------------------------------------------------------------

/// DTLS certificate fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash_function: SmolStr,
    pub fingerprint: SmolStr,
}

fn parse_fingerprint_value(value: &str) -> Option<Fingerprint> {
    let mut parts = value.splitn(2, ' ');
    let hash_function = SmolStr::new(parts.next()?);
    let fingerprint = SmolStr::new(parts.next()?.trim());
    Some(Fingerprint {
        hash_function,
        fingerprint,
    })
}

/// DTLS setup attribute (RFC 4145 §4 / RFC 5763 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    Active,
    Passive,
    ActPass,
    HoldConn,
}

impl Setup {
    pub fn as_token(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::ActPass => "actpass",
            Self::HoldConn => "holdconn",
        }
    }

    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "active" => Some(Self::Active),
            "passive" => Some(Self::Passive),
            "actpass" => Some(Self::ActPass),
            "holdconn" => Some(Self::HoldConn),
            _ => None,
        }
    }

    /// Compute the answerer's `setup` value given the offerer's
    /// (RFC 5763 §5).
    ///
    /// Rules:
    ///   * `active` → answer `passive` (only one side initiates DTLS)
    ///   * `passive` → answer `active`
    ///   * `actpass` → answer picks; `active` is the convention so
    ///     the answerer initiates the handshake (faster setup, fewer
    ///     NAT round trips).
    ///   * `holdconn` → echo `holdconn` (connection on hold).
    pub fn answer_for(offer: Setup) -> Setup {
        match offer {
            Setup::Active => Setup::Passive,
            Setup::Passive => Setup::Active,
            Setup::ActPass => Setup::Active,
            Setup::HoldConn => Setup::HoldConn,
        }
    }
}

// ---------------------------------------------------------------------------
// a=mid:<identifier>                             (RFC 5888 §4)
// a=ssrc:<ssrc-id> <attribute>[:<value>]         (RFC 5576 §4.1)
// ---------------------------------------------------------------------------

/// One ssrc attribute. A given SSRC may have multiple lines, one per
/// attribute (e.g. `cname:foo`, `msid:stream-id track-id`,
/// `label:bar`); we surface each line as its own [`Ssrc`] entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssrc {
    pub ssrc_id: u32,
    pub attribute: SmolStr,
    pub value: Option<SmolStr>,
}

fn parse_ssrc_value(value: &str) -> Option<Ssrc> {
    let mut parts = value.splitn(2, ' ');
    let ssrc_id = parts.next()?.parse::<u32>().ok()?;
    let rest = parts.next()?.trim();
    let (attribute, value) = match rest.split_once(':') {
        Some((name, val)) => (SmolStr::new(name), Some(SmolStr::new(val))),
        None => (SmolStr::new(rest), None),
    };
    Some(Ssrc {
        ssrc_id,
        attribute,
        value,
    })
}

// ===========================================================================
// MediaDescription typed accessors
// ===========================================================================

impl MediaDescription {
    /// Returns the explicitly-declared media direction, if any.
    /// Per RFC 4566 §6 the implicit default is `sendrecv` — callers
    /// that want the effective direction can `unwrap_or(Direction::SendRecv)`.
    pub fn direction(&self) -> Option<Direction> {
        direction_from_attrs(&self.attributes)
    }

    /// Set (or replace) the media direction. Removes any prior
    /// direction property to keep the section canonical.
    pub fn set_direction(&mut self, direction: Direction) {
        set_direction(&mut self.attributes, direction);
    }

    /// Remove the explicit direction attribute (falls back to the
    /// `sendrecv` default).
    pub fn clear_direction(&mut self) {
        clear_direction(&mut self.attributes);
    }

    /// Returns the *effective* direction taking RFC 3264 §5.1 hold
    /// conventions into account.
    ///
    /// Resolution order:
    ///   1. If the media-level `c=` line carries `0.0.0.0` (or the
    ///      IPv6 unspecified address `::`), the stream is on hold per
    ///      legacy RFC 2543 — surface it as [`Direction::Inactive`].
    ///   2. Otherwise, return any explicit direction attribute.
    ///   3. Otherwise, fall back to RFC 4566's `SendRecv` default.
    ///
    /// Session-level `c=` lines are intentionally NOT consulted here
    /// — that's a [`SessionDescription`] concern. Callers that need
    /// the absolute effective direction should consult
    /// [`SessionDescription::media_effective_direction`].
    pub fn effective_direction(&self) -> Direction {
        if let Some(conn) = &self.connection {
            if is_unspecified_address(conn.connection_address.as_str()) {
                return Direction::Inactive;
            }
        }
        self.direction().unwrap_or(Direction::SendRecv)
    }

    /// Convenience: true when the remote has placed this stream on
    /// hold from the answerer's perspective. A hold is signalled by
    /// the offerer with `a=sendonly`, `a=inactive`, or the legacy
    /// 0.0.0.0 connection address.
    ///
    /// Note: `recvonly` from the offerer is NOT a hold — it means
    /// the offerer wants to receive media but won't send any (think
    /// listen-only conferencing). The answerer would respond with
    /// `sendonly` and continue sending.
    pub fn is_held_by_remote(&self) -> bool {
        matches!(
            self.effective_direction(),
            Direction::SendOnly | Direction::Inactive
        )
    }

    /// Iterate every parsed `a=rtpmap:` line on this media section.
    /// Reads from the raw attribute vector each call, so it stays
    /// in sync with manual edits to `attributes`.
    pub fn rtpmaps_iter(&self) -> impl Iterator<Item = ParsedRtpMap> + '_ {
        self.attributes.iter().filter_map(|a| match a {
            Attribute::Value { name, value } if name.as_str() == "rtpmap" => {
                parse_rtpmap_value(value.as_str())
            }
            _ => None,
        })
    }

    /// Iterate every parsed `a=fmtp:` line.
    pub fn fmtp_iter(&self) -> impl Iterator<Item = Fmtp> + '_ {
        self.attributes.iter().filter_map(|a| match a {
            Attribute::Value { name, value } if name.as_str() == "fmtp" => {
                parse_fmtp_value(value.as_str())
            }
            _ => None,
        })
    }

    /// Look up the fmtp parameters for a specific payload type.
    pub fn fmtp_for(&self, payload_type: u8) -> Option<Fmtp> {
        self.fmtp_iter().find(|f| f.payload_type == payload_type)
    }

    /// Set (or replace) the fmtp line for `payload_type`. Existing
    /// fmtp lines for the same payload type are removed first; lines
    /// for other payload types are preserved unchanged.
    pub fn set_fmtp(&mut self, payload_type: u8, params: &str) {
        self.attributes.retain(|a| {
            !matches!(
                a,
                Attribute::Value { name, value }
                    if name.as_str() == "fmtp"
                        && value
                            .as_str()
                            .split_whitespace()
                            .next()
                            .and_then(|t| t.parse::<u8>().ok())
                            == Some(payload_type)
            )
        });
        self.attributes.push(Attribute::Value {
            name: SmolStr::new("fmtp"),
            value: SmolStr::new(format!("{} {}", payload_type, params.trim())),
        });
    }

    /// `a=ptime:<ms>` — packet duration hint for audio.
    pub fn ptime(&self) -> Option<u32> {
        parse_value_attr(&self.attributes, "ptime").and_then(|v| v.parse().ok())
    }

    /// Set or replace `a=ptime`.
    pub fn set_ptime(&mut self, ms: u32) {
        set_value_attr_unique(&mut self.attributes, "ptime", &ms.to_string());
    }

    /// Clear `a=ptime` if present.
    pub fn clear_ptime(&mut self) {
        clear_value_attrs(&mut self.attributes, "ptime");
    }

    /// `a=maxptime:<ms>` — upper bound on packet duration.
    pub fn maxptime(&self) -> Option<u32> {
        parse_value_attr(&self.attributes, "maxptime").and_then(|v| v.parse().ok())
    }

    /// Set or replace `a=maxptime`.
    pub fn set_maxptime(&mut self, ms: u32) {
        set_value_attr_unique(&mut self.attributes, "maxptime", &ms.to_string());
    }

    /// Clear `a=maxptime` if present.
    pub fn clear_maxptime(&mut self) {
        clear_value_attrs(&mut self.attributes, "maxptime");
    }

    /// Iterate every parsed `a=candidate:` line.
    pub fn candidates(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.attributes.iter().filter_map(|a| match a {
            Attribute::Value { name, value } if name.as_str() == "candidate" => {
                parse_candidate_value(value.as_str())
            }
            _ => None,
        })
    }

    /// Append a new ICE candidate. Existing candidates are preserved
    /// (a media stream may carry many candidates per ICE policy).
    pub fn add_candidate(&mut self, candidate: &Candidate) {
        self.attributes.push(Attribute::Value {
            name: SmolStr::new("candidate"),
            value: SmolStr::new(candidate.to_attr_value()),
        });
    }

    /// Drop every `a=candidate:` line on this media section.
    pub fn clear_candidates(&mut self) {
        clear_value_attrs(&mut self.attributes, "candidate");
    }

    /// Iterate every parsed `a=fingerprint:` line.
    pub fn fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_ {
        self.attributes.iter().filter_map(|a| match a {
            Attribute::Value { name, value } if name.as_str() == "fingerprint" => {
                parse_fingerprint_value(value.as_str())
            }
            _ => None,
        })
    }

    /// Convenience: first fingerprint (most setups carry exactly one).
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprints().next()
    }

    /// `a=setup:active|passive|actpass|holdconn`.
    pub fn setup(&self) -> Option<Setup> {
        parse_value_attr(&self.attributes, "setup").and_then(Setup::from_token)
    }

    /// Set or replace `a=setup`.
    pub fn set_setup(&mut self, setup: Setup) {
        set_value_attr_unique(&mut self.attributes, "setup", setup.as_token());
    }

    /// `a=mid:<identifier>` — RFC 5888 media identification (BUNDLE).
    pub fn mid(&self) -> Option<&str> {
        parse_value_attr(&self.attributes, "mid")
    }

    /// Set or replace `a=mid`.
    pub fn set_mid(&mut self, mid: &str) {
        set_value_attr_unique(&mut self.attributes, "mid", mid);
    }

    /// Iterate every parsed `a=ssrc:` line.
    pub fn ssrc_iter(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.attributes.iter().filter_map(|a| match a {
            Attribute::Value { name, value } if name.as_str() == "ssrc" => {
                parse_ssrc_value(value.as_str())
            }
            _ => None,
        })
    }
}

// ===========================================================================
// SessionDescription typed accessors
// ===========================================================================

impl SessionDescription {
    /// Session-level direction attribute. Per RFC 4566 §6 a session-level
    /// direction applies to all media sections that don't carry their own.
    pub fn direction(&self) -> Option<Direction> {
        direction_from_attrs(&self.attributes)
    }

    /// Set or replace the session-level direction.
    pub fn set_direction(&mut self, direction: Direction) {
        set_direction(&mut self.attributes, direction);
    }

    /// Remove the session-level direction attribute.
    pub fn clear_direction(&mut self) {
        clear_direction(&mut self.attributes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionDescription;

    fn parse(sdp: &str) -> SessionDescription {
        SessionDescription::parse(sdp).expect("valid SDP")
    }

    fn round_trip(sdp: &SessionDescription) -> SessionDescription {
        SessionDescription::parse(&sdp.serialize()).expect("re-parse must succeed")
    }

    // ----------------------------------------------------------------- Direction

    #[test]
    fn direction_parses_all_four_tokens() {
        for (token, expected) in [
            ("sendrecv", Direction::SendRecv),
            ("sendonly", Direction::SendOnly),
            ("recvonly", Direction::RecvOnly),
            ("inactive", Direction::Inactive),
        ] {
            let sdp = format!(
                "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\nm=audio 9000 RTP/AVP 0\r\na={token}\r\n"
            );
            let parsed = parse(&sdp);
            assert_eq!(parsed.media[0].direction(), Some(expected));
        }
    }

    #[test]
    fn direction_default_is_unspecified() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";
        let parsed = parse(sdp);
        assert_eq!(parsed.media[0].direction(), None);
    }

    #[test]
    fn set_direction_replaces_previous() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=sendrecv\r\n";
        let mut parsed = parse(sdp);
        parsed.media[0].set_direction(Direction::SendOnly);
        let direction_attrs = parsed.media[0]
            .attributes
            .iter()
            .filter(|a| matches!(a, Attribute::Property(n) if Direction::from_token(n).is_some()))
            .count();
        assert_eq!(direction_attrs, 1, "must not accumulate duplicates");
        let reparsed = round_trip(&parsed);
        assert_eq!(reparsed.media[0].direction(), Some(Direction::SendOnly));
    }

    #[test]
    fn set_direction_preserves_unknown_attributes() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 0\r\na=sendrecv\r\na=x-vendor:keep-me\r\n";
        let mut parsed = parse(sdp);
        parsed.media[0].set_direction(Direction::Inactive);
        let serialized = parsed.serialize();
        assert!(
            serialized.contains("a=x-vendor:keep-me"),
            "unknown attribute dropped: {serialized}",
        );
        assert!(serialized.contains("a=inactive"));
        assert!(!serialized.contains("a=sendrecv"));
    }

    // ----------------------------------------------------------------- ptime / maxptime

    #[test]
    fn ptime_round_trip() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 0\r\na=ptime:20\r\na=maxptime:60\r\n";
        let parsed = parse(sdp);
        assert_eq!(parsed.media[0].ptime(), Some(20));
        assert_eq!(parsed.media[0].maxptime(), Some(60));
        let reparsed = round_trip(&parsed);
        assert_eq!(reparsed.media[0].ptime(), Some(20));
        assert_eq!(reparsed.media[0].maxptime(), Some(60));
    }

    #[test]
    fn set_ptime_replaces_previous() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 0\r\na=ptime:20\r\n";
        let mut parsed = parse(sdp);
        parsed.media[0].set_ptime(40);
        assert_eq!(
            parsed.media[0]
                .attributes
                .iter()
                .filter(|a| matches!(a, Attribute::Value { name, .. } if name.as_str() == "ptime"))
                .count(),
            1,
        );
        assert_eq!(parsed.media[0].ptime(), Some(40));
    }

    // ----------------------------------------------------------------- fmtp

    #[test]
    fn fmtp_parses_and_round_trips() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 96 101\r\n\
                   a=rtpmap:96 opus/48000/2\r\n\
                   a=fmtp:96 minptime=10;useinbandfec=1\r\n\
                   a=rtpmap:101 telephone-event/8000\r\n\
                   a=fmtp:101 0-16\r\n";
        let parsed = parse(sdp);
        let opus = parsed.media[0].fmtp_for(96).expect("opus fmtp");
        assert_eq!(opus.params.as_str(), "minptime=10;useinbandfec=1");
        let dtmf = parsed.media[0].fmtp_for(101).expect("dtmf fmtp");
        assert_eq!(dtmf.params.as_str(), "0-16");

        let reparsed = round_trip(&parsed);
        assert_eq!(reparsed, parsed, "fmtp content must round-trip exactly");
    }

    #[test]
    fn set_fmtp_only_replaces_matching_payload_type() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 96 101\r\n\
                   a=fmtp:96 minptime=10\r\n\
                   a=fmtp:101 0-15\r\n";
        let mut parsed = parse(sdp);
        parsed.media[0].set_fmtp(96, "minptime=20;maxaveragebitrate=64000");
        assert_eq!(
            parsed.media[0].fmtp_for(96).map(|f| f.params),
            Some(SmolStr::new("minptime=20;maxaveragebitrate=64000")),
        );
        // PT 101 untouched.
        assert_eq!(
            parsed.media[0].fmtp_for(101).map(|f| f.params),
            Some(SmolStr::new("0-15")),
        );
    }

    // ----------------------------------------------------------------- candidate

    #[test]
    fn candidate_parses_with_extensions() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 UDP/TLS/RTP/SAVPF 0\r\n\
                   a=candidate:1 1 UDP 2130706431 192.168.1.5 9000 typ host generation 0\r\n\
                   a=candidate:2 1 UDP 1694498815 203.0.113.1 9001 typ srflx raddr 192.168.1.5 rport 9000 generation 0\r\n";
        let parsed = parse(sdp);
        let candidates: Vec<_> = parsed.media[0].candidates().collect();
        assert_eq!(candidates.len(), 2);

        assert_eq!(candidates[0].foundation.as_str(), "1");
        assert_eq!(candidates[0].component, 1);
        assert_eq!(candidates[0].typ, CandidateType::Host);
        assert_eq!(candidates[0].connection_address.as_str(), "192.168.1.5");
        assert_eq!(candidates[0].port, 9000);
        assert_eq!(
            candidates[0].extensions,
            vec![(SmolStr::new("generation"), SmolStr::new("0"))]
        );

        assert_eq!(candidates[1].typ, CandidateType::ServerReflexive);
        assert_eq!(candidates[1].raddr.as_deref(), Some("192.168.1.5"));
        assert_eq!(candidates[1].rport, Some(9000));
    }

    #[test]
    fn candidate_to_attr_value_round_trips() {
        let original = "1 1 udp 2130706431 192.168.1.5 9000 typ host generation 0 network-id 1";
        let parsed = parse_candidate_value(original).unwrap();
        assert_eq!(parsed.to_attr_value(), original);
    }

    // ----------------------------------------------------------------- fingerprint / setup

    #[test]
    fn fingerprint_and_setup_parse() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 UDP/TLS/RTP/SAVPF 0\r\n\
                   a=fingerprint:sha-256 AB:CD:EF:01:23:45\r\n\
                   a=setup:actpass\r\n";
        let parsed = parse(sdp);
        let fp = parsed.media[0].fingerprint().expect("fingerprint");
        assert_eq!(fp.hash_function.as_str(), "sha-256");
        assert_eq!(fp.fingerprint.as_str(), "AB:CD:EF:01:23:45");
        assert_eq!(parsed.media[0].setup(), Some(Setup::ActPass));
    }

    #[test]
    fn set_setup_replaces_previous() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 UDP/TLS/RTP/SAVPF 0\r\na=setup:actpass\r\n";
        let mut parsed = parse(sdp);
        parsed.media[0].set_setup(Setup::Active);
        assert_eq!(parsed.media[0].setup(), Some(Setup::Active));
        let reparsed = round_trip(&parsed);
        assert_eq!(reparsed.media[0].setup(), Some(Setup::Active));
    }

    // ----------------------------------------------------------------- mid / ssrc

    #[test]
    fn mid_and_ssrc_parse() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 0\r\n\
                   a=mid:audio0\r\n\
                   a=ssrc:1234567 cname:user@example.com\r\n\
                   a=ssrc:1234567 msid:stream0 track0\r\n\
                   a=ssrc:1234567 label:trackA\r\n";
        let parsed = parse(sdp);
        assert_eq!(parsed.media[0].mid(), Some("audio0"));
        let ssrcs: Vec<_> = parsed.media[0].ssrc_iter().collect();
        assert_eq!(ssrcs.len(), 3);
        assert!(ssrcs.iter().all(|s| s.ssrc_id == 1234567));
        assert_eq!(ssrcs[0].attribute.as_str(), "cname");
        assert_eq!(ssrcs[0].value.as_deref(), Some("user@example.com"));
        assert_eq!(ssrcs[1].attribute.as_str(), "msid");
        assert_eq!(ssrcs[2].attribute.as_str(), "label");
    }

    // ----------------------------------------------------------------- rtpmap

    #[test]
    fn rtpmaps_iter_reads_from_attributes_not_cache() {
        // Force-mutate attributes after parse: the iterator must see the
        // new state, proving it doesn't rely on the precomputed HashMap.
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let mut parsed = parse(sdp);
        parsed.media[0].attributes.push(Attribute::Value {
            name: SmolStr::new("rtpmap"),
            value: SmolStr::new("8 PCMA/8000"),
        });
        let pts: Vec<u8> = parsed.media[0]
            .rtpmaps_iter()
            .map(|r| r.payload_type)
            .collect();
        assert_eq!(pts, vec![0, 8]);
    }

    // ----------------------------------------------------------------- rtpmap mutators

    #[test]
    fn set_rtpmap_replaces_existing_attribute_line() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\n";
        let mut parsed = parse(sdp);
        parsed.media[0]
            .set_rtpmap(96, "opus", 48000, Some("1"))
            .unwrap();

        // Exactly one rtpmap attribute survives, with the new params.
        let rtpmap_lines: Vec<&str> = parsed.media[0]
            .attributes
            .iter()
            .filter_map(|a| match a {
                Attribute::Value { name, value } if name.as_str() == "rtpmap" => {
                    Some(value.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(rtpmap_lines, vec!["96 opus/48000/1"]);
        // Cache reflects the change too.
        assert_eq!(
            parsed.media[0]
                .rtpmaps
                .get(&96)
                .map(|r| r.encoding_params.clone()),
            Some(Some(SmolStr::new("1"))),
        );

        // Round-trip survives.
        let reparsed = round_trip(&parsed);
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn remove_rtpmap_removes_both_cache_and_attribute() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n";
        let mut parsed = parse(sdp);
        assert!(parsed.media[0].remove_rtpmap(0));
        assert!(!parsed.media[0].rtpmaps.contains_key(&0));
        assert_eq!(parsed.media[0].rtpmaps_iter().count(), 1);
        // Returns false when there's nothing to remove.
        assert!(!parsed.media[0].remove_rtpmap(99));
    }

    #[test]
    fn rebuild_rtpmaps_resyncs_after_direct_attribute_mutation() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
                   m=audio 9000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let mut parsed = parse(sdp);
        // Reach into the raw vec and add a new rtpmap.
        parsed.media[0].attributes.push(Attribute::Value {
            name: SmolStr::new("rtpmap"),
            value: SmolStr::new("8 PCMA/8000"),
        });
        // Cache is now stale.
        assert!(!parsed.media[0].rtpmaps.contains_key(&8));
        parsed.media[0].rebuild_rtpmaps();
        assert!(parsed.media[0].rtpmaps.contains_key(&8));
    }

    #[test]
    fn add_rtpmap_dedups_repeated_calls() {
        // Old behavior accumulated duplicate `a=rtpmap:0 ...` lines on
        // each builder call. With dedup, the second call replaces the
        // first cleanly so serialize emits exactly one line.
        let media = MediaDescription::audio(9000)
            .add_format(0)
            .unwrap()
            .add_rtpmap(0, "PCMU", 8000, None)
            .unwrap()
            .add_rtpmap(0, "PCMU", 16000, None)
            .unwrap();
        let rtpmap_lines: Vec<&str> = media
            .attributes
            .iter()
            .filter_map(|a| match a {
                Attribute::Value { name, value } if name.as_str() == "rtpmap" => {
                    Some(value.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            rtpmap_lines,
            vec!["0 PCMU/16000"],
            "duplicate add_rtpmap calls must replace, not accumulate",
        );
    }
}
