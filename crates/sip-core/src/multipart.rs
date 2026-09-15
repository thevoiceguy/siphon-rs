// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Multipart message bodies (RFC 2046 §5.1, as SIP uses them per RFC 5621).
//!
//! A SIP request carries more than one body as `multipart/mixed`: an
//! INVITE with its SDP and a PIDF-LO location object (RFC 6442), or a
//! SIPREC INVITE with SDP and recording metadata (RFC 7866). A part is
//! referred to from a header by its `Content-ID` through a `cid:` URI
//! (RFC 2392), as `Geolocation: <cid:…>` does.
//!
//! [`MultipartBody`] builds a body and its `Content-Type` value, choosing a
//! boundary that occurs in no part, and parses one liberally: LF-only line
//! ends, a preamble and a missing close delimiter are tolerated.
//!
//! # Examples
//!
//! ```
//! use sip_core::multipart::{BodyPart, MultipartBody};
//!
//! let body = MultipartBody::mixed()
//!     .with_part(BodyPart::new("application/sdp", "v=0\r\n").unwrap())
//!     .with_part(
//!         BodyPart::new("application/pidf+xml", "<presence/>")
//!             .unwrap()
//!             .with_content_id("loc@pbx.example")
//!             .unwrap(),
//!     );
//! let content_type = body.content_type();
//! let bytes = body.to_bytes();
//! let parsed = MultipartBody::parse(&content_type, &bytes).unwrap();
//! assert_eq!(parsed.part_by_content_id("loc@pbx.example").unwrap().body(), b"<presence/>".as_slice());
//! ```

use bytes::{Bytes, BytesMut};
use smol_str::SmolStr;
use std::sync::atomic::{AtomicU64, Ordering};

/// The most parts a body may hold, built or parsed.
pub const MAX_PARTS: usize = 16;
/// The longest boundary RFC 2046 allows.
const MAX_BOUNDARY_LENGTH: usize = 70;
/// The longest header value a part may carry.
const MAX_PART_HEADER_LENGTH: usize = 512;

/// Why a multipart body could not be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartError {
    /// The `Content-Type` is not `multipart/*`.
    NotMultipart,
    /// No `boundary` parameter, or one RFC 2046 does not allow.
    InvalidBoundary(String),
    /// A part header value is empty, too long or holds control characters.
    InvalidHeader(String),
    /// More parts than [`MAX_PARTS`].
    TooManyParts,
    /// The body holds no part.
    NoParts,
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMultipart => write!(f, "content type is not multipart"),
            Self::InvalidBoundary(why) => write!(f, "invalid multipart boundary: {}", why),
            Self::InvalidHeader(why) => write!(f, "invalid body part header: {}", why),
            Self::TooManyParts => write!(f, "too many body parts (max {})", MAX_PARTS),
            Self::NoParts => write!(f, "multipart body has no parts"),
        }
    }
}

impl std::error::Error for MultipartError {}

/// One part of a multipart body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyPart {
    /// The full `Content-Type` value, parameters included.
    content_type: SmolStr,
    /// The `Content-ID`, without its angle brackets.
    content_id: Option<SmolStr>,
    /// Other part headers (`Content-Disposition`, …), in order.
    headers: Vec<(SmolStr, SmolStr)>,
    body: Bytes,
}

impl BodyPart {
    /// A part of `content_type` holding `body`.
    pub fn new(
        content_type: impl AsRef<str>,
        body: impl Into<Bytes>,
    ) -> Result<Self, MultipartError> {
        let content_type = content_type.as_ref().trim();
        validate_header_value(content_type)?;
        Ok(Self {
            content_type: SmolStr::new(content_type),
            content_id: None,
            headers: Vec::new(),
            body: body.into(),
        })
    }

    /// Names the part for `cid:` references (RFC 2392); written as
    /// `Content-ID: <id>`.
    pub fn with_content_id(mut self, id: impl AsRef<str>) -> Result<Self, MultipartError> {
        let id = id
            .as_ref()
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>');
        validate_header_value(id)?;
        if id.contains(['<', '>', ' ']) {
            return Err(MultipartError::InvalidHeader(format!(
                "Content-ID {:?} is not an addr-spec",
                id
            )));
        }
        self.content_id = Some(SmolStr::new(id));
        Ok(self)
    }

    /// Adds another part header (`Content-Disposition: render;handling=optional`).
    pub fn with_header(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, MultipartError> {
        let name = name.as_ref().trim();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_graphic() && c != ':') {
            return Err(MultipartError::InvalidHeader(format!(
                "header name {:?}",
                name
            )));
        }
        let value = value.as_ref().trim();
        validate_header_value(value)?;
        self.headers.push((SmolStr::new(name), SmolStr::new(value)));
        Ok(self)
    }

    /// The part's `Content-Type`, parameters included.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// The part's media type without parameters, lower-cased
    /// (`application/pidf+xml`).
    pub fn media_type(&self) -> String {
        media_type_of(&self.content_type)
    }

    /// The part's `Content-ID`, without angle brackets.
    pub fn content_id(&self) -> Option<&str> {
        self.content_id.as_deref()
    }

    /// A part header other than `Content-Type` and `Content-ID`, by name
    /// (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// A multipart body: its subtype, boundary and parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartBody {
    subtype: SmolStr,
    /// Chosen when the body is made and kept clear of every part added, so
    /// [`Self::content_type`] and [`Self::to_bytes`] always agree.
    boundary: SmolStr,
    parts: Vec<BodyPart>,
}

impl MultipartBody {
    /// An empty `multipart/mixed` body.
    pub fn mixed() -> Self {
        Self {
            subtype: SmolStr::new_static("mixed"),
            boundary: fresh_boundary(&[]),
            parts: Vec::new(),
        }
    }

    /// Adds a part. Parts past [`MAX_PARTS`] are refused by [`Self::push`];
    /// this builder form drops them silently, so prefer `push` for input
    /// that is not your own.
    pub fn with_part(mut self, part: BodyPart) -> Self {
        let _ = self.push(part);
        self
    }

    /// Adds a part, choosing a new boundary if this part contains the
    /// current one.
    pub fn push(&mut self, part: BodyPart) -> Result<(), MultipartError> {
        if self.parts.len() >= MAX_PARTS {
            return Err(MultipartError::TooManyParts);
        }
        let collides = contains(&part.body, format!("--{}", self.boundary).as_bytes());
        self.parts.push(part);
        if collides {
            self.boundary = fresh_boundary(&self.parts);
        }
        Ok(())
    }

    /// Uses `boundary`, which must be valid and occur in no part.
    pub fn with_boundary(mut self, boundary: &str) -> Result<Self, MultipartError> {
        validate_boundary(boundary)?;
        let delimiter = format!("--{}", boundary);
        if self
            .parts
            .iter()
            .any(|p| contains(&p.body, delimiter.as_bytes()))
        {
            return Err(MultipartError::InvalidBoundary(format!(
                "{:?} occurs in a part",
                boundary
            )));
        }
        self.boundary = SmolStr::new(boundary);
        Ok(self)
    }

    pub fn parts(&self) -> &[BodyPart] {
        &self.parts
    }

    /// The first part of `media_type` (compared without parameters,
    /// case-insensitively).
    pub fn part_by_type(&self, media_type: &str) -> Option<&BodyPart> {
        let wanted = media_type.to_ascii_lowercase();
        self.parts.iter().find(|p| p.media_type() == wanted)
    }

    /// The part a `cid:` URI (or bare Content-ID) names.
    pub fn part_by_content_id(&self, id: &str) -> Option<&BodyPart> {
        let id = id
            .trim()
            .trim_start_matches("cid:")
            .trim_start_matches('<')
            .trim_end_matches('>');
        self.parts.iter().find(|p| p.content_id() == Some(id))
    }

    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// The `Content-Type` value for this body (`multipart/mixed;boundary=…`).
    pub fn content_type(&self) -> String {
        format!("multipart/{};boundary={}", self.subtype, self.boundary)
    }

    /// The body as it goes on the wire.
    pub fn to_bytes(&self) -> Bytes {
        let boundary = self.boundary.as_bytes();
        let mut out = BytesMut::new();
        for part in &self.parts {
            out.extend_from_slice(b"--");
            out.extend_from_slice(boundary);
            out.extend_from_slice(b"\r\nContent-Type: ");
            out.extend_from_slice(part.content_type.as_bytes());
            out.extend_from_slice(b"\r\n");
            if let Some(id) = &part.content_id {
                out.extend_from_slice(b"Content-ID: <");
                out.extend_from_slice(id.as_bytes());
                out.extend_from_slice(b">\r\n");
            }
            for (name, value) in &part.headers {
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(value.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(&part.body);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(boundary);
        out.extend_from_slice(b"--\r\n");
        out.freeze()
    }

    /// Parses a `multipart/*` body given its `Content-Type` value.
    pub fn parse(content_type: &str, body: &[u8]) -> Result<Self, MultipartError> {
        let media = media_type_of(content_type);
        let Some(subtype) = media.strip_prefix("multipart/") else {
            return Err(MultipartError::NotMultipart);
        };
        let boundary = content_type
            .split(';')
            .skip(1)
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("boundary"))
            .map(|(_, v)| v.trim().trim_matches('"').to_string())
            .ok_or_else(|| MultipartError::InvalidBoundary("missing".into()))?;
        validate_boundary(&boundary)?;

        let delimiter = format!("--{}", boundary).into_bytes();
        let mut parts = Vec::new();
        let Some(first) = find(body, &delimiter) else {
            return Err(MultipartError::NoParts);
        };
        let mut rest = &body[first + delimiter.len()..];
        loop {
            if rest.starts_with(b"--") {
                break; // the close delimiter
            }
            // The rest of the delimiter line (transport padding allowed).
            let Some(line_end) = find(rest, b"\n") else {
                break;
            };
            rest = &rest[line_end + 1..];
            let Some(next) = find(rest, &delimiter) else {
                break; // no close delimiter: keep what was complete
            };
            let mut part = &rest[..next];
            // The line break before a delimiter belongs to the delimiter.
            if part.ends_with(b"\r\n") {
                part = &part[..part.len() - 2];
            } else if part.ends_with(b"\n") {
                part = &part[..part.len() - 1];
            }
            if parts.len() >= MAX_PARTS {
                return Err(MultipartError::TooManyParts);
            }
            parts.push(parse_part(part));
            rest = &rest[next + delimiter.len()..];
        }
        if parts.is_empty() {
            return Err(MultipartError::NoParts);
        }
        Ok(Self {
            subtype: SmolStr::new(subtype),
            boundary: SmolStr::new(boundary),
            parts,
        })
    }
}

/// A boundary that occurs in none of `parts`.
fn fresh_boundary(parts: &[BodyPart]) -> SmolStr {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default();
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("siphon-{:016x}-{:x}", seed, n);
        let delimiter = format!("--{}", candidate);
        if !parts
            .iter()
            .any(|p| contains(&p.body, delimiter.as_bytes()))
        {
            return SmolStr::new(candidate);
        }
    }
}

fn parse_part(part: &[u8]) -> BodyPart {
    let (head, body) = if let Some(at) = find(part, b"\r\n\r\n") {
        (&part[..at], &part[at + 4..])
    } else if let Some(at) = find(part, b"\n\n") {
        (&part[..at], &part[at + 2..])
    } else if let Some(stripped) = part.strip_prefix(b"\r\n") {
        (&part[..0], stripped)
    } else if let Some(stripped) = part.strip_prefix(b"\n") {
        (&part[..0], stripped)
    } else {
        (&part[..0], part)
    };
    // RFC 2046 §5.1: a part without Content-Type is text/plain.
    let mut parsed = BodyPart {
        content_type: SmolStr::new_static("text/plain"),
        content_id: None,
        headers: Vec::new(),
        body: Bytes::copy_from_slice(body),
    };
    for line in String::from_utf8_lossy(head).lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        match name.to_ascii_lowercase().as_str() {
            "content-type" | "c" => parsed.content_type = SmolStr::new(value),
            "content-id" => {
                parsed.content_id = Some(SmolStr::new(
                    value.trim_start_matches('<').trim_end_matches('>'),
                ))
            }
            _ => {
                if parsed.headers.len() < MAX_PARTS {
                    parsed
                        .headers
                        .push((SmolStr::new(name), SmolStr::new(value)));
                }
            }
        }
    }
    parsed
}

/// A `Content-Type` value's media type, lower-cased, without parameters.
fn media_type_of(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn validate_header_value(value: &str) -> Result<(), MultipartError> {
    if value.is_empty() {
        return Err(MultipartError::InvalidHeader("empty".into()));
    }
    if value.len() > MAX_PART_HEADER_LENGTH {
        return Err(MultipartError::InvalidHeader("too long".into()));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(MultipartError::InvalidHeader(
            "contains control characters".into(),
        ));
    }
    Ok(())
}

/// RFC 2046 §5.1.1: 1–70 `bchars`, not ending in a space.
fn validate_boundary(boundary: &str) -> Result<(), MultipartError> {
    if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_LENGTH {
        return Err(MultipartError::InvalidBoundary(format!(
            "length {}",
            boundary.len()
        )));
    }
    let bchar = |c: char| c.is_ascii_alphanumeric() || "'()+_,-./:=? ".contains(c);
    if !boundary.chars().all(bchar) || boundary.ends_with(' ') {
        return Err(MultipartError::InvalidBoundary(format!("{:?}", boundary)));
    }
    Ok(())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDP: &str = "v=0\r\no=- 1 1 IN IP4 10.0.0.5\r\ns=-\r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";

    fn located() -> MultipartBody {
        MultipartBody::mixed()
            .with_part(BodyPart::new("application/sdp", SDP).unwrap())
            .with_part(
                BodyPart::new("application/pidf+xml", "<presence entity=\"pres:a@b\"/>")
                    .unwrap()
                    .with_content_id("<loc-1@pbx.example>")
                    .unwrap()
                    .with_header("Content-Disposition", "render;handling=optional")
                    .unwrap(),
            )
    }

    #[test]
    fn a_built_body_parses_back() {
        let body = located();
        let content_type = body.content_type();
        assert!(content_type.starts_with("multipart/mixed;boundary=siphon-"));
        let bytes = body.to_bytes();
        let parsed = MultipartBody::parse(&content_type, &bytes).unwrap();
        assert_eq!(parsed.parts().len(), 2);
        assert_eq!(
            parsed.part_by_type("application/sdp").unwrap().body(),
            SDP.as_bytes()
        );
        let pidf = parsed.part_by_content_id("cid:loc-1@pbx.example").unwrap();
        assert_eq!(pidf.media_type(), "application/pidf+xml");
        assert_eq!(
            pidf.header("content-disposition"),
            Some("render;handling=optional")
        );
        assert_eq!(parsed.to_bytes(), bytes, "writing a parsed body is stable");
    }

    #[test]
    fn the_boundary_never_occurs_in_a_part() {
        let mut body = located();
        let first = body.boundary().to_string();
        body.push(BodyPart::new("text/plain", format!("--{}\r\n", first)).unwrap())
            .unwrap();
        assert_ne!(
            body.boundary(),
            first,
            "a colliding part moves the boundary"
        );
        let delimiter = format!("--{}", body.boundary());
        assert!(body.parts().iter().all(|p| !p
            .body()
            .windows(delimiter.len())
            .any(|w| w == delimiter.as_bytes())));
        assert_eq!(
            MultipartBody::parse(&body.content_type(), &body.to_bytes())
                .unwrap()
                .parts()
                .len(),
            3
        );
        assert!(located().with_boundary(&first).is_ok());
        assert!(body.clone().with_boundary(&first).is_err());
    }

    #[test]
    fn rfc_5621_style_bodies_parse_liberally() {
        // Quoted boundary, preamble, LF line ends, headerless part.
        let body = b"preamble\n--b1\nContent-Type: application/sdp\n\nv=0\n--b1\n\nhello\n--b1--\n";
        let parsed = MultipartBody::parse("Multipart/Mixed; boundary=\"b1\"", body).unwrap();
        assert_eq!(parsed.parts()[0].body(), b"v=0");
        assert_eq!(parsed.parts()[1].media_type(), "text/plain");
        assert_eq!(parsed.parts()[1].body(), b"hello");
        // No close delimiter: complete parts are kept.
        let cut = b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b\r\nContent-Type: text/plain\r\n\r\ntrunc";
        assert_eq!(
            MultipartBody::parse("multipart/mixed;boundary=b", cut)
                .unwrap()
                .parts()
                .len(),
            1
        );
    }

    #[test]
    fn bad_input_is_refused() {
        assert_eq!(
            MultipartBody::parse("application/sdp", SDP.as_bytes()),
            Err(MultipartError::NotMultipart)
        );
        assert!(matches!(
            MultipartBody::parse("multipart/mixed", b"--x\r\n\r\nhi\r\n--x--"),
            Err(MultipartError::InvalidBoundary(_))
        ));
        assert!(matches!(
            MultipartBody::parse(&format!("multipart/mixed;boundary={}", "x".repeat(71)), b""),
            Err(MultipartError::InvalidBoundary(_))
        ));
        assert_eq!(
            MultipartBody::parse("multipart/mixed;boundary=x", b"no delimiter"),
            Err(MultipartError::NoParts)
        );
        assert!(BodyPart::new("application/sdp\r\nX-Injected: 1", "").is_err());
        assert!(BodyPart::new("text/plain", "")
            .unwrap()
            .with_content_id("a b")
            .is_err());
        let mut many = MultipartBody::mixed();
        for _ in 0..MAX_PARTS {
            many.push(BodyPart::new("text/plain", "x").unwrap())
                .unwrap();
        }
        assert_eq!(
            many.push(BodyPart::new("text/plain", "x").unwrap()),
            Err(MultipartError::TooManyParts)
        );
    }

    /// The fuzz target's property, over generated bodies: parsing never
    /// panics, and a parsed body written again parses to the same parts.
    #[test]
    fn generated_bodies_parse_and_rewrite() {
        const PIECES: [&str; 12] = [
            "--b",
            "--b--",
            "\r\n",
            "\n",
            "Content-Type: application/sdp",
            "Content-ID: <x@y>",
            "C: text/plain",
            "v=0",
            ":",
            "X-Other: 1",
            " ",
            "<>",
        ];
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5000 {
            let len = (next() % 24) as usize;
            let body: String = (0..len)
                .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
                .collect();
            if let Ok(parsed) = MultipartBody::parse("multipart/mixed;boundary=b", body.as_bytes())
            {
                let again = MultipartBody::parse(&parsed.content_type(), &parsed.to_bytes())
                    .unwrap_or_else(|e| panic!("{body:?} rewrote unparsably: {e}"));
                assert_eq!(again.parts().len(), parsed.parts().len(), "{body:?}");
            }
        }
    }
}
