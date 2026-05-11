// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Tiny header extractor for the one field HEP3 emission needs:
//! `Call-ID`. Avoids re-parsing the whole SIP message at the
//! transport layer when all we want is the correlation key.
//!
//! Why not delegate to `sip-parse`? Because parse-then-discard the
//! rest is wasted work — at the hook site we already have the raw
//! bytes and just want one header. The scan is O(payload) but bails
//! at the first match.

/// Extract the `Call-ID` value from a SIP message.
///
/// Recognizes both the long form (`Call-ID:`) and the compact form
/// (`i:`) per RFC 3261 §7.3.3. Header names are matched
/// case-insensitively. The returned slice is trimmed of leading
/// whitespace and the trailing CRLF / LF.
///
/// Returns `None` if no `Call-ID` header is found or the buffer
/// doesn't look like a SIP message.
pub fn extract_call_id(payload: &[u8]) -> Option<&str> {
    // SIP message start-line is one line; headers start on line 2.
    // Body (after the empty line) cannot contain headers — bail
    // there to avoid false positives in SDP / message bodies.
    let mut start = 0;
    while start < payload.len() {
        let line_end = find_line_end(payload, start)?;
        let line = &payload[start..line_end];

        // Empty line marks end-of-headers (SDP / body follows).
        if line.is_empty() {
            return None;
        }

        if let Some(value) = match_call_id(line) {
            // Trim leading whitespace + an optional CR if we matched
            // on a LF-only boundary.
            let trimmed = trim_ascii(value);
            return std::str::from_utf8(trimmed).ok();
        }

        start = skip_crlf(payload, line_end);
    }
    None
}

/// True iff `prefix` is an ASCII case-insensitive prefix of `bytes`.
fn starts_with_ci(bytes: &[u8], prefix: &[u8]) -> bool {
    if bytes.len() < prefix.len() {
        return false;
    }
    bytes[..prefix.len()]
        .iter()
        .zip(prefix.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn match_call_id(line: &[u8]) -> Option<&[u8]> {
    // Long form: "Call-ID:" then value.
    if starts_with_ci(line, b"Call-ID:") {
        return Some(&line[b"Call-ID:".len()..]);
    }
    // Compact form: "i:" then value. Has to be a stand-alone header
    // start so we don't false-match on (e.g.) "Identity:".
    if starts_with_ci(line, b"i:") {
        return Some(&line[b"i:".len()..]);
    }
    None
}

fn find_line_end(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < buf.len() {
        // CRLF or bare LF (some loose stacks send just LF — RFC
        // allows the parser to be lenient).
        if buf[i] == b'\n' {
            // If preceded by CR, strip it from the line slice by
            // returning the index of the CR.
            return Some(if i > from && buf[i - 1] == b'\r' {
                i - 1
            } else {
                i
            });
        }
        i += 1;
    }
    None
}

fn skip_crlf(buf: &[u8], line_end: usize) -> usize {
    let mut i = line_end;
    if i < buf.len() && buf[i] == b'\r' {
        i += 1;
    }
    if i < buf.len() && buf[i] == b'\n' {
        i += 1;
    }
    i
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t' || s[end - 1] == b'\r') {
        end -= 1;
    }
    &s[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &[u8] = b"\
INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK77\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: abc-123@10.0.0.1\r\n\
CSeq: 1 INVITE\r\n\
\r\n\
v=0\r\n\
";

    #[test]
    fn extracts_long_form() {
        assert_eq!(extract_call_id(INVITE), Some("abc-123@10.0.0.1"));
    }

    #[test]
    fn extracts_compact_form() {
        let msg: &[u8] = b"INVITE sip:b SIP/2.0\r\ni: short-cid@host\r\n\r\n";
        assert_eq!(extract_call_id(msg), Some("short-cid@host"));
    }

    #[test]
    fn case_insensitive_match() {
        let msg: &[u8] = b"INVITE sip:b SIP/2.0\r\ncALL-id:   cid@x\r\n\r\n";
        assert_eq!(extract_call_id(msg), Some("cid@x"));
    }

    #[test]
    fn handles_lf_only_endings() {
        let msg: &[u8] = b"INVITE sip:b SIP/2.0\nCall-ID: cid@host\n\nbody";
        assert_eq!(extract_call_id(msg), Some("cid@host"));
    }

    #[test]
    fn ignores_call_id_inside_body() {
        // After the blank line we hit the body; even though it
        // textually contains "Call-ID:" it must NOT match.
        let msg: &[u8] = b"INVITE sip:b SIP/2.0\r\n\r\nCall-ID: nope@host\r\n";
        assert_eq!(extract_call_id(msg), None);
    }

    #[test]
    fn missing_header_returns_none() {
        let msg: &[u8] = b"INVITE sip:b SIP/2.0\r\nFrom: <sip:a@b>\r\n\r\n";
        assert_eq!(extract_call_id(msg), None);
    }

    #[test]
    fn doesnt_false_match_on_identity_header() {
        // The compact form is "i:"; ensure "Identity:" doesn't trip
        // the prefix match.
        let msg: &[u8] = b"INVITE sip:b SIP/2.0\r\nIdentity: foo\r\nCall-ID: real-cid@h\r\n\r\n";
        assert_eq!(extract_call_id(msg), Some("real-cid@h"));
    }
}
