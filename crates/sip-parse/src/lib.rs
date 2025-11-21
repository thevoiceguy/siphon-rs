use bytes::{Bytes, BytesMut};
use sip_core::{
    is_valid_branch, Headers, Method, Request, RequestLine, Response, Uri, SipVersion,
    StatusLine,
};
use smol_str::SmolStr;

mod header_values;

pub use header_values::{
    parse_allow_header, parse_authorization_header, parse_call_info_header,
    parse_call_info_headers, parse_contact_header, parse_date_header, parse_event_header,
    parse_from_header, parse_geolocation_error, parse_geolocation_header,
    parse_geolocation_routing, parse_history_info, parse_mime_type, parse_min_se,
    parse_p_access_network_info, parse_p_asserted_identity, parse_p_preferred_identity,
    parse_p_visited_network_id, parse_path, parse_priority_header,
    parse_proxy_authorization_header, parse_rack_header, parse_reason_header,
    parse_resource_priority, parse_route_header, parse_route_headers, parse_rseq_header, parse_sdp,
    parse_service_route, parse_session_expires, parse_sip_etag, parse_subject_header,
    parse_subscription_state, parse_supported_header, parse_to_header, parse_via_header,
};

/// Convenience re-export for decrementing Max-Forwards safely.
pub use sip_core::decrement_max_forwards;

pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Parses a SIP request from raw network bytes.
pub fn parse_request(datagram: &Bytes) -> Option<Request> {
    parse_request_with_limit(datagram, DEFAULT_MAX_MESSAGE_SIZE)
}

/// Parses a SIP request with an explicit max size check.
pub fn parse_request_with_limit(datagram: &Bytes, max_size: usize) -> Option<Request> {
    if datagram.len() > max_size {
        return None;
    }
    let (head, body_bytes) = split_head_body(datagram)?;
    let mut lines = head.split("\r\n");
    let first = lines.next()?.trim();
    if first.is_empty() {
        return None;
    }

    let (method, uri) = parse_request_line(first)?;
    let headers = parse_headers(lines)?;
    if let Some(via) = headers.get("Via") {
        if let Some(branch) = via
            .split(';')
            .find_map(|p| p.trim().strip_prefix("branch="))
        {
            if !is_valid_branch(branch.trim()) {
                return None;
            }
        }
    }
    let body = extract_body(body_bytes, &headers)?;
    if !cseq_matches(&headers, method)? {
        return None;
    }

    Some(Request::new(
        RequestLine {
            method,
            uri,
            version: SipVersion::V2,
        },
        headers,
        body,
    ))
}

/// Parses a SIP response from raw network bytes.
pub fn parse_response(datagram: &Bytes) -> Option<Response> {
    if datagram.len() > DEFAULT_MAX_MESSAGE_SIZE {
        return None;
    }
    let (head, body_bytes) = split_head_body(datagram)?;
    let mut lines = head.split("\r\n");
    let first = lines.next()?.trim();
    if first.is_empty() {
        return None;
    }

    let status = parse_status_line(first)?;
    let headers = parse_headers(lines)?;
    let body = extract_body(body_bytes, &headers)?;

    Some(Response::new(status, headers, body))
}

/// Serializes a SIP request while normalising the `Content-Length` header.
pub fn serialize_request(req: &Request) -> Bytes {
    let mut buf = String::new();
    use std::fmt::Write;

    let _ = write!(
        buf,
        "{} {} {}\r\n",
        req.start.method.as_str(),
        req.start.uri.as_str(),
        req.start.version.as_str()
    );

    let mut has_max_forwards = false;
    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        if header.name.eq_ignore_ascii_case("Max-Forwards") {
            has_max_forwards = true;
        }
        let name = canonical_name(&header.name);
        let value = header.value.trim();
        let _ = write!(buf, "{}: {}\r\n", name, value);
    }

    if !has_max_forwards {
        let _ = write!(buf, "Max-Forwards: 70\r\n");
    }

    let _ = write!(buf, "Content-Length: {}\r\n", req.body.len());

    buf.push_str("\r\n");

    let mut out = BytesMut::with_capacity(buf.len() + req.body.len());
    out.extend_from_slice(buf.as_bytes());
    out.extend_from_slice(req.body.as_ref());
    out.freeze()
}

/// Serializes a SIP response while normalising the `Content-Length` header.
pub fn serialize_response(res: &sip_core::Response) -> Bytes {
    let mut buf = String::new();
    use std::fmt::Write;

    let _ = write!(
        buf,
        "{} {} {}\r\n",
        res.start.version.as_str(),
        res.start.code,
        res.start.reason
    );

    for header in res.headers.iter() {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        let _ = write!(buf, "{}: {}\r\n", header.name, header.value);
    }

    let _ = write!(buf, "Content-Length: {}\r\n", res.body.len());

    buf.push_str("\r\n");

    let mut out = BytesMut::with_capacity(buf.len() + res.body.len());
    out.extend_from_slice(buf.as_bytes());
    out.extend_from_slice(res.body.as_ref());
    out.freeze()
}

/// Parses the request-line into a method and request URI.
/// Supports both SIP/SIPS URIs and tel URIs per RFC 3966.
fn parse_request_line(line: &str) -> Option<(Method, Uri)> {
    use nom::{
        bytes::complete::take_while1,
        character::complete::space1,
        combinator::rest,
        sequence::tuple,
    };

    let mut parser = tuple((
        take_while1::<_, _, nom::error::Error<_>>(is_token_char),
        space1::<_, nom::error::Error<_>>,
        take_while1::<_, _, nom::error::Error<_>>(is_uri_char),
        space1::<_, nom::error::Error<_>>,
        rest::<_, nom::error::Error<_>>,
    ));
    let (_, (method_token, _, uri_token, _, version_token)) = parser(line.trim()).ok()?;

    if !version_token.eq_ignore_ascii_case("SIP/2.0") {
        return None;
    }
    let method = detect_method(method_token)?;
    // Use Uri::parse to support both SIP and tel URIs
    let uri = Uri::parse(uri_token)?;
    Some((method, uri))
}

/// Parses the status-line of a SIP response.
fn parse_status_line(line: &str) -> Option<StatusLine> {
    use nom::{
        bytes::complete::tag_no_case,
        character::complete::{space1, u16 as nom_u16},
        combinator::rest,
        sequence::tuple,
    };

    let mut parser = tuple((
        tag_no_case::<_, _, nom::error::Error<_>>("SIP/2.0"),
        space1::<_, nom::error::Error<_>>,
        nom_u16::<_, nom::error::Error<_>>,
        space1::<_, nom::error::Error<_>>,
        rest::<_, nom::error::Error<_>>,
    ));
    let (_, (_, _, code, _, reason)) = parser(line.trim()).ok()?;

    Some(StatusLine {
        version: SipVersion::V2,
        code,
        reason: SmolStr::new(reason.trim().to_owned()),
    })
}

/// Maps an uppercase method token to the [`Method`] enum.
pub(crate) fn detect_method(token: &str) -> Option<Method> {
    match token {
        "OPTIONS" => Some(Method::Options),
        "INVITE" => Some(Method::Invite),
        "ACK" => Some(Method::Ack),
        "BYE" => Some(Method::Bye),
        "CANCEL" => Some(Method::Cancel),
        "REGISTER" => Some(Method::Register),
        "INFO" => Some(Method::Info),
        "UPDATE" => Some(Method::Update),
        "MESSAGE" => Some(Method::Message),
        "PRACK" => Some(Method::Prack),
        "REFER" => Some(Method::Refer),
        "SUBSCRIBE" => Some(Method::Subscribe),
        "NOTIFY" => Some(Method::Notify),
        "PUBLISH" => Some(Method::Publish),
        _ => None,
    }
}

/// Returns the first header value matching `name` (case insensitive).
pub fn header<'a>(headers: &'a Headers, name: &str) -> Option<&'a SmolStr> {
    let canonical = canonical_header_name(name);
    headers
        .get(name)
        .or_else(|| headers.get(canonical.as_str()))
}

/// Splits raw bytes into header text and body slice using the `\r\n\r\n` separator.
fn split_head_body(datagram: &Bytes) -> Option<(&str, &[u8])> {
    let data = datagram.as_ref();
    let delim = b"\r\n\r\n";

    if let Some(pos) = data.windows(delim.len()).position(|window| window == delim) {
        let head = std::str::from_utf8(&data[..pos]).ok()?;
        let body = &data[pos + delim.len()..];
        Some((head, body))
    } else {
        let head = std::str::from_utf8(data).ok()?;
        Some((head, &[]))
    }
}

/// Parses SIP headers, handling folded continuation lines per RFC 3261 §7.3.1.
fn parse_headers<'a, I>(lines: I) -> Option<Headers>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut headers = Headers::new();
    let mut current_name: Option<SmolStr> = None;
    let mut current_value = String::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            let value = line.trim();
            if value.is_empty() {
                continue;
            }
            if current_name.is_none() {
                return None;
            }
            if !current_value.is_empty() {
                current_value.push(' ');
            }
            current_value.push_str(value);
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            if let Some(prev_name) = current_name.take() {
                headers.push(prev_name, SmolStr::new(current_value.trim().to_owned()));
                current_value.clear();
            }
            current_name = Some(canonical_header_name(name.trim()));
            current_value = value.trim().to_owned();
        } else if current_name.is_some() {
            let value = line.trim();
            if !value.is_empty() {
                if !current_value.is_empty() {
                    current_value.push(' ');
                }
                current_value.push_str(value);
            }
        }
    }

    if let Some(name) = current_name.take() {
        headers.push(name, SmolStr::new(current_value.trim().to_owned()));
    }

    Some(headers)
}

fn canonical_header_name(name: &str) -> SmolStr {
    let lower = name.to_ascii_lowercase();
    let canonical = match lower.as_str() {
        "i" => "Call-ID",
        "f" => "From",
        "t" => "To",
        "m" => "Contact",
        "l" => "Content-Length",
        "s" => "Subject",
        "k" => "Supported",
        "o" => "Event",
        "e" => "Content-Encoding",
        "c" => "Content-Type",
        "v" => "Via",
        "r" => "Refer-To",
        "b" => "Referred-By",
        "d" => "Request-Disposition",
        "x" => "Session-Expires",
        "a" => "Accept-Contact",
        "u" => "Allow-Events",
        _ => name,
    };
    SmolStr::new(canonical.to_owned())
}

/// Returns the body truncated to the declared `Content-Length`, or [`None`] if shorter.
fn extract_body(body_bytes: &[u8], headers: &Headers) -> Option<Bytes> {
    let declared = content_length(headers).unwrap_or(body_bytes.len());
    if declared > body_bytes.len() {
        return None;
    }
    Some(Bytes::copy_from_slice(&body_bytes[..declared]))
}

/// Reads the `Content-Length` header, ignoring invalid values.
fn content_length(headers: &Headers) -> Option<usize> {
    headers
        .get("Content-Length")
        .and_then(|value| value.trim().parse::<usize>().ok())
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.'
                | '^' | '_' | '`' | '|' | '~'
        )
}

// Permissive URI character set: stop at whitespace.
fn is_uri_char(c: char) -> bool {
    !c.is_whitespace()
}

fn cseq_matches(headers: &Headers, method: Method) -> Option<bool> {
    let cseq = match headers.get("CSeq") {
        Some(v) => v,
        None => return Some(true),
    };
    let mut parts = cseq.split_whitespace();
    let _number = parts.next()?;
    let m = parts.next().unwrap_or("");
    Some(detect_method(m)? == method)
}

fn canonical_name(name: &SmolStr) -> SmolStr {
    if name.eq_ignore_ascii_case("Via") {
        SmolStr::new("Via")
    } else if name.eq_ignore_ascii_case("Contact") {
        SmolStr::new("Contact")
    } else if name.eq_ignore_ascii_case("Route") {
        SmolStr::new("Route")
    } else if name.eq_ignore_ascii_case("Record-Route") {
        SmolStr::new("Record-Route")
    } else {
        name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prelude::*, string::string_regex};
    use sip_core::{
        Headers, PriorityValue, RefresherRole, Response, SipUri, StatusLine, SubscriptionState,
    };
    use smol_str::SmolStr;

    use crate::{
        parse_geolocation_error, parse_geolocation_routing, parse_history_info,
        parse_p_access_network_info, parse_p_asserted_identity, parse_p_preferred_identity,
        parse_p_visited_network_id, parse_path, parse_reason_header, parse_service_route,
        parse_sip_etag,
    };

    fn sample_request_bytes() -> Bytes {
        Bytes::from_static(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=123\r\n\
Call-ID: abc123\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n",
        )
    }

    fn sample_response_bytes() -> Bytes {
        Bytes::from_static(
            b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/TCP host;branch=z9hG4bK\r\n\
To: <sip:bob@example.com>;tag=321\r\n\
From: <sip:alice@example.com>;tag=123\r\n\
Call-ID: abc123\r\n\
CSeq: 1 OPTIONS\r\n\
Contact: \"Alice\" <sip:alice@example.com>;expires=60\r\n\
Record-Route: <sip:proxy1.example.com;lr>\r\n\
Service-Route: <sip:service.example.com>\r\n\
Path: <sip:path.example.com>\r\n\
History-Info: <sip:callee@example.com>;index=1\r\n\
Geolocation: <sip:geo@example.com>;purpose=emergency\r\n\
Geolocation-Error: 100;reason=\"Failure\"\r\n\
Geolocation-Routing: yes;accept=yes\r\n\
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0000\r\n\
P-Visited-Network-ID: \"example.com\",example.net\r\n\
P-Asserted-Identity: <sip:alice@example.com>\r\n\
P-Preferred-Identity: <sip:alice@example.com>\r\n\
RAck: 2000 1 INVITE\r\n\
RSeq: 2000\r\n\
Session-Expires: 90;refresher=uac\r\n\
Min-SE: 60\r\n\
Resource-Priority: drs.5, drs.4\r\n\
Event: dialog;id=123\r\n\
Subscription-State: active;expires=10\r\n\
Reason: Q.850;cause=16;text=\"Normal call clearing\"\r\n\
SIP-ETag: abc123\r\n\
Content-Type: application/sdp; charset=utf-8\r\n\
Content-Length: 44\r\n\r\n\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=call\r\n\
t=0 0",
        )
    }

    #[test]
    fn parses_basic_request() {
        let req = parse_request(&sample_request_bytes()).expect("parse");
        assert_eq!(req.start.method, Method::Options);
        assert_eq!(req.start.uri.as_str(), "sip:example.com");
        assert_eq!(
            header(&req.headers, "via").unwrap().as_str(),
            "SIP/2.0/UDP host;branch=z9hG4bK"
        );
        assert_eq!(
            header(&req.headers, "to").unwrap().as_str(),
            "<sip:bob@example.com>"
        );
        assert_eq!(
            header(&req.headers, "from").unwrap().as_str(),
            "<sip:alice@example.com>;tag=123"
        );
        assert_eq!(header(&req.headers, "call-id").unwrap().as_str(), "abc123");
        assert_eq!(header(&req.headers, "cseq").unwrap().as_str(), "1 OPTIONS");
        assert_eq!(header(&req.headers, "max-forwards").unwrap().as_str(), "70");
    }

    #[test]
    fn roundtrip_serialization_preserves_headers() {
        let req = parse_request(&sample_request_bytes()).expect("parse");
        let serialized = serialize_request(&req);
        let reparsed = parse_request(&serialized).expect("reparse");

        for name in ["Via", "To", "From", "Call-ID", "CSeq", "Max-Forwards"] {
            assert_eq!(
                header(&req.headers, name).map(|h| h.as_str()),
                header(&reparsed.headers, name).map(|h| h.as_str()),
                "header {name} mismatch"
            );
        }
    }

    #[test]
    fn roundtrip_response_serialization_preserves_headers() {
        let resp = parse_response(&sample_response_bytes()).expect("parse");
        let serialized = serialize_response(&resp);
        let reparsed = parse_response(&serialized).expect("reparse");

        for name in ["Via", "To", "From", "Call-ID", "CSeq", "Contact"] {
            assert_eq!(
                header(&resp.headers, name).map(|h| h.as_str()),
                header(&reparsed.headers, name).map(|h| h.as_str()),
                "header {name} mismatch"
            );
        }
    }

    #[test]
    fn parses_folded_header_lines() {
        let raw = Bytes::from_static(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK\r\n\
Subject: first line\r\n\
\tsecond line\r\n\
 max forwards\r\n\
Content-Length: 0\r\n\r\n",
        );

        let req = parse_request(&raw).expect("parse");
        let subject = header(&req.headers, "Subject").expect("subject");
        assert_eq!(subject.as_str(), "first line second line max forwards");
    }

    #[test]
    fn preserves_repeated_headers() {
        let raw = Bytes::from_static(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
Record-Route: <sip:proxy1.example.com>\r\n\
Record-Route: <sip:proxy2.example.com>\r\n\
Max-Forwards: 70\r\n\
CSeq: 1 INVITE\r\n\
From: <sip:alice@example.com>;tag=123\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: abc123\r\n\
Content-Length: 0\r\n\r\n",
        );

        let req = parse_request(&raw).expect("parse");
        let routes: Vec<&str> = req
            .headers
            .get_all("record-route")
            .map(|v| v.as_str())
            .collect();
        assert_eq!(routes.len(), 2);
        assert_eq!(
            routes,
            vec!["<sip:proxy1.example.com>", "<sip:proxy2.example.com>"]
        );
    }

    #[test]
    fn parse_request_truncates_extra_body_bytes() {
        let raw = Bytes::from_static(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Content-Length: 4\r\n\r\n\
bodyEXTRA",
        );
        let req = parse_request(&raw).expect("parse");
        assert_eq!(req.body.as_ref(), b"body");
    }

    #[test]
    fn parse_request_fails_when_body_too_short() {
        let raw = Bytes::from_static(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Content-Length: 10\r\n\r\n\
body",
        );
        assert!(parse_request(&raw).is_none());
    }

    #[test]
    fn canonicalizes_compact_header_names() {
        let raw = Bytes::from_static(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
f: <sip:alice@example.com>;tag=1\r\n\
t: <sip:bob@example.com>\r\n\
m: <sip:alice@example.com>\r\n\
k: 100rel, timer\r\n\
l: 0\r\n\r\n",
        );
        let req = parse_request(&raw).expect("parse");
        assert!(req.headers.iter().any(|h| h.name == "From"));
        assert!(req.headers.iter().any(|h| h.name == "To"));
        assert!(req.headers.iter().any(|h| h.name == "Contact"));

        let from = parse_from_header(header(&req.headers, "From").unwrap()).expect("from");
        assert!(from.tag().is_some());
        let contact =
            parse_contact_header(header(&req.headers, "Contact").unwrap()).expect("contact");
        assert_eq!(contact.uri().as_str(), "sip:alice@example.com");

        let supported = parse_supported_header(header(&req.headers, "Supported").unwrap());
        assert_eq!(supported.tokens().len(), 2);

        let allow = parse_allow_header(&SmolStr::new("INVITE, ACK, CANCEL"));
        let allow_tokens: Vec<&str> = allow.tokens().iter().map(|s| s.as_str()).collect();
        assert_eq!(allow_tokens, vec!["INVITE", "ACK", "CANCEL"]);

        let call_info = parse_call_info_header(&SmolStr::new("<sip:info@example.com>")).unwrap();
        assert_eq!(call_info.inner().uri.as_str(), "sip:info@example.com");

        let mut call_info_headers = Headers::new();
        call_info_headers.push(
            SmolStr::new("Call-Info"),
            SmolStr::new("<sip:info@example.com>"),
        );
        let infos = parse_call_info_headers(&call_info_headers);
        assert_eq!(infos.len(), 1);
    }

    #[test]
    fn parses_contact_route_and_via_headers() {
        let resp = parse_response(&sample_response_bytes()).expect("parse");
        let via = parse_via_header(header(&resp.headers, "Via").unwrap()).expect("via");
        assert_eq!(via.transport(), "TCP");
        assert_eq!(via.sent_by.as_str(), "host");

        let contact =
            parse_contact_header(header(&resp.headers, "Contact").unwrap()).expect("contact");
        assert_eq!(
            contact.inner().display_name.as_deref(),
            Some("Alice"),
            "contact display"
        );
        assert_eq!(contact.uri().as_str(), "sip:alice@example.com");
        assert_eq!(
            contact.inner().params_map().get("expires"),
            Some(&Some(SmolStr::new("60".to_owned())))
        );

        let routes = parse_route_headers(&resp.headers, "Record-Route");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].uri().as_str(), "sip:proxy1.example.com;lr");
        assert!(routes[0].inner().params_map().is_empty());

        let rack = parse_rack_header(header(&resp.headers, "RAck").unwrap()).expect("rack");
        assert_eq!(rack.rseq, 2000);
        let rseq = parse_rseq_header(header(&resp.headers, "RSeq").unwrap()).expect("rseq");
        assert_eq!(rseq.sequence, 2000);

        let session_expires =
            parse_session_expires(header(&resp.headers, "Session-Expires").unwrap()).expect("se");
        assert_eq!(session_expires.delta_seconds, 90);
        assert!(matches!(
            session_expires.refresher,
            Some(RefresherRole::Uac)
        ));

        let min_se = parse_min_se(header(&resp.headers, "Min-SE").unwrap()).expect("min-se");
        assert_eq!(min_se.delta_seconds, 60);

        let rp = parse_resource_priority(header(&resp.headers, "Resource-Priority").unwrap());
        assert_eq!(rp.values.len(), 2);

        let event = parse_event_header(header(&resp.headers, "Event").unwrap()).expect("event");
        assert_eq!(event.package.as_str(), "dialog");
        assert_eq!(event.id.as_deref(), Some("123"));

        let sub_state =
            parse_subscription_state(header(&resp.headers, "Subscription-State").unwrap());
        assert!(matches!(sub_state.state, SubscriptionState::Active));

        let service_route = parse_service_route(&resp.headers);
        assert_eq!(service_route.routes.len(), 1);
        assert_eq!(
            service_route.routes[0].uri.as_str(),
            "sip:service.example.com"
        );

        let path = parse_path(&resp.headers);
        assert_eq!(path.routes.len(), 1);
        assert_eq!(path.routes[0].uri.as_str(), "sip:path.example.com");

        let history = parse_history_info(&resp.headers);
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].uri.as_str(), "sip:callee@example.com");

        let reason = parse_reason_header(header(&resp.headers, "Reason").unwrap());
        assert_eq!(reason.protocol.as_str(), "Q.850");
        assert_eq!(
            reason.params.get("cause"),
            Some(&Some(SmolStr::new("16".to_owned())))
        );

        let etag = parse_sip_etag(header(&resp.headers, "SIP-ETag").unwrap());
        assert_eq!(etag.value.as_str(), "abc123");

        let geo = parse_geolocation_header(&resp.headers);
        assert_eq!(geo.values.len(), 1);
        assert_eq!(geo.values[0].uri.as_str(), "sip:geo@example.com");

        let geo_error =
            parse_geolocation_error(header(&resp.headers, "Geolocation-Error").unwrap());
        assert_eq!(geo_error.code.as_deref(), Some("100"));
        assert_eq!(geo_error.description.as_deref(), Some("Failure"));

        let geo_routing =
            parse_geolocation_routing(header(&resp.headers, "Geolocation-Routing").unwrap());
        assert!(geo_routing.params.contains_key("yes"));

        let pani =
            parse_p_access_network_info(header(&resp.headers, "P-Access-Network-Info").unwrap())
                .expect("pani");
        assert_eq!(pani.access_type.as_str(), "3GPP-E-UTRAN-FDD");

        let visited =
            parse_p_visited_network_id(header(&resp.headers, "P-Visited-Network-ID").unwrap());
        assert_eq!(visited.values.len(), 2);

        let asserted = parse_p_asserted_identity(&resp.headers);
        assert_eq!(asserted.identities.len(), 1);

        let preferred = parse_p_preferred_identity(&resp.headers);
        assert_eq!(preferred.identities.len(), 1);
    }

    #[test]
    fn parses_mime_type_and_sdp_payload() {
        let resp = parse_response(&sample_response_bytes()).expect("parse");
        let mime = parse_mime_type(header(&resp.headers, "Content-Type").unwrap()).expect("mime");
        assert_eq!(mime.as_str(), "application/sdp");
        assert_eq!(mime.param("charset").map(|c| c.as_str()), Some("utf-8"));

        let sdp = parse_sdp(&resp.body).expect("sdp");
        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.session_name, "call");
    }

    #[test]
    fn route_header_params_preserved() {
        let raw = Bytes::from_static(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Route: <sip:proxy.example.com;lr>;foo=bar\r\n\
Content-Length: 0\r\n\r\n",
        );
        let req = parse_request(&raw).expect("parse");
        let routes = parse_route_headers(&req.headers, "Route");
        assert_eq!(routes.len(), 1);
        assert!(routes[0].inner().params_map().contains_key("foo"));
    }

    #[test]
    fn parses_authorization_priority_date_subject() {
        let auth_value = SmolStr::new(
            "Digest username=\"alice\", realm=\"example.com\", uri=\"sip:example.com\"".to_owned(),
        );
        let auth = parse_authorization_header(&auth_value).expect("auth");
        assert_eq!(auth.scheme.as_str(), "Digest");
        assert_eq!(auth.param("username").map(|v| v.as_str()), Some("alice"));
        let proxy = parse_proxy_authorization_header(&auth_value).expect("proxy");
        assert_eq!(
            proxy.param("realm").map(|v| v.as_str()),
            Some("example.com")
        );

        let priority = parse_priority_header(&SmolStr::new("urgent".to_owned()));
        assert!(matches!(priority, PriorityValue::Urgent));

        let date_value = SmolStr::new("Fri, 21 Feb 2025 10:00:00 GMT".to_owned());
        let date = parse_date_header(&date_value);
        assert!(date.timestamp.is_some());

        let subject = parse_subject_header(&SmolStr::new("Test Call".to_owned()));
        assert_eq!(subject.value.as_str(), "Test Call");
    }

    #[test]
    fn parses_basic_response() {
        let raw = Bytes::from_static(
            b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK\r\n\
Record-Route: <sip:proxy1>\r\n\
Record-Route: <sip:proxy2>\r\n\
Content-Length: 5\r\n\r\nhello",
        );
        let res = parse_response(&raw).expect("parse");
        assert_eq!(res.start.code, 200);
        assert_eq!(res.start.reason.as_str(), "OK");
        let rr: Vec<&str> = res
            .headers
            .get_all("record-route")
            .map(|v| v.as_str())
            .collect();
        assert_eq!(rr, vec!["<sip:proxy1>", "<sip:proxy2>"]);
        assert_eq!(res.body.as_ref(), b"hello");
    }

    #[test]
    fn serialize_request_recomputes_content_length() {
        let uri = SipUri::parse("sip:example.com").unwrap();
        let mut headers = Headers::new();
        headers.push(SmolStr::new("Via"), SmolStr::new("SIP/2.0/UDP host"));
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("999"));

        let body = Bytes::from_static(b"hello");
        let req = Request::new(
            RequestLine::new(Method::Options, uri),
            headers,
            body.clone(),
        );

        let serialized = serialize_request(&req);
        let text = std::str::from_utf8(&serialized).unwrap();
        assert_eq!(text.matches("Content-Length").count(), 1);
        assert!(text.contains("Content-Length: 5\r\n"));

        let reparsed = parse_request(&serialized).expect("reparse");
        assert_eq!(
            header(&reparsed.headers, "Content-Length")
                .expect("content-length")
                .as_str(),
            "5"
        );
        assert_eq!(reparsed.body.len(), body.len());
    }

    #[test]
    fn serialize_response_sets_content_length() {
        let mut headers = Headers::new();
        headers.push(SmolStr::new("Server"), SmolStr::new("siphon"));
        headers.push(SmolStr::new("Content-Length"), SmolStr::new("123"));

        let body = Bytes::from_static(b"hi");
        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            headers,
            body.clone(),
        );

        let serialized = serialize_response(&response);
        let text = std::str::from_utf8(&serialized).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert_eq!(text.matches("Content-Length").count(), 1);
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\nhi"));
    }

    #[test]
    fn reject_invalid_branch_cookie() {
        let raw = Bytes::from_static(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host;branch=badbranch\r\n\
Content-Length: 0\r\n\r\n",
        );
        assert!(parse_request(&raw).is_none(), "should reject bad branch");
    }

    #[test]
    fn serializer_inserts_max_forwards() {
        let uri = SipUri::parse("sip:example.com").unwrap();
        let mut headers = Headers::new();
        headers.push(SmolStr::new("Via"), SmolStr::new("SIP/2.0/UDP host".to_owned()));

        let req = Request::new(
            RequestLine::new(Method::Options, uri),
            headers,
            Bytes::new(),
        );
        let serialized = serialize_request(&req);
        let text = std::str::from_utf8(&serialized).unwrap();
        assert!(text.contains("Max-Forwards: 70"));
    }

    proptest! {
        #[test]
        fn roundtrip_random_request(
            method_idx in 0usize..5,
            host in "[a-z]{1,6}",
            body in "[a-z]{0,8}"
        ) {
            let methods = ["OPTIONS", "INVITE", "BYE", "CANCEL", "MESSAGE"];
            let method = methods[method_idx % methods.len()];
            let uri = SipUri::parse(&format!("sip:{host}.example.com")).unwrap();
            let mut headers = Headers::new();
            headers.push(SmolStr::new("Via"), SmolStr::new("SIP/2.0/UDP host".to_owned()));
            headers.push(SmolStr::new("Call-ID"), SmolStr::new("abc@host".to_owned()));
            headers.push(SmolStr::new("CSeq"), SmolStr::new(format!("1 {method}")));

            let req = Request::new(RequestLine::new(detect_method(method).unwrap(), uri), headers, Bytes::from(body.clone()));
            let bytes = serialize_request(&req);
            let reparsed = parse_request(&bytes).expect("parse");
            assert_eq!(reparsed.start.method.as_str(), method);
            assert_eq!(reparsed.body.as_ref(), body.as_bytes());
        }
    }

    proptest! {
        #[test]
        fn header_lookup_is_case_insensitive(
            name in "[A-Za-z][A-Za-z0-9\\-]{0,10}",
            value in "[^\\r\\n]{0,16}"
        ) {
            prop_assume!(!name.is_empty());
            prop_assume!(value.trim() == value);

            let uri = SipUri::parse("sip:example.com").unwrap();
            let mut headers = Headers::new();
            headers.push(
                SmolStr::new(name.clone()),
                SmolStr::new(value.clone()),
            );

            let req = Request::new(
                RequestLine::new(Method::Options, uri),
                headers,
                Bytes::new(),
            );

            let bytes = serialize_request(&req);
            let reparsed = parse_request(&bytes).expect("parse");

            let upper = name.to_ascii_uppercase();
            prop_assert_eq!(
                header(&reparsed.headers, &upper).map(|h| h.as_str()),
                Some(value.as_str()),
            );

            let lower = name.to_ascii_lowercase();
            prop_assert_eq!(
                header(&reparsed.headers, &lower).map(|h| h.as_str()),
                Some(value.as_str()),
            );
        }

        #[test]
        fn rack_round_trips(
            rseq in 1u32..1_000_000,
            cseq in 1u32..1_000_000,
            method_idx in 0usize..5
        ) {
            let tokens = ["INVITE", "UPDATE", "MESSAGE", "PRACK", "BYE"];
            let token = tokens[method_idx % tokens.len()];
            let header_value = format!("{rseq} {cseq} {}", token);
            let rack = parse_rack_header(&SmolStr::new(header_value)).expect("rack");
            let expected_method = super::detect_method(token).unwrap();
            prop_assert_eq!(rack.rseq, rseq);
            prop_assert_eq!(rack.cseq_number, cseq);
            prop_assert_eq!(rack.cseq_method, expected_method);
        }

        #[test]
        fn resource_priority_preserves_order(
            pairs in proptest::collection::vec(
                (string_regex("[a-z]{1,4}").unwrap(), string_regex("[a-z0-9]{1,4}").unwrap()),
                1..5
            )
        ) {
            let serialized = pairs.iter()
                .map(|(ns, priority)| format!("{}.{}", ns, priority))
                .collect::<Vec<_>>()
                .join(", ");
            let header = parse_resource_priority(&SmolStr::new(serialized));
            prop_assert_eq!(header.values.len(), pairs.len());
            for (parsed, (ns, priority)) in header.values.iter().zip(pairs.iter()) {
                prop_assert_eq!(parsed.namespace.as_str(), ns);
                prop_assert_eq!(parsed.priority.as_str(), priority);
            }
        }

        #[test]
        fn history_info_preserves_order(
            entries in proptest::collection::vec(
                (string_regex("[a-z]{1,4}").unwrap(), string_regex("[0-9]{1,2}").unwrap()),
                1..5
            )
        ) {
            let header_value = entries.iter()
                .map(|(user, index)| format!("<sip:{user}@example.com>;index={index}"))
                .collect::<Vec<_>>()
                .join(", ");
            let mut headers = Headers::new();
            headers.push(SmolStr::new("History-Info"), SmolStr::new(header_value));
            let parsed = parse_history_info(&headers);
            prop_assert_eq!(parsed.entries.len(), entries.len());
            for (entry, (user, index)) in parsed.entries.iter().zip(entries.iter()) {
                prop_assert!(entry.uri.as_str().contains(user));
                prop_assert_eq!(
                    entry.params.get(&SmolStr::new("index".to_owned())),
                    Some(&Some(SmolStr::new(index.to_owned())))
                );
            }
        }
    }
}
