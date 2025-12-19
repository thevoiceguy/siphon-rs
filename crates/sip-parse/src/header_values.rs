use std::collections::BTreeMap;

use bytes::Bytes;
use httpdate::parse_http_date;
use sip_core::{
    AllowHeader, AuthorizationHeader, ContactHeader, DateHeader, EventHeader, FromHeader,
    GeolocationErrorHeader, GeolocationHeader, GeolocationRoutingHeader, GeolocationValue, Headers,
    HistoryInfoEntry, HistoryInfoHeader, MimeType, MinSessionExpires, NameAddr, NameAddrHeader,
    PAccessNetworkInfo, PAssertedIdentityHeader, PPreferredIdentityHeader, PVisitedNetworkIdHeader,
    PathHeader, PriorityValue, RAckHeader, RSeqHeader, ReasonHeader, RefresherRole, Uri,
    ResourcePriorityHeader, ResourcePriorityValue, RouteHeader, SdpSession, ServiceRouteHeader,
    SessionExpires, SipETagHeader, SubjectHeader, SubscriptionState,
    SubscriptionStateHeader, SupportedHeader, ToHeader, TokenList, ViaHeader,
};
use smol_str::SmolStr;

pub fn parse_via_header(value: &SmolStr) -> Option<ViaHeader> {
    use nom::{
        bytes::complete::{tag_no_case, take_until, take_while1},
        character::complete::space1,
        combinator::rest,
        sequence::tuple,
    };

    let input = value.trim();
    let transport_token =
        take_while1::<_, _, nom::error::Error<_>>(|c: char| c.is_ascii_alphanumeric() || c == '-');
    let mut parser = tuple((
        tag_no_case::<_, _, nom::error::Error<_>>("SIP/2.0/"),
        transport_token,
        space1::<_, nom::error::Error<_>>,
        rest::<_, nom::error::Error<_>>,
    ));
    let (_, (_, transport, _, remainder)) = parser(input).ok()?;

    let (sent_by, params_part) = if let Ok((after, sb)) = take_until::<_, _, ()>(";")(remainder) {
        (sb.trim(), Some(after))
    } else {
        (remainder.trim(), None)
    };

    if sent_by.is_empty() {
        return None;
    }

    let params = parse_params(params_part.unwrap_or("").trim());
    Some(ViaHeader {
        transport: SmolStr::new(transport.to_uppercase()),
        sent_by: SmolStr::new(sent_by.to_owned()),
        params,
    })
}

pub fn parse_contact_header(value: &SmolStr) -> Option<ContactHeader> {
    parse_name_addr(value).map(ContactHeader)
}

pub fn parse_route_headers(headers: &Headers, name: &str) -> Vec<RouteHeader> {
    headers
        .get_all(name)
        .filter_map(|value| parse_route_header(value))
        .collect()
}

pub fn parse_route_header(value: &SmolStr) -> Option<RouteHeader> {
    parse_name_addr(value).map(RouteHeader)
}

pub fn parse_from_header(value: &SmolStr) -> Option<FromHeader> {
    parse_name_addr(value).map(FromHeader)
}

pub fn parse_to_header(value: &SmolStr) -> Option<ToHeader> {
    parse_name_addr(value).map(ToHeader)
}

pub fn parse_call_info_header(value: &SmolStr) -> Option<NameAddrHeader> {
    parse_name_addr(value).map(NameAddrHeader)
}

pub fn parse_call_info_headers(headers: &Headers) -> Vec<NameAddrHeader> {
    headers
        .get_all("Call-Info")
        .filter_map(parse_call_info_header)
        .collect()
}

pub fn parse_service_route(headers: &Headers) -> ServiceRouteHeader {
    let mut routes = Vec::new();
    for value in headers.get_all("Service-Route") {
        for part in split_quoted_commas(value.as_str()) {
            if let Some(name_addr) = parse_name_addr(&SmolStr::new(part.trim().to_owned())) {
                routes.push(name_addr);
            }
        }
    }
    ServiceRouteHeader { routes }
}

pub fn parse_path(headers: &Headers) -> PathHeader {
    let mut routes = Vec::new();
    for value in headers.get_all("Path") {
        for part in split_quoted_commas(value.as_str()) {
            if let Some(name_addr) = parse_name_addr(&SmolStr::new(part.trim().to_owned())) {
                routes.push(name_addr);
            }
        }
    }
    PathHeader { routes }
}

pub fn parse_mime_type(value: &SmolStr) -> Option<MimeType> {
    let mut parts = value.split(';');
    let main = parts.next()?.trim();
    let (top_level, subtype) = main.split_once('/')?;
    let mut params = BTreeMap::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            params.insert(
                SmolStr::new(k.trim().to_ascii_lowercase()),
                SmolStr::new(v.trim().trim_matches('"').to_owned()),
            );
        }
    }
    Some(MimeType {
        top_level: SmolStr::new(top_level.to_ascii_lowercase()),
        subtype: SmolStr::new(subtype.to_ascii_lowercase()),
        params,
    })
}

pub fn parse_sdp(body: &Bytes) -> Option<SdpSession> {
    let text = std::str::from_utf8(body.as_ref()).ok()?;
    SdpSession::parse(text.trim()).ok()
}

pub fn parse_allow_header(value: &SmolStr) -> AllowHeader {
    TokenList(parse_token_list(value))
}

pub fn parse_supported_header(value: &SmolStr) -> SupportedHeader {
    TokenList(parse_token_list(value))
}

pub fn parse_authorization_header(value: &SmolStr) -> Option<AuthorizationHeader> {
    parse_auth_like_header(value)
}

pub fn parse_proxy_authorization_header(value: &SmolStr) -> Option<AuthorizationHeader> {
    parse_auth_like_header(value)
}

pub fn parse_priority_header(value: &SmolStr) -> PriorityValue {
    match value.trim().to_ascii_lowercase().as_str() {
        "emergency" => PriorityValue::Emergency,
        "urgent" => PriorityValue::Urgent,
        "normal" => PriorityValue::Normal,
        "non-urgent" => PriorityValue::NonUrgent,
        other => PriorityValue::Unknown(SmolStr::new(other.to_owned())),
    }
}

pub fn parse_date_header(value: &SmolStr) -> DateHeader {
    let timestamp = parse_http_date(value.as_str()).ok();
    DateHeader {
        raw: value.clone(),
        timestamp,
    }
}

pub fn parse_subject_header(value: &SmolStr) -> SubjectHeader {
    SubjectHeader {
        value: value.clone(),
    }
}

pub fn parse_rseq_header(value: &SmolStr) -> Option<RSeqHeader> {
    let seq = value.trim().parse().ok()?;
    Some(RSeqHeader { sequence: seq })
}

pub fn parse_rack_header(value: &SmolStr) -> Option<RAckHeader> {
    let mut parts = value.split_whitespace();
    let rseq = parts.next()?.parse().ok()?;
    let cseq_number = parts.next()?.parse().ok()?;
    let cseq_method = parts.next()?.to_uppercase();
    let method = crate::detect_method(&cseq_method)?;
    Some(RAckHeader {
        rseq,
        cseq_number,
        cseq_method: method,
    })
}

pub fn parse_session_expires(value: &SmolStr) -> Option<SessionExpires> {
    let mut parts = value.split(';');
    let delta = parts.next()?.trim().parse().ok()?;
    let mut refresher = None;
    for part in parts {
        let part = part.trim();
        if let Some((name, val)) = part.split_once('=') {
            if name.eq_ignore_ascii_case("refresher") {
                refresher = match val.trim().to_ascii_lowercase().as_str() {
                    "uac" => Some(RefresherRole::Uac),
                    "uas" => Some(RefresherRole::Uas),
                    _ => None,
                };
            }
        }
    }
    Some(SessionExpires {
        delta_seconds: delta,
        refresher,
    })
}

pub fn parse_min_se(value: &SmolStr) -> Option<MinSessionExpires> {
    value
        .trim()
        .parse()
        .ok()
        .map(|delta_seconds| MinSessionExpires { delta_seconds })
}

pub fn parse_resource_priority(value: &SmolStr) -> ResourcePriorityHeader {
    let mut values = Vec::new();
    for token in value.split(',') {
        let token = token.trim();
        if let Some((ns, prio)) = token.split_once('.') {
            values.push(ResourcePriorityValue {
                namespace: SmolStr::new(ns.trim().to_owned()),
                priority: SmolStr::new(prio.trim().to_owned()),
            });
        }
    }
    ResourcePriorityHeader { values }
}

pub fn parse_event_header(value: &SmolStr) -> Option<EventHeader> {
    let mut parts = value.split(';');
    let package = parts.next()?.trim();
    let mut id = None;
    let mut params = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            let val = val.trim().trim_matches('"');
            if name.eq_ignore_ascii_case("id") {
                id = Some(SmolStr::new(val.to_owned()));
            } else {
                params.push((
                    SmolStr::new(name.to_ascii_lowercase()),
                    Some(SmolStr::new(val.to_owned())),
                ));
            }
        } else {
            params.push((SmolStr::new(part.to_ascii_lowercase()), None));
        }
    }
    Some(EventHeader {
        package: SmolStr::new(package.to_ascii_lowercase()),
        id,
        params,
    })
}

pub fn parse_subscription_state(value: &SmolStr) -> SubscriptionStateHeader {
    let mut parts = value.split(';');
    let state = match parts
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "active" => SubscriptionState::Active,
        "pending" => SubscriptionState::Pending,
        "terminated" => SubscriptionState::Terminated,
        other => SubscriptionState::Unknown(SmolStr::new(other.to_owned())),
    };
    let mut params = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            params.push((
                SmolStr::new(name.to_ascii_lowercase()),
                Some(SmolStr::new(val.trim().trim_matches('"').to_owned())),
            ));
        } else {
            params.push((SmolStr::new(part.to_ascii_lowercase()), None));
        }
    }
    SubscriptionStateHeader { state, params }
}

pub fn parse_history_info(headers: &Headers) -> HistoryInfoHeader {
    let mut entries = Vec::new();
    for value in headers.get_all("History-Info") {
        for part in split_quoted_commas(value.as_str()) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(name_addr) = parse_name_addr(&SmolStr::new(part.to_owned())) {
                entries.push(HistoryInfoEntry {
                    uri: name_addr.uri.clone(),
                    params: name_addr.params_map().clone(),
                });
            }
        }
    }
    HistoryInfoHeader { entries }
}

pub fn parse_reason_header(value: &SmolStr) -> ReasonHeader {
    let mut parts = value.split(';');
    let protocol = SmolStr::new(parts.next().unwrap_or("").trim().to_owned());
    let mut params = BTreeMap::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            params.insert(
                SmolStr::new(name.to_ascii_lowercase()),
                Some(SmolStr::new(val.trim().trim_matches('"').to_owned())),
            );
        } else {
            params.insert(SmolStr::new(part.to_ascii_lowercase()), None);
        }
    }
    ReasonHeader { protocol, params }
}

pub fn parse_sip_etag(value: &SmolStr) -> SipETagHeader {
    SipETagHeader {
        value: value.clone(),
    }
}

pub fn parse_geolocation_header(headers: &Headers) -> GeolocationHeader {
    let mut values = Vec::new();
    for header in headers.get_all("Geolocation") {
        for part in split_quoted_commas(header.as_str()) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(name_addr) = parse_name_addr(&SmolStr::new(part.to_owned())) {
                values.push(GeolocationValue {
                    uri: name_addr.uri.clone(),
                    params: name_addr.params_map().clone(),
                });
            }
        }
    }
    GeolocationHeader { values }
}

pub fn parse_geolocation_error(value: &SmolStr) -> GeolocationErrorHeader {
    let mut parts = value.split(';');
    let code = parts.next().map(|c| c.trim()).filter(|c| !c.is_empty());
    let mut params = BTreeMap::new();
    let mut description = None;
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            let key = name.trim().to_ascii_lowercase();
            let value = SmolStr::new(val.trim().trim_matches('"').to_owned());
            if key == "reason" {
                description = Some(value.clone());
            }
            params.insert(SmolStr::new(key), Some(value));
        } else {
            params.insert(SmolStr::new(part.to_ascii_lowercase()), None);
        }
    }
    GeolocationErrorHeader {
        code: code.map(|c| SmolStr::new(c.to_owned())),
        description,
        params,
    }
}

pub fn parse_geolocation_routing(value: &SmolStr) -> GeolocationRoutingHeader {
    GeolocationRoutingHeader {
        params: parse_params(value.as_str()),
    }
}

pub fn parse_p_access_network_info(value: &SmolStr) -> Option<PAccessNetworkInfo> {
    let mut parts = value.split(';');
    let access_type = SmolStr::new(parts.next()?.trim().to_owned());
    let mut params = BTreeMap::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            params.insert(
                SmolStr::new(name.trim().to_ascii_lowercase()),
                Some(SmolStr::new(val.trim().trim_matches('"').to_owned())),
            );
        } else {
            params.insert(SmolStr::new(part.to_ascii_lowercase()), None);
        }
    }
    Some(PAccessNetworkInfo {
        access_type,
        params,
    })
}

pub fn parse_p_visited_network_id(value: &SmolStr) -> PVisitedNetworkIdHeader {
    let values = split_quoted_commas(value.as_str())
        .into_iter()
        .map(|token| SmolStr::new(token.trim_matches('"').to_owned()))
        .collect();
    PVisitedNetworkIdHeader { values }
}

#[allow(dead_code)]
fn parse_name_addr_list<'a>(header_values: impl Iterator<Item = &'a SmolStr>) -> Vec<NameAddr> {
    let mut out = Vec::new();
    for value in header_values {
        for part in split_quoted_commas(value.as_str()) {
            if let Some(name_addr) = parse_name_addr(&SmolStr::new(part.trim().to_owned())) {
                out.push(name_addr);
            }
        }
    }
    out
}

pub fn parse_p_asserted_identity(headers: &Headers) -> PAssertedIdentityHeader {
    let identities = parse_p_identity_list(headers.get_all("P-Asserted-Identity"));
    PAssertedIdentityHeader { identities }
}

pub fn parse_p_preferred_identity(headers: &Headers) -> PPreferredIdentityHeader {
    let identities = parse_p_identity_list(headers.get_all("P-Preferred-Identity"));
    PPreferredIdentityHeader { identities }
}

fn parse_p_identity_list<'a, I>(header_values: I) -> Vec<sip_core::PIdentity>
where
    I: Iterator<Item = &'a SmolStr>,
{
    let mut out = Vec::new();
    for value in header_values {
        for part in split_quoted_commas(value.as_str()) {
            if let Some(identity) = parse_p_identity(&SmolStr::new(part.trim().to_owned())) {
                out.push(identity);
            }
        }
    }
    out
}

fn parse_p_identity(value: &SmolStr) -> Option<sip_core::PIdentity> {
    use sip_core::{PIdentity, Uri};
    let input = value.trim();
    if input.is_empty() {
        return None;
    }
    if let Some(start) = input.find('<') {
        let end_rel = input[start + 1..].find('>')?;
        let end = start + 1 + end_rel;
        let display = input[..start].trim();
        let uri_str = input[start + 1..end].trim();
        let params = parse_params(input[end + 1..].trim());

        // Parse as Uri (supports both SIP and Tel)
        let uri = Uri::parse(uri_str)?;

        Some(PIdentity {
            display_name: if display.is_empty() {
                None
            } else {
                Some(SmolStr::new(display.trim_matches('"').to_owned()))
            },
            uri,
            params,
        })
    } else {
        let (uri_part, param_part) = input.split_once(';').unwrap_or((input, ""));
        let uri = Uri::parse(uri_part.trim())?;
        Some(PIdentity {
            display_name: None,
            uri,
            params: parse_params(param_part),
        })
    }
}

fn parse_name_addr(value: &SmolStr) -> Option<NameAddr> {
    let input = value.trim();
    if input.is_empty() {
        return None;
    }
    if let Some(start) = input.find('<') {
        let end_rel = input[start + 1..].find('>')?;
        let end = start + 1 + end_rel;
        let display = input[..start].trim();
        let uri = input[start + 1..end].trim();
        let params = parse_params(input[end + 1..].trim());
        let uri = Uri::parse(uri)?;
        Some(NameAddr {
            display_name: if display.is_empty() {
                None
            } else {
                Some(SmolStr::new(display.trim_matches('"').to_owned()))
            },
            uri,
            params,
        })
    } else {
        let (uri_part, param_part) = input.split_once(';').unwrap_or((input, ""));
        let uri = Uri::parse(uri_part.trim())?;
        Some(NameAddr {
            display_name: None,
            uri,
            params: parse_params(param_part),
        })
    }
}

fn parse_params(input: &str) -> BTreeMap<SmolStr, Option<SmolStr>> {
    let mut params = BTreeMap::new();
    for raw in input.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Some((name, value)) = raw.split_once('=') {
            params.insert(
                SmolStr::new(name.trim().to_ascii_lowercase()),
                Some(SmolStr::new(value.trim().trim_matches('"').to_owned())),
            );
        } else {
            params.insert(SmolStr::new(raw.to_ascii_lowercase()), None);
        }
    }
    params
}

fn parse_token_list(value: &SmolStr) -> Vec<SmolStr> {
    value
        .split(',')
        .filter_map(|token| {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(SmolStr::new(trimmed.to_owned()))
            }
        })
        .collect()
}

fn parse_auth_like_header(value: &SmolStr) -> Option<AuthorizationHeader> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.splitn(2, ' ');
    let scheme = SmolStr::new(parts.next()?.trim().to_owned());
    let remainder = parts.next().unwrap_or("");
    let mut params = BTreeMap::new();
    for part in split_quoted_commas(remainder) {
        if let Some((name, val)) = part.split_once('=') {
            let cleaned = val.trim().trim_matches('"');
            params.insert(
                SmolStr::new(name.trim().to_ascii_lowercase()),
                SmolStr::new(cleaned.to_owned()),
            );
        }
    }
    Some(AuthorizationHeader { scheme, params })
}

fn split_quoted_commas(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_owned());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_owned());
    }
    parts
}
