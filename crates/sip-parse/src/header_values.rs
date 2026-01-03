// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use bytes::Bytes;
use sip_core::geolocation::{GeolocationError, MAX_GEO_VALUES};
use sip_core::history_info::{HistoryInfoError, MAX_ENTRIES as MAX_HISTORY_ENTRIES};
use sip_core::{
    p_headers::PHeaderError,
    service_route::{RouteError, MAX_ROUTES},
    AllowHeader, AuthorizationHeader, ContactHeader, DateHeader, EventHeader, FromHeader,
    GeolocationErrorHeader, GeolocationHeader, GeolocationRoutingHeader, GeolocationValue, Headers,
    HistoryInfoEntry, HistoryInfoHeader, MimeType, MinSessionExpires, NameAddr, NameAddrHeader,
    PAccessNetworkInfo, PAssertedIdentityHeader, PPreferredIdentityHeader, PVisitedNetworkIdHeader,
    PathHeader, PriorityValue, RAckHeader, RSeqHeader, ReasonHeader, ResourcePriorityHeader,
    RouteHeader, SdpSession, ServiceRouteHeader, SessionExpires, SipETagHeader, SubjectHeader,
    SubscriptionState, SubscriptionStateHeader, SupportedHeader, ToHeader, TokenList, Uri,
    ViaHeader,
};
use smol_str::SmolStr;

pub fn parse_via_header(value: &SmolStr) -> Option<ViaHeader> {
    ViaHeader::parse(value.as_str()).ok()
}

pub fn parse_contact_header(value: &SmolStr) -> Option<ContactHeader> {
    parse_name_addr(value).map(ContactHeader::new)
}

pub fn parse_route_headers(headers: &Headers, name: &str) -> Vec<RouteHeader> {
    headers
        .get_all_smol(name)
        .filter_map(parse_route_header)
        .collect()
}

pub fn parse_route_header(value: &SmolStr) -> Option<RouteHeader> {
    parse_name_addr(value).map(RouteHeader::new)
}

pub fn parse_from_header(value: &SmolStr) -> Option<FromHeader> {
    parse_name_addr(value).map(FromHeader::new)
}

pub fn parse_to_header(value: &SmolStr) -> Option<ToHeader> {
    parse_name_addr(value).map(ToHeader::new)
}

pub fn parse_call_info_header(value: &SmolStr) -> Option<NameAddrHeader> {
    parse_name_addr(value).map(NameAddrHeader::new)
}

pub fn parse_call_info_headers(headers: &Headers) -> Vec<NameAddrHeader> {
    headers
        .get_all_smol("Call-Info")
        .filter_map(parse_call_info_header)
        .collect()
}

pub fn parse_service_route(headers: &Headers) -> Result<ServiceRouteHeader, RouteError> {
    let mut routes = Vec::new();
    for value in headers.get_all_smol("Service-Route") {
        let parts = split_quoted_commas(value.as_str(), MAX_ROUTES).ok_or_else(|| {
            RouteError::ValidationError("too many Service-Route values".to_string())
        })?;
        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value = SmolStr::new(trimmed);
            if let Some(name_addr) = parse_name_addr(&value) {
                routes.push(name_addr);
            } else {
                return Err(RouteError::ValidationError(
                    "invalid Service-Route name-addr".to_string(),
                ));
            }
        }
    }
    ServiceRouteHeader::new(routes)
}

pub fn parse_path(headers: &Headers) -> Result<PathHeader, RouteError> {
    let mut routes = Vec::new();
    for value in headers.get_all_smol("Path") {
        let parts = split_quoted_commas(value.as_str(), MAX_ROUTES)
            .ok_or_else(|| RouteError::ValidationError("too many Path values".to_string()))?;
        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value = SmolStr::new(trimmed);
            if let Some(name_addr) = parse_name_addr(&value) {
                routes.push(name_addr);
            } else {
                return Err(RouteError::ValidationError(
                    "invalid Path name-addr".to_string(),
                ));
            }
        }
    }
    PathHeader::new(routes)
}

pub fn parse_mime_type(value: &SmolStr) -> Option<MimeType> {
    value.as_str().parse().ok()
}

pub fn parse_sdp(body: &Bytes) -> Option<SdpSession> {
    let text = std::str::from_utf8(body.as_ref()).ok()?;
    SdpSession::parse(text.trim()).ok()
}

pub fn parse_allow_header(value: &SmolStr) -> AllowHeader {
    TokenList::parse(value.as_str()).unwrap_or_default()
}

pub fn parse_supported_header(value: &SmolStr) -> SupportedHeader {
    TokenList::parse(value.as_str()).unwrap_or_default()
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
        other => PriorityValue::Unknown(SmolStr::new(other)),
    }
}

pub fn parse_date_header(value: &SmolStr) -> DateHeader {
    // Try to create a validated DateHeader from the raw string
    // If validation fails, return a DateHeader with the current timestamp
    // This maintains backward compatibility while using the new validated API
    DateHeader::new(value.as_str()).unwrap_or_else(|_| DateHeader::now())
}

pub fn parse_subject_header(value: &SmolStr) -> Option<SubjectHeader> {
    SubjectHeader::parse(value.as_str()).ok()
}

pub fn parse_rseq_header(value: &SmolStr) -> Option<RSeqHeader> {
    RSeqHeader::parse(value.as_str()).ok()
}

pub fn parse_rack_header(value: &SmolStr) -> Option<RAckHeader> {
    RAckHeader::parse(value.as_str()).ok()
}

pub fn parse_session_expires(value: &SmolStr) -> Option<SessionExpires> {
    // Use the validated parser from sip-core which checks ranges and control characters
    SessionExpires::parse(value.as_str())
}

pub fn parse_min_se(value: &SmolStr) -> Option<MinSessionExpires> {
    // Use the validated parser from sip-core which checks ranges and control characters
    MinSessionExpires::parse(value.as_str())
}

pub fn parse_resource_priority(value: &SmolStr) -> Option<ResourcePriorityHeader> {
    ResourcePriorityHeader::parse(value.as_str()).ok()
}

pub fn parse_event_header(value: &SmolStr) -> Option<EventHeader> {
    let mut parts = value.split(';');
    let package = parts.next()?.trim();
    let mut header = EventHeader::new(package).ok()?;
    let mut has_id = false;
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            let val = val.trim().trim_matches('"');
            if name.eq_ignore_ascii_case("id") {
                if has_id {
                    return None;
                }
                header = header.with_id(val).ok()?;
                has_id = true;
            } else {
                header.add_param(name, Some(val)).ok()?;
            }
        } else {
            if part.eq_ignore_ascii_case("id") {
                return None;
            }
            header.add_param(part, None).ok()?;
        }
    }
    Some(header)
}

pub fn parse_subscription_state(value: &SmolStr) -> Option<SubscriptionStateHeader> {
    let mut parts = value.split(';');
    let state = SubscriptionState::parse(parts.next().unwrap_or("").trim()).ok()?;
    let mut header = SubscriptionStateHeader::new(state);
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            let val = val.trim().trim_matches('"');
            header.add_param(name, Some(val)).ok()?;
        } else {
            header.add_param(part, None).ok()?;
        }
    }
    Some(header)
}

pub fn parse_history_info(headers: &Headers) -> Result<HistoryInfoHeader, HistoryInfoError> {
    let mut entries = Vec::new();
    for value in headers.get_all_smol("History-Info") {
        let parts = split_quoted_commas(value.as_str(), MAX_HISTORY_ENTRIES).ok_or_else(|| {
            HistoryInfoError::TooManyEntries {
                max: MAX_HISTORY_ENTRIES,
                actual: MAX_HISTORY_ENTRIES + 1,
            }
        })?;
        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let name_addr = parse_name_addr(&SmolStr::new(part)).ok_or_else(|| {
                HistoryInfoError::InvalidEntry("invalid History-Info name-addr".to_string())
            })?;
            let mut entry = HistoryInfoEntry::new(name_addr.uri().clone());
            // Add all parameters from the name_addr
            for (k, v) in name_addr.params_map() {
                entry.add_param(k, v.as_deref())?;
            }
            entries.push(entry);
        }
    }
    HistoryInfoHeader::new(entries)
}

pub fn parse_reason_header(value: &SmolStr) -> Option<ReasonHeader> {
    sip_core::reason::parse_reason_from_string(value.as_str()).ok()
}

pub fn parse_sip_etag(value: &SmolStr) -> Option<SipETagHeader> {
    SipETagHeader::parse(value.as_str()).ok()
}

pub fn parse_geolocation_header(headers: &Headers) -> Result<GeolocationHeader, GeolocationError> {
    let mut values = Vec::new();
    for header in headers.get_all_smol("Geolocation") {
        let parts = split_quoted_commas(header.as_str(), MAX_GEO_VALUES).ok_or_else(|| {
            GeolocationError::TooManyValues {
                max: MAX_GEO_VALUES,
                actual: MAX_GEO_VALUES + 1,
            }
        })?;
        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(name_addr) = parse_name_addr(&SmolStr::new(part)) {
                let mut value = GeolocationValue::new(name_addr.uri().clone());
                for (name, param_value) in name_addr.params_map() {
                    let _ =
                        value.add_param(name.as_str(), param_value.as_ref().map(|s| s.as_str()));
                }
                values.push(value);
            }
        }
    }
    GeolocationHeader::new(values)
}

pub fn parse_geolocation_error(
    value: &SmolStr,
) -> Result<GeolocationErrorHeader, GeolocationError> {
    let mut parts = value.split(';');
    let code = parts.next().map(|c| c.trim()).filter(|c| !c.is_empty());
    let mut header = GeolocationErrorHeader::new();
    if let Some(code) = code {
        if let Ok(updated) = header.clone().with_code(code) {
            header = updated;
        }
    }
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            let key = name.trim().to_ascii_lowercase();
            let value = SmolStr::new(val.trim().trim_matches('"'));
            if key == "reason" {
                if let Ok(updated) = header.clone().with_description(value.as_str()) {
                    header = updated;
                }
            }
            let _ = header.add_param(&key, Some(value.as_str()));
        } else {
            let key = part.to_ascii_lowercase();
            let _ = header.add_param(&key, None);
        }
    }
    Ok(header)
}

pub fn parse_geolocation_routing(
    value: &SmolStr,
) -> Result<GeolocationRoutingHeader, GeolocationError> {
    let mut header = GeolocationRoutingHeader::new();
    let params = parse_params(value.as_str()).ok_or_else(|| GeolocationError::TooManyParams {
        max: MAX_PARAMS,
        actual: MAX_PARAMS + 1,
    })?;
    for (name, param_value) in params.iter() {
        let value_str = param_value.as_ref().map(|s| s.as_str());
        let _ = header.add_param(name.as_str(), value_str);
    }
    Ok(header)
}

pub fn parse_p_access_network_info(value: &SmolStr) -> Option<PAccessNetworkInfo> {
    let mut parts = value.split(';');
    let access_type = parts.next()?.trim();
    let mut header = PAccessNetworkInfo::new(access_type).ok()?;
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            if header
                .add_param(name.trim(), Some(val.trim().trim_matches('"')))
                .is_err()
            {
                return None;
            }
        } else if header.add_param(part, Option::<&str>::None).is_err() {
            return None;
        }
    }
    Some(header)
}

pub fn parse_p_visited_network_id(value: &SmolStr) -> Option<PVisitedNetworkIdHeader> {
    let parts = split_quoted_commas(value.as_str(), MAX_PARAMS)?;
    let values: Vec<SmolStr> = parts
        .into_iter()
        .filter_map(|token| {
            let trimmed = token.trim_matches('"').trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(SmolStr::new(trimmed))
            }
        })
        .collect();
    PVisitedNetworkIdHeader::new(values).ok()
}

#[allow(dead_code)]
fn parse_name_addr_list<'a>(
    header_values: impl Iterator<Item = &'a SmolStr>,
) -> Option<Vec<NameAddr>> {
    let mut out = Vec::new();
    for value in header_values {
        let parts = split_quoted_commas(value.as_str(), MAX_ROUTES)?;
        for part in parts {
            if let Some(name_addr) = parse_name_addr(&SmolStr::new(part.trim())) {
                out.push(name_addr);
                if out.len() > MAX_ROUTES {
                    return None;
                }
            }
        }
    }
    Some(out)
}

pub fn parse_p_asserted_identity(
    headers: &Headers,
) -> Result<Option<PAssertedIdentityHeader>, PHeaderError> {
    sip_core::parse_p_asserted_identity(headers)
}

pub fn parse_p_preferred_identity(
    headers: &Headers,
) -> Result<Option<PPreferredIdentityHeader>, PHeaderError> {
    sip_core::parse_p_preferred_identity(headers)
}

fn parse_name_addr(value: &SmolStr) -> Option<NameAddr> {
    let input = value.trim();
    if input.is_empty() {
        return None;
    }
    match find_unquoted_angle_brackets(input) {
        Ok(Some((start, end))) => {
            let display = input[..start].trim();
            let uri = input[start + 1..end].trim();
            let params = parse_params(input[end + 1..].trim())?;
            let uri = Uri::parse(uri).ok()?;
            NameAddr::new(
                if display.is_empty() {
                    None
                } else {
                    Some(SmolStr::new(display.trim_matches('"')))
                },
                uri,
                params,
            )
            .ok()
        }
        Ok(None) => {
            let (uri_part, param_part) = input.split_once(';').unwrap_or((input, ""));
            let uri = Uri::parse(uri_part.trim()).ok()?;
            let params = parse_params(param_part)?;
            NameAddr::new(None, uri, params).ok()
        }
        Err(()) => None,
    }
}

/// Maximum number of parameters to prevent DoS attacks
const MAX_PARAMS: usize = 64;

/// Parses parameters with bounds checking to prevent memory exhaustion.
/// Returns None if there are too many parameters (>64).
fn parse_params(input: &str) -> Option<BTreeMap<SmolStr, Option<SmolStr>>> {
    let mut params = BTreeMap::new();
    for raw in input.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        // Security: Reject if too many parameters (DoS prevention)
        if params.len() >= MAX_PARAMS {
            return None;
        }

        if let Some((name, value)) = raw.split_once('=') {
            params.insert(
                SmolStr::new(name.trim().to_ascii_lowercase()),
                Some(SmolStr::new(value.trim().trim_matches('"'))),
            );
        } else {
            params.insert(SmolStr::new(raw.to_ascii_lowercase()), None);
        }
    }
    Some(params)
}

fn find_unquoted_angle_brackets(input: &str) -> Result<Option<(usize, usize)>, ()> {
    let mut in_quotes = false;
    let mut escape_next = false;
    let mut start: Option<usize> = None;
    for (idx, ch) in input.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escape_next = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if in_quotes {
            continue;
        }
        if ch == '<' {
            start = Some(idx);
            break;
        }
    }
    let start = match start {
        Some(value) => value,
        None => return Ok(None),
    };
    in_quotes = false;
    escape_next = false;
    for (idx, ch) in input[start + 1..].char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escape_next = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if in_quotes {
            continue;
        }
        if ch == '>' {
            return Ok(Some((start, start + 1 + idx)));
        }
    }
    Err(())
}

fn parse_auth_like_header(value: &SmolStr) -> Option<AuthorizationHeader> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.splitn(2, ' ');
    let scheme = SmolStr::new(parts.next()?.trim());
    let remainder = parts.next().unwrap_or("");
    let mut params = BTreeMap::new();
    // split_quoted_commas now returns Option to prevent DoS attacks
    for part in split_quoted_commas(remainder, MAX_PARAMS)? {
        let (name, val) = part.split_once('=')?;
        let key = SmolStr::new(name.trim().to_ascii_lowercase());
        if params.contains_key(&key) {
            return None;
        }
        let cleaned = val.trim().trim_matches('"');
        params.insert(key, SmolStr::new(cleaned));
    }
    // Use from_raw() which validates scheme, params count, and param values
    AuthorizationHeader::from_raw(scheme, params).ok()
}

/// Splits comma-separated values, respecting quotes. Returns None if too many parts or unbalanced quotes.
fn split_quoted_commas(input: &str, max_parts: usize) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escape_next = false;
    for ch in input.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escape_next = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    // Security: Prevent DoS via excessive comma-separated values
                    if parts.len() >= max_parts {
                        return None;
                    }
                    parts.push(current.trim().to_owned());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if in_quotes {
        return None;
    }
    if !current.trim().is_empty() {
        // Security: Prevent DoS via excessive comma-separated values
        if parts.len() >= max_parts {
            return None;
        }
        parts.push(current.trim().to_owned());
    }
    Some(parts)
}
