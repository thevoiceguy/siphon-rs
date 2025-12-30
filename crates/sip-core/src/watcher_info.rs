// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 3857/3858 Watcher Information support with security hardening.
//!
//! This module implements:
//! - RFC 3857: Watcher Information Event Template-Package for SIP
//! - RFC 3858: XML-Based Format for Watcher Information
//!
//! # Security
//!
//! All components are validated for:
//! - Maximum length limits to prevent DoS attacks
//! - Bounded collections
//! - XML-safe content (no control characters, proper escaping)
//! - Valid state and status values

use smol_str::SmolStr;
use std::fmt;

use crate::Uri;

// Security: Input size limits
const MAX_URI_LENGTH: usize = 512;
const MAX_ID_LENGTH: usize = 128;
const MAX_DISPLAY_NAME_LENGTH: usize = 256;
const MAX_PACKAGE_NAME_LENGTH: usize = 64;
const MAX_STATE_LENGTH: usize = 16;
const MAX_WATCHER_LISTS: usize = 100;
const MAX_WATCHERS_PER_LIST: usize = 1000;

/// Error types for watcherinfo operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherinfoError {
    /// Invalid state value
    InvalidState(String),
    /// Invalid URI
    InvalidUri(String),
    /// Invalid ID
    InvalidId(String),
    /// Invalid display name
    InvalidDisplayName(String),
    /// Too many items
    TooManyItems { field: &'static str, max: usize },
    /// Input too long
    TooLong { field: &'static str, max: usize },
    /// Invalid format
    InvalidFormat(String),
    /// XML parsing error
    XmlParseError(String),
}

impl fmt::Display for WatcherinfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatcherinfoError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            WatcherinfoError::InvalidUri(msg) => write!(f, "Invalid URI: {}", msg),
            WatcherinfoError::InvalidId(msg) => write!(f, "Invalid ID: {}", msg),
            WatcherinfoError::InvalidDisplayName(msg) => write!(f, "Invalid display name: {}", msg),
            WatcherinfoError::TooManyItems { field, max } => {
                write!(f, "Too many {} (max {})", field, max)
            }
            WatcherinfoError::TooLong { field, max } => {
                write!(f, "{} too long (max {})", field, max)
            }
            WatcherinfoError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            WatcherinfoError::XmlParseError(msg) => write!(f, "XML parse error: {}", msg),
        }
    }
}

impl std::error::Error for WatcherinfoError {}

/// Validates a state value.
fn validate_state(state: &str) -> Result<(), WatcherinfoError> {
    if state.is_empty() {
        return Err(WatcherinfoError::InvalidState("state cannot be empty".to_string()));
    }

    if state.len() > MAX_STATE_LENGTH {
        return Err(WatcherinfoError::TooLong {
            field: "state",
            max: MAX_STATE_LENGTH,
        });
    }

    // Must be "full" or "partial"
    if !state.eq_ignore_ascii_case("full") && !state.eq_ignore_ascii_case("partial") {
        return Err(WatcherinfoError::InvalidState(
            "must be 'full' or 'partial'".to_string(),
        ));
    }

    Ok(())
}

/// Validates a URI.
fn validate_uri(uri: &str) -> Result<(), WatcherinfoError> {
    if uri.is_empty() {
        return Err(WatcherinfoError::InvalidUri("URI cannot be empty".to_string()));
    }

    if uri.len() > MAX_URI_LENGTH {
        return Err(WatcherinfoError::TooLong {
            field: "URI",
            max: MAX_URI_LENGTH,
        });
    }

    // Check for control characters
    if uri.chars().any(|c| c.is_control()) {
        return Err(WatcherinfoError::InvalidUri(
            "contains control characters".to_string(),
        ));
    }

    Uri::parse(uri)
        .map(|_| ())
        .map_err(|e| WatcherinfoError::InvalidUri(e.to_string()))
}

/// Validates an ID.
fn validate_id(id: &str) -> Result<(), WatcherinfoError> {
    if id.is_empty() {
        return Err(WatcherinfoError::InvalidId("ID cannot be empty".to_string()));
    }

    if id.len() > MAX_ID_LENGTH {
        return Err(WatcherinfoError::TooLong {
            field: "ID",
            max: MAX_ID_LENGTH,
        });
    }

    // Check for control characters
    if id.chars().any(|c| c.is_control()) {
        return Err(WatcherinfoError::InvalidId(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a display name.
fn validate_display_name(name: &str) -> Result<(), WatcherinfoError> {
    if name.len() > MAX_DISPLAY_NAME_LENGTH {
        return Err(WatcherinfoError::TooLong {
            field: "display name",
            max: MAX_DISPLAY_NAME_LENGTH,
        });
    }

    // Check for control characters
    if name.chars().any(|c| c.is_control() && c != '\t') {
        return Err(WatcherinfoError::InvalidDisplayName(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a package name.
fn validate_package(package: &str) -> Result<(), WatcherinfoError> {
    if package.is_empty() {
        return Err(WatcherinfoError::InvalidFormat(
            "package name cannot be empty".to_string(),
        ));
    }

    if package.len() > MAX_PACKAGE_NAME_LENGTH {
        return Err(WatcherinfoError::TooLong {
            field: "package name",
            max: MAX_PACKAGE_NAME_LENGTH,
        });
    }

    // Check for control characters
    if package.chars().any(|c| c.is_control()) {
        return Err(WatcherinfoError::InvalidFormat(
            "package name contains control characters".to_string(),
        ));
    }

    if !package.chars().all(is_token_char) {
        return Err(WatcherinfoError::InvalidFormat(
            "package name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
        )
}

/// RFC 3858 Watcherinfo Document.
///
/// # Security
///
/// WatcherinfoDocument validates all components and enforces bounds to prevent DoS attacks.
#[derive(Debug, Clone, PartialEq)]
pub struct WatcherinfoDocument {
    version: u32,
    state: SmolStr,
    watcher_lists: Vec<WatcherList>,
}

impl WatcherinfoDocument {
    /// Creates a new watcherinfo document with validation.
    pub fn new(version: u32, state: impl Into<SmolStr>) -> Result<Self, WatcherinfoError> {
        let state = state.into();
        validate_state(&state)?;
        let state = SmolStr::new(state.as_str().to_ascii_lowercase());

        Ok(Self {
            version,
            state,
            watcher_lists: Vec::new(),
        })
    }

    /// Gets the version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Gets the state.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Gets the watcher lists.
    pub fn watcher_lists(&self) -> &[WatcherList] {
        &self.watcher_lists
    }

    /// Adds a watcher list to the document.
    pub fn add_watcher_list(&mut self, list: WatcherList) -> Result<(), WatcherinfoError> {
        if self.watcher_lists.len() >= MAX_WATCHER_LISTS {
            return Err(WatcherinfoError::TooManyItems {
                field: "watcher lists",
                max: MAX_WATCHER_LISTS,
            });
        }
        self.watcher_lists.push(list);
        Ok(())
    }

    /// Returns true if there are no watcher lists.
    pub fn is_empty(&self) -> bool {
        self.watcher_lists.is_empty()
    }

    /// Returns true if this is a full state document.
    pub fn is_full(&self) -> bool {
        self.state.eq_ignore_ascii_case("full")
    }

    /// Returns true if this is a partial state document.
    pub fn is_partial(&self) -> bool {
        self.state.eq_ignore_ascii_case("partial")
    }

    /// Formats the watcherinfo document as application/watcherinfo+xml.
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();

        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<watcherinfo xmlns=\"urn:ietf:params:xml:ns:watcherinfo\" version=\"");
        xml.push_str(&self.version.to_string());
        xml.push_str("\" state=\"");
        xml.push_str(&xml_escape(&self.state));
        xml.push_str("\">\n");

        for list in &self.watcher_lists {
            xml.push_str(&list.to_xml());
        }

        xml.push_str("</watcherinfo>\n");
        xml
    }
}

impl fmt::Display for WatcherinfoDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_xml())
    }
}

/// RFC 3858 Watcher List.
///
/// # Security
///
/// WatcherList validates all components and enforces bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct WatcherList {
    resource: SmolStr,
    package: SmolStr,
    watchers: Vec<Watcher>,
}

impl WatcherList {
    /// Creates a new watcher list with validation.
    pub fn new(
        resource: impl Into<SmolStr>,
        package: impl Into<SmolStr>,
    ) -> Result<Self, WatcherinfoError> {
        let resource = resource.into();
        let package = package.into();

        validate_uri(&resource)?;
        validate_package(&package)?;

        Ok(Self {
            resource,
            package,
            watchers: Vec::new(),
        })
    }

    /// Gets the resource URI.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Gets the package name.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Gets the watchers.
    pub fn watchers(&self) -> &[Watcher] {
        &self.watchers
    }

    /// Adds a watcher to the list.
    pub fn add_watcher(&mut self, watcher: Watcher) -> Result<(), WatcherinfoError> {
        if self.watchers.len() >= MAX_WATCHERS_PER_LIST {
            return Err(WatcherinfoError::TooManyItems {
                field: "watchers",
                max: MAX_WATCHERS_PER_LIST,
            });
        }
        self.watchers.push(watcher);
        Ok(())
    }

    /// Returns true if there are no watchers.
    pub fn is_empty(&self) -> bool {
        self.watchers.is_empty()
    }

    /// Formats the watcher list as XML.
    fn to_xml(&self) -> String {
        let mut xml = String::new();

        xml.push_str("  <watcher-list resource=\"");
        xml.push_str(&xml_escape(&self.resource));
        xml.push_str("\" package=\"");
        xml.push_str(&xml_escape(&self.package));
        xml.push_str("\">\n");

        for watcher in &self.watchers {
            xml.push_str(&watcher.to_xml());
        }

        xml.push_str("  </watcher-list>\n");
        xml
    }
}

/// RFC 3858 Watcher element.
///
/// # Security
///
/// Watcher validates all components.
#[derive(Debug, Clone, PartialEq)]
pub struct Watcher {
    id: SmolStr,
    status: WatcherStatus,
    event: WatcherEvent,
    uri: Option<SmolStr>,
    display_name: Option<SmolStr>,
    expiration: Option<u32>,
    duration_subscribed: Option<u32>,
}

impl Watcher {
    /// Creates a new watcher with validation.
    pub fn new(
        id: impl Into<SmolStr>,
        status: WatcherStatus,
        event: WatcherEvent,
    ) -> Result<Self, WatcherinfoError> {
        let id = id.into();
        validate_id(&id)?;

        Ok(Self {
            id,
            status,
            event,
            uri: None,
            display_name: None,
            expiration: None,
            duration_subscribed: None,
        })
    }

    /// Gets the ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Gets the status.
    pub fn status(&self) -> WatcherStatus {
        self.status
    }

    /// Gets the event.
    pub fn event(&self) -> WatcherEvent {
        self.event
    }

    /// Gets the URI.
    pub fn uri(&self) -> Option<&str> {
        self.uri.as_deref()
    }

    /// Gets the display name.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Gets the expiration.
    pub fn expiration(&self) -> Option<u32> {
        self.expiration
    }

    /// Gets the duration subscribed.
    pub fn duration_subscribed(&self) -> Option<u32> {
        self.duration_subscribed
    }

    /// Sets the watcher URI with validation.
    pub fn with_uri(mut self, uri: impl Into<SmolStr>) -> Result<Self, WatcherinfoError> {
        let uri = uri.into();
        validate_uri(&uri)?;
        self.uri = Some(uri);
        Ok(self)
    }

    /// Sets the display name with validation.
    pub fn with_display_name(mut self, name: impl Into<SmolStr>) -> Result<Self, WatcherinfoError> {
        let name = name.into();
        validate_display_name(&name)?;
        self.display_name = Some(name);
        Ok(self)
    }

    /// Sets the expiration time.
    pub fn with_expiration(mut self, seconds: u32) -> Self {
        self.expiration = Some(seconds);
        self
    }

    /// Sets the duration subscribed.
    pub fn with_duration_subscribed(mut self, seconds: u32) -> Self {
        self.duration_subscribed = Some(seconds);
        self
    }

    /// Formats the watcher as XML.
    fn to_xml(&self) -> String {
        let mut xml = String::new();

        xml.push_str("    <watcher id=\"");
        xml.push_str(&xml_escape(&self.id));
        xml.push_str("\" status=\"");
        xml.push_str(self.status.as_str());
        xml.push_str("\" event=\"");
        xml.push_str(self.event.as_str());
        xml.push('"');

        if let Some(ref display_name) = self.display_name {
            xml.push_str(" display-name=\"");
            xml.push_str(&xml_escape(display_name));
            xml.push('"');
        }

        if let Some(expiration) = self.expiration {
            xml.push_str(" expiration=\"");
            xml.push_str(&expiration.to_string());
            xml.push('"');
        }

        if let Some(duration) = self.duration_subscribed {
            xml.push_str(" duration-subscribed=\"");
            xml.push_str(&duration.to_string());
            xml.push('"');
        }

        xml.push('>');

        if let Some(ref uri) = self.uri {
            xml.push_str(&xml_escape(uri));
        }

        xml.push_str("</watcher>\n");
        xml
    }
}

/// RFC 3858 Watcher Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatcherStatus {
    Pending,
    Active,
    Waiting,
    Terminated,
}

impl WatcherStatus {
    pub fn as_str(&self) -> &str {
        match self {
            WatcherStatus::Pending => "pending",
            WatcherStatus::Active => "active",
            WatcherStatus::Waiting => "waiting",
            WatcherStatus::Terminated => "terminated",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pending" => Some(WatcherStatus::Pending),
            "active" => Some(WatcherStatus::Active),
            "waiting" => Some(WatcherStatus::Waiting),
            "terminated" => Some(WatcherStatus::Terminated),
            _ => None,
        }
    }
}

impl std::str::FromStr for WatcherStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

impl fmt::Display for WatcherStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// RFC 3858 Watcher Event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatcherEvent {
    Subscribe,
    Approved,
    Deactivated,
    Probation,
    Rejected,
    Timeout,
    Giveup,
    Noresource,
}

impl WatcherEvent {
    pub fn as_str(&self) -> &str {
        match self {
            WatcherEvent::Subscribe => "subscribe",
            WatcherEvent::Approved => "approved",
            WatcherEvent::Deactivated => "deactivated",
            WatcherEvent::Probation => "probation",
            WatcherEvent::Rejected => "rejected",
            WatcherEvent::Timeout => "timeout",
            WatcherEvent::Giveup => "giveup",
            WatcherEvent::Noresource => "noresource",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "subscribe" => Some(WatcherEvent::Subscribe),
            "approved" => Some(WatcherEvent::Approved),
            "deactivated" => Some(WatcherEvent::Deactivated),
            "probation" => Some(WatcherEvent::Probation),
            "rejected" => Some(WatcherEvent::Rejected),
            "timeout" => Some(WatcherEvent::Timeout),
            "giveup" => Some(WatcherEvent::Giveup),
            "noresource" => Some(WatcherEvent::Noresource),
            _ => None,
        }
    }
}

impl std::str::FromStr for WatcherEvent {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

impl fmt::Display for WatcherEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Escapes XML special characters comprehensively.
fn xml_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            // Filter out other control characters for security
            c if c.is_control() && c != '\t' && c != '\n' && c != '\r' => {
                format!("&#x{:X};", c as u32)
            }
            _ => c.to_string(),
        })
        .collect()
}

fn xml_unescape(s: &str) -> Result<String, WatcherinfoError> {
    let mut out = String::with_capacity(s.len());
    let mut idx = 0;
    while idx < s.len() {
        let remainder = &s[idx..];
        if remainder.starts_with('&') {
            let end = remainder.find(';').ok_or_else(|| {
                WatcherinfoError::XmlParseError("unterminated entity".to_string())
            })?;
            let entity = &remainder[1..end];
            let decoded = match entity {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
            } else if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                let value = u32::from_str_radix(hex, 16).map_err(|_| {
                    WatcherinfoError::XmlParseError("invalid hex character reference".to_string())
                })?;
                let ch = char::from_u32(value).ok_or_else(|| {
                    WatcherinfoError::XmlParseError("invalid character reference".to_string())
                })?;
                out.push(ch);
            } else if let Some(dec) = entity.strip_prefix('#') {
                let value = dec.parse::<u32>().map_err(|_| {
                    WatcherinfoError::XmlParseError("invalid character reference".to_string())
                })?;
                let ch = char::from_u32(value).ok_or_else(|| {
                    WatcherinfoError::XmlParseError("invalid character reference".to_string())
                })?;
                out.push(ch);
            } else {
                return Err(WatcherinfoError::XmlParseError(format!(
                    "unknown entity: &{};",
                    entity
                )));
            }
            idx += end + 1;
        } else {
            let ch = remainder.chars().next().unwrap();
            out.push(ch);
            idx += ch.len_utf8();
        }
    }
    Ok(out)
}

/// Parses a watcherinfo document from XML.
///
/// Note: This is a basic parser. Production use should use a proper XML parser library.
pub fn parse_watcherinfo(xml: &str) -> Result<WatcherinfoDocument, WatcherinfoError> {
    let version = extract_attribute(xml, "<watcherinfo", "version")?
        .ok_or_else(|| WatcherinfoError::XmlParseError("missing version attribute".to_string()))?
        .parse::<u32>()
        .map_err(|_| WatcherinfoError::XmlParseError("invalid version number".to_string()))?;

    let state = extract_attribute(xml, "<watcherinfo", "state")?
        .ok_or_else(|| WatcherinfoError::XmlParseError("missing state attribute".to_string()))?;

    let mut doc = WatcherinfoDocument::new(version, state)?;

    let mut pos = 0;
    while let Some(list_start) = xml[pos..].find("<watcher-list") {
        let abs_start = pos + list_start;
        let list_end = xml[abs_start..].find("</watcher-list>")
            .ok_or_else(|| WatcherinfoError::XmlParseError("unclosed watcher-list".to_string()))?
            + abs_start + 15;
        let list_xml = &xml[abs_start..list_end];

        let list = parse_watcher_list(list_xml)?;
        doc.add_watcher_list(list)?;

        pos = list_end;
    }

    Ok(doc)
}

fn parse_watcher_list(xml: &str) -> Result<WatcherList, WatcherinfoError> {
    let resource = extract_attribute(xml, "<watcher-list", "resource")?
        .ok_or_else(|| WatcherinfoError::XmlParseError("missing resource".to_string()))?;
    let package = extract_attribute(xml, "<watcher-list", "package")?
        .ok_or_else(|| WatcherinfoError::XmlParseError("missing package".to_string()))?;

    let mut list = WatcherList::new(resource, package)?;

    let mut pos = 0;
    while let Some(watcher_start) = xml[pos..].find("<watcher ") {
        let abs_start = pos + watcher_start;
        let watcher_end = xml[abs_start..].find("</watcher>")
            .ok_or_else(|| WatcherinfoError::XmlParseError("unclosed watcher".to_string()))?
            + abs_start + 10;
        let watcher_xml = &xml[abs_start..watcher_end];

        let watcher = parse_watcher(watcher_xml)?;
        list.add_watcher(watcher)?;

        pos = watcher_end;
    }

    Ok(list)
}

fn parse_watcher(xml: &str) -> Result<Watcher, WatcherinfoError> {
    let id = extract_attribute(xml, "<watcher", "id")?
        .ok_or_else(|| WatcherinfoError::XmlParseError("missing id".to_string()))?;
    let status_str = extract_attribute(xml, "<watcher", "status")?
        .ok_or_else(|| WatcherinfoError::XmlParseError("missing status".to_string()))?;
    let event_str = extract_attribute(xml, "<watcher", "event")?
        .ok_or_else(|| WatcherinfoError::XmlParseError("missing event".to_string()))?;

    let status = WatcherStatus::parse(&status_str)
        .ok_or_else(|| WatcherinfoError::XmlParseError(format!("invalid status: {}", status_str)))?;
    let event = WatcherEvent::parse(&event_str)
        .ok_or_else(|| WatcherinfoError::XmlParseError(format!("invalid event: {}", event_str)))?;

    let mut watcher = Watcher::new(id, status, event)?;

    if let Some(display_name) = extract_attribute(xml, "<watcher", "display-name")? {
        watcher = watcher.with_display_name(display_name)?;
    }

    if let Some(expiration) = extract_attribute(xml, "<watcher", "expiration")? {
        if let Ok(exp) = expiration.parse::<u32>() {
            watcher = watcher.with_expiration(exp);
        }
    }

    if let Some(duration) = extract_attribute(xml, "<watcher", "duration-subscribed")? {
        if let Ok(dur) = duration.parse::<u32>() {
            watcher = watcher.with_duration_subscribed(dur);
        }
    }

    if let Some(content_start) = xml.find('>') {
        if let Some(content_end) = xml.find("</watcher>") {
            let uri = xml_unescape(xml[content_start + 1..content_end].trim())?;
            if !uri.is_empty() {
                watcher = watcher.with_uri(uri)?;
            }
        }
    }

    Ok(watcher)
}

fn extract_attribute(
    xml: &str,
    tag_name: &str,
    attr_name: &str,
) -> Result<Option<String>, WatcherinfoError> {
    let tag_start = match xml.find(tag_name) {
        Some(start) => start,
        None => return Ok(None),
    };
    let tag_content = &xml[tag_start..];
    let tag_end = tag_content.find('>').ok_or_else(|| {
        WatcherinfoError::XmlParseError("unterminated tag".to_string())
    })?;
    let tag_str = &tag_content[..tag_end];

    let mut search_idx = 0;
    while let Some(found) = tag_str[search_idx..].find(attr_name) {
        let attr_start = search_idx + found;
        let before_ok = attr_start == 0
            || tag_str[..attr_start]
                .chars()
                .last()
                .map(|c| c.is_whitespace() || c == '<')
                .unwrap_or(true);
        let after_idx = attr_start + attr_name.len();
        let after_char = tag_str[after_idx..].chars().next();
        if !before_ok || matches!(after_char, Some(c) if !c.is_whitespace() && c != '=') {
            search_idx = attr_start + 1;
            continue;
        }

        let mut idx = after_idx;
        while idx < tag_str.len() {
            let ch = tag_str[idx..].chars().next().unwrap();
            if !ch.is_whitespace() {
                break;
            }
            idx += ch.len_utf8();
        }

        if idx >= tag_str.len() || !tag_str[idx..].starts_with('=') {
            search_idx = attr_start + 1;
            continue;
        }
        idx += 1;

        while idx < tag_str.len() {
            let ch = tag_str[idx..].chars().next().unwrap();
            if !ch.is_whitespace() {
                break;
            }
            idx += ch.len_utf8();
        }

        if idx >= tag_str.len() {
            return Err(WatcherinfoError::XmlParseError(
                "unterminated attribute".to_string(),
            ));
        }

        let quote = tag_str[idx..].chars().next().unwrap();
        if quote != '"' && quote != '\'' {
            return Err(WatcherinfoError::XmlParseError(
                "unterminated attribute".to_string(),
            ));
        }
        idx += quote.len_utf8();

        let rest = &tag_str[idx..];
        let end_rel = rest.find(quote).ok_or_else(|| {
            WatcherinfoError::XmlParseError("unterminated attribute".to_string())
        })?;
        let value = &rest[..end_rel];
        return xml_unescape(value).map(Some);
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcherinfo_document_creation() {
        let doc = WatcherinfoDocument::new(0, "full").unwrap();
        assert_eq!(doc.version(), 0);
        assert!(doc.is_full());
        assert!(doc.is_empty());
    }

    #[test]
    fn watcherinfo_rejects_invalid_state() {
        assert!(WatcherinfoDocument::new(0, "invalid").is_err());
        assert!(WatcherinfoDocument::new(0, "").is_err());
    }

    #[test]
    fn watcher_list_creation() {
        let list = WatcherList::new("sip:alice@example.com", "presence").unwrap();
        assert_eq!(list.resource(), "sip:alice@example.com");
        assert_eq!(list.package(), "presence");
        assert!(list.is_empty());
    }

    #[test]
    fn watcher_list_rejects_empty_resource() {
        assert!(WatcherList::new("", "presence").is_err());
    }

    #[test]
    fn watcher_list_rejects_empty_package() {
        assert!(WatcherList::new("sip:alice@example.com", "").is_err());
    }

    #[test]
    fn watcher_list_rejects_too_long_uri() {
        let long_uri = format!("sip:{}", "x".repeat(MAX_URI_LENGTH));
        assert!(WatcherList::new(long_uri, "presence").is_err());
    }

    #[test]
    fn watcher_list_rejects_too_many_watchers() {
        let mut list = WatcherList::new("sip:alice@example.com", "presence").unwrap();
        for i in 0..MAX_WATCHERS_PER_LIST {
            let watcher = Watcher::new(format!("w{}", i), WatcherStatus::Active, WatcherEvent::Approved).unwrap();
            list.add_watcher(watcher).unwrap();
        }
        
        let extra = Watcher::new("extra", WatcherStatus::Active, WatcherEvent::Approved).unwrap();
        assert!(list.add_watcher(extra).is_err());
    }

    #[test]
    fn watcherinfo_rejects_too_many_lists() {
        let mut doc = WatcherinfoDocument::new(0, "full").unwrap();
        for i in 0..MAX_WATCHER_LISTS {
            let list = WatcherList::new(format!("sip:user{}@example.com", i), "presence").unwrap();
            doc.add_watcher_list(list).unwrap();
        }
        
        let extra = WatcherList::new("sip:extra@example.com", "presence").unwrap();
        assert!(doc.add_watcher_list(extra).is_err());
    }

    #[test]
    fn watcher_creation() {
        let watcher = Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
            .unwrap()
            .with_uri("sip:bob@example.com").unwrap()
            .with_display_name("Bob").unwrap()
            .with_expiration(3600);

        assert_eq!(watcher.id(), "w1");
        assert_eq!(watcher.status(), WatcherStatus::Active);
        assert_eq!(watcher.event(), WatcherEvent::Approved);
        assert_eq!(watcher.uri(), Some("sip:bob@example.com"));
        assert_eq!(watcher.display_name(), Some("Bob"));
        assert_eq!(watcher.expiration(), Some(3600));
    }

    #[test]
    fn watcher_rejects_empty_id() {
        assert!(Watcher::new("", WatcherStatus::Active, WatcherEvent::Approved).is_err());
    }

    #[test]
    fn watcher_rejects_too_long_id() {
        let long_id = "x".repeat(MAX_ID_LENGTH + 1);
        assert!(Watcher::new(long_id, WatcherStatus::Active, WatcherEvent::Approved).is_err());
    }

    #[test]
    fn watcher_rejects_control_chars_in_id() {
        assert!(Watcher::new("id\r\n", WatcherStatus::Active, WatcherEvent::Approved).is_err());
    }

    #[test]
    fn watcher_rejects_control_chars_in_uri() {
        let watcher = Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved).unwrap();
        assert!(watcher.with_uri("sip:user\r\n@example.com").is_err());
    }

    #[test]
    fn watcher_rejects_invalid_uri_format() {
        let watcher = Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved).unwrap();
        assert!(watcher.with_uri("not a uri").is_err());
    }

    #[test]
    fn watcher_rejects_control_chars_in_display_name() {
        let watcher = Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved).unwrap();
        assert!(watcher.with_display_name("Name\x00").is_err());
    }

    #[test]
    fn watcherinfo_xml_output() {
        let mut doc = WatcherinfoDocument::new(0, "full").unwrap();
        let mut list = WatcherList::new("sip:alice@example.com", "presence").unwrap();
        list.add_watcher(
            Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
                .unwrap()
                .with_uri("sip:bob@example.com").unwrap(),
        ).unwrap();
        doc.add_watcher_list(list).unwrap();

        let xml = doc.to_xml();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<watcherinfo"));
        assert!(xml.contains("version=\"0\""));
        assert!(xml.contains("state=\"full\""));
    }

    #[test]
    fn xml_escape_basic() {
        assert_eq!(xml_escape("<test>"), "&lt;test&gt;");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn xml_escape_control_chars() {
        let escaped = xml_escape("test\x00value");
        assert!(escaped.contains("&#x"));
    }

    #[test]
    fn parse_simple_watcherinfo() {
        let xml = r#"<?xml version="1.0"?>
<watcherinfo xmlns="urn:ietf:params:xml:ns:watcherinfo" version="0" state="full">
  <watcher-list resource="sip:alice@example.com" package="presence">
    <watcher id="w1" status="active" event="approved">sip:bob@example.com</watcher>
  </watcher-list>
</watcherinfo>"#;

        let doc = parse_watcherinfo(xml).unwrap();
        assert_eq!(doc.version(), 0);
        assert_eq!(doc.state(), "full");
        assert_eq!(doc.watcher_lists().len(), 1);
    }

    #[test]
    fn parse_watcherinfo_single_quotes() {
        let xml = r#"<?xml version='1.0'?>
<watcherinfo xmlns='urn:ietf:params:xml:ns:watcherinfo' version = '0' state = 'full'>
  <watcher-list resource = 'sip:alice@example.com' package = 'presence'>
    <watcher id = 'w1' status = 'active' event = 'approved'>sip:bob@example.com</watcher>
  </watcher-list>
</watcherinfo>"#;

        let doc = parse_watcherinfo(xml).unwrap();
        assert_eq!(doc.version(), 0);
        assert_eq!(doc.state(), "full");
        assert_eq!(doc.watcher_lists().len(), 1);
    }

    #[test]
    fn round_trip() {
        let mut doc = WatcherinfoDocument::new(0, "full").unwrap();
        let mut list = WatcherList::new("sip:alice@example.com", "presence").unwrap();
        list.add_watcher(
            Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
                .unwrap()
                .with_uri("sip:bob@example.com").unwrap(),
        ).unwrap();
        doc.add_watcher_list(list).unwrap();

        let xml = doc.to_xml();
        let parsed = parse_watcherinfo(&xml).unwrap();

        assert_eq!(doc.version(), parsed.version());
        assert_eq!(doc.state(), parsed.state());
        assert_eq!(doc.watcher_lists().len(), parsed.watcher_lists().len());
    }

    #[test]
    fn fields_are_private() {
        let doc = WatcherinfoDocument::new(0, "full").unwrap();
        
        // These should compile (read access via getters)
        let _ = doc.version();
        let _ = doc.state();
        let _ = doc.watcher_lists();
        
        // These should NOT compile:
        // doc.version = 5;                     // ← Does not compile!
        // doc.watcher_lists.push(...);         // ← Does not compile!
    }

    #[test]
    fn error_display() {
        let err1 = WatcherinfoError::InvalidState("test".to_string());
        assert_eq!(err1.to_string(), "Invalid state: test");
        
        let err2 = WatcherinfoError::TooManyItems {
            field: "watchers",
            max: 1000,
        };
        assert_eq!(err2.to_string(), "Too many watchers (max 1000)");
    }
}
