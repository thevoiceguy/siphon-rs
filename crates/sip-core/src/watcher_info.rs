/// RFC 3857/3858 Watcher Information support for SIP.
///
/// This module implements:
/// - RFC 3857: Watcher Information Event Template-Package for SIP
/// - RFC 3858: XML-Based Format for Watcher Information
///
/// # Overview
///
/// Watcher information provides visibility into who is subscribing to a resource.
/// This enables use cases like presence authorization (seeing who wants to see
/// your presence) and subscription management.
///
/// # RFC Summary
///
/// - Event package naming: "<package>.winfo" (e.g., "presence.winfo")
/// - MIME type: application/watcherinfo+xml
/// - Default subscription duration: 3600 seconds (1 hour)
/// - Watcher states: pending, active, waiting, terminated
/// - Event types: subscribe, approved, deactivated, rejected, etc.
///
/// # Examples
///
/// ```
/// use sip_core::{WatcherinfoDocument, WatcherList, Watcher, WatcherStatus, WatcherEvent};
///
/// // Create a watcherinfo document
/// let mut doc = WatcherinfoDocument::new(0, "full");
///
/// let mut list = WatcherList::new("sip:alice@example.com", "presence");
/// list.add_watcher(
///     Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
///         .with_uri("sip:bob@example.com")
/// );
///
/// doc.add_watcher_list(list);
///
/// // Format as application/watcherinfo+xml
/// let xml = doc.to_xml();
/// ```

use smol_str::SmolStr;
use std::fmt;

/// RFC 3858 Watcherinfo Document.
///
/// A watcherinfo document conveys information about watchers (subscribers)
/// to a resource. It contains one or more watcher lists, each describing
/// subscriptions to a specific resource within an event package.
#[derive(Debug, Clone, PartialEq)]
pub struct WatcherinfoDocument {
    /// Version number (increments with each update)
    pub version: u32,
    /// State: "full" or "partial"
    pub state: SmolStr,
    /// List of watcher lists
    pub watcher_lists: Vec<WatcherList>,
}

impl WatcherinfoDocument {
    /// Creates a new watcherinfo document.
    pub fn new(version: u32, state: impl Into<SmolStr>) -> Self {
        Self {
            version,
            state: state.into(),
            watcher_lists: Vec::new(),
        }
    }

    /// Adds a watcher list to the document.
    pub fn add_watcher_list(&mut self, list: WatcherList) {
        self.watcher_lists.push(list);
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

        // Watcher lists
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
/// A watcher list represents all subscriptions to a specific resource
/// within a specific event package.
#[derive(Debug, Clone, PartialEq)]
pub struct WatcherList {
    /// Resource URI being watched
    pub resource: SmolStr,
    /// Event package name
    pub package: SmolStr,
    /// List of watchers
    pub watchers: Vec<Watcher>,
}

impl WatcherList {
    /// Creates a new watcher list.
    pub fn new(resource: impl Into<SmolStr>, package: impl Into<SmolStr>) -> Self {
        Self {
            resource: resource.into(),
            package: package.into(),
            watchers: Vec::new(),
        }
    }

    /// Adds a watcher to the list.
    pub fn add_watcher(&mut self, watcher: Watcher) {
        self.watchers.push(watcher);
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

        // Watchers
        for watcher in &self.watchers {
            xml.push_str(&watcher.to_xml());
        }

        xml.push_str("  </watcher-list>\n");
        xml
    }
}

/// RFC 3858 Watcher element.
///
/// Represents a single watcher (subscriber) with their status, event,
/// and optional metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Watcher {
    /// Watcher identifier (unique within list)
    pub id: SmolStr,
    /// Current status
    pub status: WatcherStatus,
    /// Event that caused this status
    pub event: WatcherEvent,
    /// Watcher URI
    pub uri: Option<SmolStr>,
    /// Display name
    pub display_name: Option<SmolStr>,
    /// Expiration time in seconds
    pub expiration: Option<u32>,
    /// Duration subscribed in seconds
    pub duration_subscribed: Option<u32>,
}

impl Watcher {
    /// Creates a new watcher.
    pub fn new(id: impl Into<SmolStr>, status: WatcherStatus, event: WatcherEvent) -> Self {
        Self {
            id: id.into(),
            status,
            event,
            uri: None,
            display_name: None,
            expiration: None,
            duration_subscribed: None,
        }
    }

    /// Sets the watcher URI (builder pattern).
    pub fn with_uri(mut self, uri: impl Into<SmolStr>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Sets the display name (builder pattern).
    pub fn with_display_name(mut self, name: impl Into<SmolStr>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Sets the expiration time (builder pattern).
    pub fn with_expiration(mut self, seconds: u32) -> Self {
        self.expiration = Some(seconds);
        self
    }

    /// Sets the duration subscribed (builder pattern).
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
        xml.push_str("\"");

        // Optional attributes
        if let Some(ref display_name) = self.display_name {
            xml.push_str(" display-name=\"");
            xml.push_str(&xml_escape(display_name));
            xml.push_str("\"");
        }

        if let Some(expiration) = self.expiration {
            xml.push_str(" expiration=\"");
            xml.push_str(&expiration.to_string());
            xml.push_str("\"");
        }

        if let Some(duration) = self.duration_subscribed {
            xml.push_str(" duration-subscribed=\"");
            xml.push_str(&duration.to_string());
            xml.push_str("\"");
        }

        xml.push('>');

        // Watcher URI (element content)
        if let Some(ref uri) = self.uri {
            xml.push_str(&xml_escape(uri));
        }

        xml.push_str("</watcher>\n");
        xml
    }
}

/// RFC 3858 Watcher Status.
///
/// Represents the current state of a watcher's subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatcherStatus {
    /// Subscription is pending authorization
    Pending,
    /// Subscription is active
    Active,
    /// Subscription is temporarily suspended
    Waiting,
    /// Subscription has been terminated
    Terminated,
}

impl WatcherStatus {
    /// Returns the string representation for XML.
    pub fn as_str(&self) -> &str {
        match self {
            WatcherStatus::Pending => "pending",
            WatcherStatus::Active => "active",
            WatcherStatus::Waiting => "waiting",
            WatcherStatus::Terminated => "terminated",
        }
    }

    /// Parses a watcher status from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pending" => Some(WatcherStatus::Pending),
            "active" => Some(WatcherStatus::Active),
            "waiting" => Some(WatcherStatus::Waiting),
            "terminated" => Some(WatcherStatus::Terminated),
            _ => None,
        }
    }
}

impl fmt::Display for WatcherStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// RFC 3858 Watcher Event.
///
/// Represents the event that caused the current watcher status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatcherEvent {
    /// Subscription request received
    Subscribe,
    /// Subscription was approved
    Approved,
    /// Subscription was deactivated
    Deactivated,
    /// Subscription is in probation period
    Probation,
    /// Subscription was rejected
    Rejected,
    /// Subscription timed out
    Timeout,
    /// Watcher gave up (unsubscribed)
    Giveup,
    /// Resource no longer exists
    Noresource,
}

impl WatcherEvent {
    /// Returns the string representation for XML.
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

    /// Parses a watcher event from a string.
    pub fn from_str(s: &str) -> Option<Self> {
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

impl fmt::Display for WatcherEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Escapes XML special characters.
fn xml_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Parses a watcherinfo document from XML.
///
/// This is a basic parser that extracts version, state, and watcher lists.
/// A full implementation would use a proper XML parser.
pub fn parse_watcherinfo(xml: &str) -> Option<WatcherinfoDocument> {
    // Basic parsing - a real implementation should use an XML parser
    let version = extract_attribute(xml, "<watcherinfo", "version")?
        .parse::<u32>()
        .ok()?;
    let state = extract_attribute(xml, "<watcherinfo", "state")?;

    let mut doc = WatcherinfoDocument::new(version, state);

    // Extract watcher lists
    let mut pos = 0;
    while let Some(list_start) = xml[pos..].find("<watcher-list") {
        let abs_start = pos + list_start;
        let list_end = xml[abs_start..].find("</watcher-list>")? + abs_start + 15;
        let list_xml = &xml[abs_start..list_end];

        if let Some(list) = parse_watcher_list(list_xml) {
            doc.add_watcher_list(list);
        }

        pos = list_end;
    }

    Some(doc)
}

/// Parses a single watcher list from XML.
fn parse_watcher_list(xml: &str) -> Option<WatcherList> {
    let resource = extract_attribute(xml, "<watcher-list", "resource")?;
    let package = extract_attribute(xml, "<watcher-list", "package")?;

    let mut list = WatcherList::new(resource, package);

    // Extract watchers
    let mut pos = 0;
    while let Some(watcher_start) = xml[pos..].find("<watcher ") {
        let abs_start = pos + watcher_start;
        let watcher_end = xml[abs_start..].find("</watcher>")? + abs_start + 10;
        let watcher_xml = &xml[abs_start..watcher_end];

        if let Some(watcher) = parse_watcher(watcher_xml) {
            list.add_watcher(watcher);
        }

        pos = watcher_end;
    }

    Some(list)
}

/// Parses a single watcher from XML.
fn parse_watcher(xml: &str) -> Option<Watcher> {
    let id = extract_attribute(xml, "<watcher", "id")?;
    let status_str = extract_attribute(xml, "<watcher", "status")?;
    let event_str = extract_attribute(xml, "<watcher", "event")?;

    let status = WatcherStatus::from_str(&status_str)?;
    let event = WatcherEvent::from_str(&event_str)?;

    let mut watcher = Watcher::new(id, status, event);

    // Extract optional attributes
    if let Some(display_name) = extract_attribute(xml, "<watcher", "display-name") {
        watcher.display_name = Some(SmolStr::new(&display_name));
    }

    if let Some(expiration) = extract_attribute(xml, "<watcher", "expiration") {
        if let Ok(exp) = expiration.parse::<u32>() {
            watcher.expiration = Some(exp);
        }
    }

    if let Some(duration) = extract_attribute(xml, "<watcher", "duration-subscribed") {
        if let Ok(dur) = duration.parse::<u32>() {
            watcher.duration_subscribed = Some(dur);
        }
    }

    // Extract watcher URI (element content)
    if let Some(content_start) = xml.find('>') {
        if let Some(content_end) = xml.find("</watcher>") {
            let uri = xml[content_start + 1..content_end].trim();
            if !uri.is_empty() {
                watcher.uri = Some(SmolStr::new(uri));
            }
        }
    }

    Some(watcher)
}

/// Extracts an XML attribute value.
fn extract_attribute(xml: &str, tag_name: &str, attr_name: &str) -> Option<String> {
    let tag_start = xml.find(tag_name)?;
    let tag_content = &xml[tag_start..];
    let tag_end = tag_content.find('>')?;
    let tag_str = &tag_content[..tag_end];

    let attr_start = tag_str.find(&format!("{}=\"", attr_name))?;
    let value_start = attr_start + attr_name.len() + 2;
    let value_end = tag_str[value_start..].find('"')?;
    Some(tag_str[value_start..value_start + value_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcherinfo_document_creation() {
        let doc = WatcherinfoDocument::new(0, "full");
        assert_eq!(doc.version, 0);
        assert!(doc.is_full());
        assert!(doc.is_empty());
    }

    #[test]
    fn watcher_list_creation() {
        let list = WatcherList::new("sip:alice@example.com", "presence");
        assert_eq!(list.resource, "sip:alice@example.com");
        assert_eq!(list.package, "presence");
        assert!(list.is_empty());
    }

    #[test]
    fn watcher_creation() {
        let watcher = Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
            .with_uri("sip:bob@example.com")
            .with_display_name("Bob")
            .with_expiration(3600);

        assert_eq!(watcher.id, "w1");
        assert_eq!(watcher.status, WatcherStatus::Active);
        assert_eq!(watcher.event, WatcherEvent::Approved);
        assert_eq!(watcher.uri, Some(SmolStr::new("sip:bob@example.com")));
        assert_eq!(watcher.display_name, Some(SmolStr::new("Bob")));
        assert_eq!(watcher.expiration, Some(3600));
    }

    #[test]
    fn watcher_status_values() {
        assert_eq!(WatcherStatus::Pending.as_str(), "pending");
        assert_eq!(WatcherStatus::Active.as_str(), "active");
        assert_eq!(WatcherStatus::Waiting.as_str(), "waiting");
        assert_eq!(WatcherStatus::Terminated.as_str(), "terminated");

        assert_eq!(WatcherStatus::from_str("active"), Some(WatcherStatus::Active));
        assert_eq!(WatcherStatus::from_str("PENDING"), Some(WatcherStatus::Pending));
        assert_eq!(WatcherStatus::from_str("invalid"), None);
    }

    #[test]
    fn watcher_event_values() {
        assert_eq!(WatcherEvent::Subscribe.as_str(), "subscribe");
        assert_eq!(WatcherEvent::Approved.as_str(), "approved");
        assert_eq!(WatcherEvent::Rejected.as_str(), "rejected");

        assert_eq!(WatcherEvent::from_str("approved"), Some(WatcherEvent::Approved));
        assert_eq!(WatcherEvent::from_str("TIMEOUT"), Some(WatcherEvent::Timeout));
        assert_eq!(WatcherEvent::from_str("invalid"), None);
    }

    #[test]
    fn watcherinfo_xml_output() {
        let mut doc = WatcherinfoDocument::new(0, "full");

        let mut list = WatcherList::new("sip:alice@example.com", "presence");
        list.add_watcher(
            Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
                .with_uri("sip:bob@example.com"),
        );

        doc.add_watcher_list(list);

        let xml = doc.to_xml();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<watcherinfo"));
        assert!(xml.contains("version=\"0\""));
        assert!(xml.contains("state=\"full\""));
        assert!(xml.contains("<watcher-list"));
        assert!(xml.contains("resource=\"sip:alice@example.com\""));
        assert!(xml.contains("package=\"presence\""));
        assert!(xml.contains("<watcher"));
        assert!(xml.contains("id=\"w1\""));
        assert!(xml.contains("status=\"active\""));
        assert!(xml.contains("event=\"approved\""));
        assert!(xml.contains("sip:bob@example.com"));
        assert!(xml.contains("</watcher>"));
        assert!(xml.contains("</watcher-list>"));
        assert!(xml.contains("</watcherinfo>"));
    }

    #[test]
    fn multiple_watchers() {
        let mut list = WatcherList::new("sip:alice@example.com", "presence");

        list.add_watcher(
            Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
                .with_uri("sip:bob@example.com"),
        );

        list.add_watcher(
            Watcher::new("w2", WatcherStatus::Pending, WatcherEvent::Subscribe)
                .with_uri("sip:carol@example.com"),
        );

        assert_eq!(list.watchers.len(), 2);
    }

    #[test]
    fn partial_state_document() {
        let doc = WatcherinfoDocument::new(5, "partial");
        assert_eq!(doc.version, 5);
        assert!(doc.is_partial());
        assert!(!doc.is_full());
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
        assert_eq!(doc.version, 0);
        assert_eq!(doc.state, "full");
        assert_eq!(doc.watcher_lists.len(), 1);

        let list = &doc.watcher_lists[0];
        assert_eq!(list.resource, "sip:alice@example.com");
        assert_eq!(list.package, "presence");
        assert_eq!(list.watchers.len(), 1);

        let watcher = &list.watchers[0];
        assert_eq!(watcher.id, "w1");
        assert_eq!(watcher.status, WatcherStatus::Active);
        assert_eq!(watcher.event, WatcherEvent::Approved);
        assert_eq!(watcher.uri, Some(SmolStr::new("sip:bob@example.com")));
    }

    #[test]
    fn round_trip_watcherinfo() {
        let mut doc = WatcherinfoDocument::new(0, "full");
        let mut list = WatcherList::new("sip:alice@example.com", "presence");
        list.add_watcher(
            Watcher::new("w1", WatcherStatus::Active, WatcherEvent::Approved)
                .with_uri("sip:bob@example.com"),
        );
        doc.add_watcher_list(list);

        let xml = doc.to_xml();
        let parsed = parse_watcherinfo(&xml).unwrap();

        assert_eq!(doc.version, parsed.version);
        assert_eq!(doc.state, parsed.state);
        assert_eq!(doc.watcher_lists.len(), parsed.watcher_lists.len());
    }
}
