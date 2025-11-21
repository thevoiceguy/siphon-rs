/// RFC 3856/3859/3863 Presence support for SIP.
///
/// This module implements:
/// - RFC 3856: Presence Event Package for SIP
/// - RFC 3859: Common Profile for Presence (CPP)
/// - RFC 3863: Presence Information Data Format (PIDF)
///
/// # Overview
///
/// Presence represents the willingness and ability of a user to communicate
/// with other users on the network. PIDF (Presence Information Data Format)
/// is an XML-based format for conveying presence information.
///
/// # RFC Summary
///
/// - Event package name: "presence"
/// - MIME type: application/pidf+xml
/// - Default subscription duration: 3600 seconds (1 hour)
/// - Basic status values: open, closed
///
/// # Examples
///
/// ```
/// use sip_core::{PresenceDocument, Tuple, BasicStatus};
///
/// // Create a presence document
/// let mut doc = PresenceDocument::new("pres:alice@example.com");
///
/// let tuple = Tuple::new("t1")
///     .with_status(BasicStatus::Open)
///     .with_contact("sip:alice@192.168.1.100")
///     .with_note("Available");
///
/// doc.add_tuple(tuple);
///
/// // Format as application/pidf+xml
/// let xml = doc.to_xml();
/// ```

use smol_str::SmolStr;
use std::fmt;

/// RFC 3863 PIDF Presence Document.
///
/// A presence document conveys presence information about a presentity
/// (the entity whose presence is being reported). It contains one or more
/// tuples, each describing a communication endpoint or status.
#[derive(Debug, Clone, PartialEq)]
pub struct PresenceDocument {
    /// The entity URI (presentity)
    pub entity: SmolStr,
    /// List of presence tuples
    pub tuples: Vec<Tuple>,
    /// Optional notes about the presentity
    pub notes: Vec<SmolStr>,
}

impl PresenceDocument {
    /// Creates a new presence document for the given entity.
    pub fn new(entity: impl Into<SmolStr>) -> Self {
        Self {
            entity: entity.into(),
            tuples: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Adds a tuple to the presence document.
    pub fn add_tuple(&mut self, tuple: Tuple) {
        self.tuples.push(tuple);
    }

    /// Adds a note to the presence document.
    pub fn add_note(&mut self, note: impl Into<SmolStr>) {
        self.notes.push(note.into());
    }

    /// Returns true if there are no tuples.
    pub fn is_empty(&self) -> bool {
        self.tuples.is_empty()
    }

    /// Returns the basic status from the first tuple, if any.
    pub fn basic_status(&self) -> Option<BasicStatus> {
        self.tuples.first().and_then(|t| t.status)
    }

    /// Formats the presence document as application/pidf+xml.
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();

        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"");
        xml.push_str(&xml_escape(&self.entity));
        xml.push_str("\">\n");

        // Tuples
        for tuple in &self.tuples {
            xml.push_str(&tuple.to_xml());
        }

        // Document-level notes
        for note in &self.notes {
            xml.push_str("  <note>");
            xml.push_str(&xml_escape(note));
            xml.push_str("</note>\n");
        }

        xml.push_str("</presence>\n");
        xml
    }
}

impl fmt::Display for PresenceDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_xml())
    }
}

/// RFC 3863 Presence Tuple.
///
/// A tuple represents a single communication endpoint or aspect of presence.
/// Each tuple contains status information, optional contact address, notes,
/// and timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct Tuple {
    /// Tuple identifier (must be unique within document)
    pub id: SmolStr,
    /// Basic status (open or closed)
    pub status: Option<BasicStatus>,
    /// Contact URI for this tuple
    pub contact: Option<SmolStr>,
    /// Optional notes about this tuple
    pub notes: Vec<SmolStr>,
    /// Optional timestamp
    pub timestamp: Option<SmolStr>,
}

impl Tuple {
    /// Creates a new tuple with the given ID.
    pub fn new(id: impl Into<SmolStr>) -> Self {
        Self {
            id: id.into(),
            status: None,
            contact: None,
            notes: Vec::new(),
            timestamp: None,
        }
    }

    /// Sets the basic status (builder pattern).
    pub fn with_status(mut self, status: BasicStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the contact URI (builder pattern).
    pub fn with_contact(mut self, contact: impl Into<SmolStr>) -> Self {
        self.contact = Some(contact.into());
        self
    }

    /// Adds a note (builder pattern).
    pub fn with_note(mut self, note: impl Into<SmolStr>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Sets the timestamp (builder pattern).
    pub fn with_timestamp(mut self, timestamp: impl Into<SmolStr>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    /// Formats the tuple as XML.
    fn to_xml(&self) -> String {
        let mut xml = String::new();

        xml.push_str("  <tuple id=\"");
        xml.push_str(&xml_escape(&self.id));
        xml.push_str("\">\n");

        // Status
        if let Some(status) = self.status {
            xml.push_str("    <status>\n");
            xml.push_str("      <basic>");
            xml.push_str(status.as_str());
            xml.push_str("</basic>\n");
            xml.push_str("    </status>\n");
        }

        // Contact
        if let Some(ref contact) = self.contact {
            xml.push_str("    <contact>");
            xml.push_str(&xml_escape(contact));
            xml.push_str("</contact>\n");
        }

        // Notes
        for note in &self.notes {
            xml.push_str("    <note>");
            xml.push_str(&xml_escape(note));
            xml.push_str("</note>\n");
        }

        // Timestamp
        if let Some(ref timestamp) = self.timestamp {
            xml.push_str("    <timestamp>");
            xml.push_str(&xml_escape(timestamp));
            xml.push_str("</timestamp>\n");
        }

        xml.push_str("  </tuple>\n");
        xml
    }
}

/// RFC 3863 Basic Presence Status.
///
/// The basic status indicates whether a presentity is available for
/// communication. Per RFC 3863, the two basic values are "open" and "closed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BasicStatus {
    /// The presentity is available for communication
    Open,
    /// The presentity is not available for communication
    Closed,
}

impl BasicStatus {
    /// Returns the string representation for XML.
    pub fn as_str(&self) -> &str {
        match self {
            BasicStatus::Open => "open",
            BasicStatus::Closed => "closed",
        }
    }

    /// Parses a basic status from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "open" => Some(BasicStatus::Open),
            "closed" => Some(BasicStatus::Closed),
            _ => None,
        }
    }
}

impl fmt::Display for BasicStatus {
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

/// Parses a PIDF presence document from XML.
///
/// This is a basic parser that extracts entity, tuples, status, and notes.
/// A full implementation would use a proper XML parser.
pub fn parse_pidf(xml: &str) -> Option<PresenceDocument> {
    // Very basic parsing - a real implementation should use an XML parser
    let entity = extract_attribute(xml, "<presence", "entity")?;
    let mut doc = PresenceDocument::new(entity);

    // Extract tuples
    let mut pos = 0;
    while let Some(tuple_start) = xml[pos..].find("<tuple") {
        let abs_start = pos + tuple_start;
        let tuple_end = xml[abs_start..].find("</tuple>")? + abs_start + 8;
        let tuple_xml = &xml[abs_start..tuple_end];

        if let Some(tuple) = parse_tuple(tuple_xml) {
            doc.add_tuple(tuple);
        }

        pos = tuple_end;
    }

    Some(doc)
}

/// Parses a single tuple from XML.
fn parse_tuple(xml: &str) -> Option<Tuple> {
    let id = extract_attribute(xml, "<tuple", "id")?;
    let mut tuple = Tuple::new(id);

    // Extract status
    if let Some(basic_start) = xml.find("<basic>") {
        if let Some(basic_end) = xml.find("</basic>") {
            let status_str = &xml[basic_start + 7..basic_end].trim();
            tuple.status = BasicStatus::from_str(status_str);
        }
    }

    // Extract contact
    if let Some(contact) = extract_element(xml, "contact") {
        tuple.contact = Some(SmolStr::new(&contact));
    }

    // Extract notes
    let mut pos = 0;
    while let Some(note_start) = xml[pos..].find("<note>") {
        let abs_start = pos + note_start;
        if let Some(note_end) = xml[abs_start..].find("</note>") {
            let note = &xml[abs_start + 6..abs_start + note_end].trim();
            tuple.notes.push(SmolStr::new(note));
            pos = abs_start + note_end + 7;
        } else {
            break;
        }
    }

    // Extract timestamp
    if let Some(timestamp) = extract_element(xml, "timestamp") {
        tuple.timestamp = Some(SmolStr::new(&timestamp));
    }

    Some(tuple)
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

/// Extracts an XML element content.
fn extract_element(xml: &str, element_name: &str) -> Option<String> {
    let start_tag = format!("<{}>", element_name);
    let end_tag = format!("</{}>", element_name);

    let content_start = xml.find(&start_tag)? + start_tag.len();
    let content_end = xml.find(&end_tag)?;

    Some(xml[content_start..content_end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_document_creation() {
        let doc = PresenceDocument::new("pres:alice@example.com");
        assert_eq!(doc.entity, "pres:alice@example.com");
        assert!(doc.is_empty());
    }

    #[test]
    fn tuple_creation() {
        let tuple = Tuple::new("t1")
            .with_status(BasicStatus::Open)
            .with_contact("sip:alice@192.168.1.100")
            .with_note("Available");

        assert_eq!(tuple.id, "t1");
        assert_eq!(tuple.status, Some(BasicStatus::Open));
        assert_eq!(tuple.contact, Some(SmolStr::new("sip:alice@192.168.1.100")));
        assert_eq!(tuple.notes.len(), 1);
    }

    #[test]
    fn basic_status_values() {
        assert_eq!(BasicStatus::Open.as_str(), "open");
        assert_eq!(BasicStatus::Closed.as_str(), "closed");

        assert_eq!(BasicStatus::from_str("open"), Some(BasicStatus::Open));
        assert_eq!(BasicStatus::from_str("CLOSED"), Some(BasicStatus::Closed));
        assert_eq!(BasicStatus::from_str("invalid"), None);
    }

    #[test]
    fn xml_escaping() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("\"quotes\""), "&quot;quotes&quot;");
    }

    #[test]
    fn presence_document_xml_output() {
        let mut doc = PresenceDocument::new("pres:alice@example.com");

        let tuple = Tuple::new("t1")
            .with_status(BasicStatus::Open)
            .with_contact("sip:alice@192.168.1.100")
            .with_note("Available");

        doc.add_tuple(tuple);

        let xml = doc.to_xml();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<presence"));
        assert!(xml.contains("entity=\"pres:alice@example.com\""));
        assert!(xml.contains("<tuple id=\"t1\""));
        assert!(xml.contains("<basic>open</basic>"));
        assert!(xml.contains("<contact>sip:alice@192.168.1.100</contact>"));
        assert!(xml.contains("<note>Available</note>"));
        assert!(xml.contains("</tuple>"));
        assert!(xml.contains("</presence>"));
    }

    #[test]
    fn presence_document_multiple_tuples() {
        let mut doc = PresenceDocument::new("pres:alice@example.com");

        doc.add_tuple(
            Tuple::new("t1")
                .with_status(BasicStatus::Open)
                .with_contact("sip:alice@work.example.com"),
        );

        doc.add_tuple(
            Tuple::new("t2")
                .with_status(BasicStatus::Closed)
                .with_contact("sip:alice@home.example.com"),
        );

        assert_eq!(doc.tuples.len(), 2);

        let xml = doc.to_xml();
        assert!(xml.contains("t1"));
        assert!(xml.contains("t2"));
        assert!(xml.contains("open"));
        assert!(xml.contains("closed"));
    }

    #[test]
    fn tuple_with_timestamp() {
        let tuple = Tuple::new("t1")
            .with_status(BasicStatus::Open)
            .with_timestamp("2023-11-21T12:00:00Z");

        let xml = tuple.to_xml();
        assert!(xml.contains("<timestamp>2023-11-21T12:00:00Z</timestamp>"));
    }

    #[test]
    fn presence_document_with_notes() {
        let mut doc = PresenceDocument::new("pres:alice@example.com");
        doc.add_note("Away from desk");

        let xml = doc.to_xml();
        assert!(xml.contains("<note>Away from desk</note>"));
    }

    #[test]
    fn parse_simple_pidf() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:alice@example.com">
  <tuple id="t1">
    <status>
      <basic>open</basic>
    </status>
    <contact>sip:alice@192.168.1.100</contact>
    <note>Available</note>
  </tuple>
</presence>"#;

        let doc = parse_pidf(xml).unwrap();
        assert_eq!(doc.entity, "pres:alice@example.com");
        assert_eq!(doc.tuples.len(), 1);

        let tuple = &doc.tuples[0];
        assert_eq!(tuple.id, "t1");
        assert_eq!(tuple.status, Some(BasicStatus::Open));
        assert_eq!(tuple.contact, Some(SmolStr::new("sip:alice@192.168.1.100")));
        assert_eq!(tuple.notes.len(), 1);
    }

    #[test]
    fn round_trip_pidf() {
        let mut doc = PresenceDocument::new("pres:alice@example.com");
        doc.add_tuple(
            Tuple::new("t1")
                .with_status(BasicStatus::Open)
                .with_contact("sip:alice@192.168.1.100")
                .with_note("Available"),
        );

        let xml = doc.to_xml();
        let parsed = parse_pidf(&xml).unwrap();

        assert_eq!(doc.entity, parsed.entity);
        assert_eq!(doc.tuples.len(), parsed.tuples.len());
        assert_eq!(doc.tuples[0].id, parsed.tuples[0].id);
        assert_eq!(doc.tuples[0].status, parsed.tuples[0].status);
    }

    #[test]
    fn basic_status_from_first_tuple() {
        let mut doc = PresenceDocument::new("pres:alice@example.com");
        assert_eq!(doc.basic_status(), None);

        doc.add_tuple(Tuple::new("t1").with_status(BasicStatus::Open));
        assert_eq!(doc.basic_status(), Some(BasicStatus::Open));
    }
}
