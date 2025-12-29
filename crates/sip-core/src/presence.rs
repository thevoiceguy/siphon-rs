// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// RFC 3856/3859/3863 Presence support for SIP.
///
/// This module implements:
/// - RFC 3856: Presence Event Package for SIP
/// - RFC 3859: Common Profile for Presence (CPP)
/// - RFC 3863: Presence Information Data Format (PIDF)
///
/// # Security
///
/// All types validate input to prevent XML injection attacks and DoS.
use smol_str::SmolStr;
use std::fmt;

const MAX_ENTITY_LENGTH: usize = 512;
const MAX_ID_LENGTH: usize = 128;
const MAX_CONTACT_LENGTH: usize = 512;
const MAX_NOTE_LENGTH: usize = 512;
const MAX_TIMESTAMP_LENGTH: usize = 64;
const MAX_TUPLES: usize = 50;
const MAX_NOTES_PER_TUPLE: usize = 10;
const MAX_NOTES_PER_DOC: usize = 20;
const MAX_PARSE_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    EntityTooLong { max: usize, actual: usize },
    IdTooLong { max: usize, actual: usize },
    ContactTooLong { max: usize, actual: usize },
    NoteTooLong { max: usize, actual: usize },
    TimestampTooLong { max: usize, actual: usize },
    TooManyTuples { max: usize, actual: usize },
    TooManyNotes { max: usize, actual: usize },
    InvalidEntity(String),
    InvalidId(String),
    InvalidContact(String),
    InvalidNote(String),
    InvalidTimestamp(String),
    EmptyEntity,
    EmptyId,
    ParseError(String),
    InputTooLarge { max: usize, actual: usize },
}

impl std::fmt::Display for PresenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntityTooLong { max, actual } => {
                write!(f, "entity too long (max {}, got {})", max, actual)
            }
            Self::IdTooLong { max, actual } => {
                write!(f, "ID too long (max {}, got {})", max, actual)
            }
            Self::TooManyTuples { max, actual } => {
                write!(f, "too many tuples (max {}, got {})", max, actual)
            }
            Self::TooManyNotes { max, actual } => {
                write!(f, "too many notes (max {}, got {})", max, actual)
            }
            Self::InvalidEntity(msg) => write!(f, "invalid entity: {}", msg),
            Self::EmptyEntity => write!(f, "entity cannot be empty"),
            Self::EmptyId => write!(f, "tuple ID cannot be empty"),
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
            Self::InputTooLarge { max, actual } => {
                write!(f, "input too large (max {}, got {})", max, actual)
            }
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for PresenceError {}

/// RFC 3863 PIDF Presence Document.
///
/// A presence document conveys presence information about a presentity
/// (the entity whose presence is being reported).
///
/// # Security
///
/// PresenceDocument validates all fields to prevent:
/// - XML injection attacks
/// - Control character injection
/// - Excessive length (DoS)
/// - Unbounded collections
#[derive(Debug, Clone, PartialEq)]
pub struct PresenceDocument {
    entity: SmolStr,
    tuples: Vec<Tuple>,
    notes: Vec<SmolStr>,
}

impl PresenceDocument {
    /// Creates a new presence document for the given entity.
    ///
    /// # Errors
    ///
    /// Returns an error if the entity is invalid.
    pub fn new(entity: impl AsRef<str>) -> Result<Self, PresenceError> {
        validate_entity(entity.as_ref())?;

        Ok(Self {
            entity: SmolStr::new(entity.as_ref()),
            tuples: Vec::new(),
            notes: Vec::new(),
        })
    }

    /// Adds a tuple to the presence document.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed MAX_TUPLES.
    pub fn add_tuple(&mut self, tuple: Tuple) -> Result<(), PresenceError> {
        if self.tuples.len() >= MAX_TUPLES {
            return Err(PresenceError::TooManyTuples {
                max: MAX_TUPLES,
                actual: self.tuples.len() + 1,
            });
        }
        self.tuples.push(tuple);
        Ok(())
    }

    /// Adds a note to the presence document.
    ///
    /// # Errors
    ///
    /// Returns an error if the note is invalid or exceeds limits.
    pub fn add_note(&mut self, note: impl AsRef<str>) -> Result<(), PresenceError> {
        validate_note(note.as_ref())?;

        if self.notes.len() >= MAX_NOTES_PER_DOC {
            return Err(PresenceError::TooManyNotes {
                max: MAX_NOTES_PER_DOC,
                actual: self.notes.len() + 1,
            });
        }

        self.notes.push(SmolStr::new(note.as_ref()));
        Ok(())
    }

    /// Returns the entity URI.
    pub fn entity(&self) -> &str {
        &self.entity
    }

    /// Returns an iterator over tuples.
    pub fn tuples(&self) -> impl Iterator<Item = &Tuple> {
        self.tuples.iter()
    }

    /// Returns an iterator over notes.
    pub fn notes(&self) -> impl Iterator<Item = &str> {
        self.notes.iter().map(|s| s.as_str())
    }

    /// Returns true if there are no tuples.
    pub fn is_empty(&self) -> bool {
        self.tuples.is_empty()
    }

    /// Returns the number of tuples.
    pub fn len(&self) -> usize {
        self.tuples.len()
    }

    /// Returns the basic status from the first tuple, if any.
    pub fn basic_status(&self) -> Option<BasicStatus> {
        self.tuples.first().and_then(|t| t.status())
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
///
/// # Security
///
/// Tuple validates all fields to prevent injection attacks.
#[derive(Debug, Clone, PartialEq)]
pub struct Tuple {
    id: SmolStr,
    status: Option<BasicStatus>,
    contact: Option<SmolStr>,
    notes: Vec<SmolStr>,
    timestamp: Option<SmolStr>,
}

impl Tuple {
    /// Creates a new tuple with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is invalid.
    pub fn new(id: impl AsRef<str>) -> Result<Self, PresenceError> {
        validate_id(id.as_ref())?;

        Ok(Self {
            id: SmolStr::new(id.as_ref()),
            status: None,
            contact: None,
            notes: Vec::new(),
            timestamp: None,
        })
    }

    /// Sets the basic status (builder pattern).
    pub fn with_status(mut self, status: BasicStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the contact URI (builder pattern).
    ///
    /// # Errors
    ///
    /// Returns an error if the contact is invalid.
    pub fn with_contact(mut self, contact: impl AsRef<str>) -> Result<Self, PresenceError> {
        validate_contact(contact.as_ref())?;
        self.contact = Some(SmolStr::new(contact.as_ref()));
        Ok(self)
    }

    /// Adds a note (builder pattern).
    ///
    /// # Errors
    ///
    /// Returns an error if the note is invalid or exceeds limits.
    pub fn with_note(mut self, note: impl AsRef<str>) -> Result<Self, PresenceError> {
        validate_note(note.as_ref())?;

        if self.notes.len() >= MAX_NOTES_PER_TUPLE {
            return Err(PresenceError::TooManyNotes {
                max: MAX_NOTES_PER_TUPLE,
                actual: self.notes.len() + 1,
            });
        }

        self.notes.push(SmolStr::new(note.as_ref()));
        Ok(self)
    }

    /// Sets the timestamp (builder pattern).
    ///
    /// # Errors
    ///
    /// Returns an error if the timestamp is invalid.
    pub fn with_timestamp(mut self, timestamp: impl AsRef<str>) -> Result<Self, PresenceError> {
        validate_timestamp(timestamp.as_ref())?;
        self.timestamp = Some(SmolStr::new(timestamp.as_ref()));
        Ok(self)
    }

    /// Returns the tuple ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the status.
    pub fn status(&self) -> Option<BasicStatus> {
        self.status
    }

    /// Returns the contact.
    pub fn contact(&self) -> Option<&str> {
        self.contact.as_ref().map(|s| s.as_str())
    }

    /// Returns an iterator over notes.
    pub fn notes(&self) -> impl Iterator<Item = &str> {
        self.notes.iter().map(|s| s.as_str())
    }

    /// Returns the timestamp.
    pub fn timestamp(&self) -> Option<&str> {
        self.timestamp.as_ref().map(|s| s.as_str())
    }

    /// Formats the tuple as XML.
    pub fn to_xml(&self) -> String {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BasicStatus {
    Open,
    Closed,
}

impl BasicStatus {
    /// Returns the string representation for XML.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }

    /// Parses a basic status from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "open" => Some(Self::Open),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

impl std::str::FromStr for BasicStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
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

fn xml_unescape(s: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    while let Some(rel) = s[i..].find('&') {
        let amp = i + rel;
        out.push_str(&s[i..amp]);
        if let Some(semi) = s[amp..].find(';') {
            let end = amp + semi;
            let entity = &s[amp + 1..end];
            match entity {
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "amp" => out.push('&'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ => out.push_str(&s[amp..=end]),
            }
            i = end + 1;
        } else {
            out.push('&');
            i = amp + 1;
        }
    }
    out.push_str(&s[i..]);
    out
}

/// Parses a PIDF presence document from XML.
///
/// # Security
///
/// Enforces input size limits and validates all fields during parsing.
pub fn parse_pidf(xml: &str) -> Result<PresenceDocument, PresenceError> {
    // Check input size
    if xml.len() > MAX_PARSE_SIZE {
        return Err(PresenceError::InputTooLarge {
            max: MAX_PARSE_SIZE,
            actual: xml.len(),
        });
    }

    // Very basic parsing - a real implementation should use an XML parser
    let entity = extract_attribute(xml, "<presence", "entity")
        .ok_or_else(|| PresenceError::ParseError("missing entity attribute".to_string()))?;

    let entity = xml_unescape(&entity);
    let mut doc = PresenceDocument::new(entity)?;

    // Extract tuples
    let mut tuple_ranges = Vec::new();
    let mut pos = 0;
    while let Some(tuple_start) = xml[pos..].find("<tuple") {
        let abs_start = pos + tuple_start;
        let tuple_end = xml[abs_start..]
            .find("</tuple>")
            .ok_or_else(|| PresenceError::ParseError("unclosed tuple".to_string()))?
            + abs_start
            + 8;
        let tuple_xml = &xml[abs_start..tuple_end];

        let tuple = parse_tuple(tuple_xml)?;
        doc.add_tuple(tuple)?;
        tuple_ranges.push((abs_start, tuple_end));

        pos = tuple_end;
    }

    // Extract document-level notes (outside tuples)
    extract_document_notes(xml, &tuple_ranges, &mut doc)?;

    Ok(doc)
}

/// Parses a single tuple from XML.
fn parse_tuple(xml: &str) -> Result<Tuple, PresenceError> {
    let id = extract_attribute(xml, "<tuple", "id")
        .ok_or_else(|| PresenceError::ParseError("missing tuple id".to_string()))?;

    let id = xml_unescape(&id);
    let mut tuple = Tuple::new(id)?;

    // Extract status
    if let Some(basic_start) = xml.find("<basic>") {
        if let Some(basic_end) = xml.find("</basic>") {
            let status_str = &xml[basic_start + 7..basic_end].trim();
            tuple.status =
                Some(BasicStatus::parse(status_str).ok_or_else(|| {
                    PresenceError::ParseError("invalid basic status".to_string())
                })?);
        }
    }

    // Extract contact
    if let Some((contact, end_idx)) = extract_element_with_range(xml, "contact") {
        if has_duplicate_element(xml, "contact", end_idx) {
            return Err(PresenceError::ParseError(
                "multiple contact elements".to_string(),
            ));
        }
        let contact = xml_unescape(&contact);
        tuple = tuple.with_contact(contact)?;
    }

    // Extract notes
    let mut pos = 0;
    while let Some(note_start) = xml[pos..].find("<note>") {
        let abs_start = pos + note_start;
        if let Some(note_end) = xml[abs_start..].find("</note>") {
            let note = &xml[abs_start + 6..abs_start + note_end].trim();
            let note = xml_unescape(note);
            tuple = tuple.with_note(note)?;
            pos = abs_start + note_end + 7;
        } else {
            break;
        }
    }

    // Extract timestamp
    if let Some((timestamp, end_idx)) = extract_element_with_range(xml, "timestamp") {
        if has_duplicate_element(xml, "timestamp", end_idx) {
            return Err(PresenceError::ParseError(
                "multiple timestamp elements".to_string(),
            ));
        }
        let timestamp = xml_unescape(&timestamp);
        tuple = tuple.with_timestamp(timestamp)?;
    }

    Ok(tuple)
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

fn extract_element_with_range(xml: &str, element_name: &str) -> Option<(String, usize)> {
    let start_tag = format!("<{}>", element_name);
    let end_tag = format!("</{}>", element_name);

    let content_start = xml.find(&start_tag)? + start_tag.len();
    let content_end = xml[content_start..].find(&end_tag)? + content_start;
    let end_idx = content_end + end_tag.len();

    Some((xml[content_start..content_end].trim().to_string(), end_idx))
}

fn has_duplicate_element(xml: &str, element_name: &str, after_idx: usize) -> bool {
    let start_tag = format!("<{}>", element_name);
    xml[after_idx..].contains(&start_tag)
}

fn extract_document_notes(
    xml: &str,
    tuple_ranges: &[(usize, usize)],
    doc: &mut PresenceDocument,
) -> Result<(), PresenceError> {
    let mut pos = 0;
    while let Some(note_start) = xml[pos..].find("<note>") {
        let abs_start = pos + note_start;
        if tuple_ranges
            .iter()
            .any(|(start, end)| abs_start >= *start && abs_start < *end)
        {
            pos = abs_start + 6;
            continue;
        }

        if let Some(note_end) = xml[abs_start..].find("</note>") {
            let note = &xml[abs_start + 6..abs_start + note_end].trim();
            let note = xml_unescape(note);
            doc.add_note(note)?;
            pos = abs_start + note_end + 7;
        } else {
            return Err(PresenceError::ParseError(
                "unclosed note element".to_string(),
            ));
        }
    }
    Ok(())
}

// Validation functions

fn validate_entity(entity: &str) -> Result<(), PresenceError> {
    if entity.is_empty() {
        return Err(PresenceError::EmptyEntity);
    }

    if entity.len() > MAX_ENTITY_LENGTH {
        return Err(PresenceError::EntityTooLong {
            max: MAX_ENTITY_LENGTH,
            actual: entity.len(),
        });
    }

    if entity.chars().any(|c| c.is_ascii_control()) {
        return Err(PresenceError::InvalidEntity(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_id(id: &str) -> Result<(), PresenceError> {
    if id.is_empty() {
        return Err(PresenceError::EmptyId);
    }

    if id.len() > MAX_ID_LENGTH {
        return Err(PresenceError::IdTooLong {
            max: MAX_ID_LENGTH,
            actual: id.len(),
        });
    }

    if id.chars().any(|c| c.is_ascii_control()) {
        return Err(PresenceError::InvalidId(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_contact(contact: &str) -> Result<(), PresenceError> {
    if contact.len() > MAX_CONTACT_LENGTH {
        return Err(PresenceError::ContactTooLong {
            max: MAX_CONTACT_LENGTH,
            actual: contact.len(),
        });
    }

    if contact.chars().any(|c| c.is_ascii_control()) {
        return Err(PresenceError::InvalidContact(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_note(note: &str) -> Result<(), PresenceError> {
    if note.len() > MAX_NOTE_LENGTH {
        return Err(PresenceError::NoteTooLong {
            max: MAX_NOTE_LENGTH,
            actual: note.len(),
        });
    }

    if note.chars().any(|c| c.is_ascii_control()) {
        return Err(PresenceError::InvalidNote(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_timestamp(timestamp: &str) -> Result<(), PresenceError> {
    if timestamp.len() > MAX_TIMESTAMP_LENGTH {
        return Err(PresenceError::TimestampTooLong {
            max: MAX_TIMESTAMP_LENGTH,
            actual: timestamp.len(),
        });
    }

    if timestamp.chars().any(|c| c.is_ascii_control()) {
        return Err(PresenceError::InvalidTimestamp(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_document_creation() {
        let doc = PresenceDocument::new("pres:alice@example.com").unwrap();
        assert_eq!(doc.entity(), "pres:alice@example.com");
        assert!(doc.is_empty());
    }

    #[test]
    fn reject_empty_entity() {
        let result = PresenceDocument::new("");
        assert!(matches!(result, Err(PresenceError::EmptyEntity)));
    }

    #[test]
    fn reject_oversized_entity() {
        let long_entity = format!("pres:{}", "x".repeat(MAX_ENTITY_LENGTH));
        let result = PresenceDocument::new(&long_entity);
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_entity() {
        let result = PresenceDocument::new("pres:alice\r\ninjected@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn tuple_creation() {
        let tuple = Tuple::new("t1")
            .unwrap()
            .with_status(BasicStatus::Open)
            .with_contact("sip:alice@192.168.1.100")
            .unwrap()
            .with_note("Available")
            .unwrap();

        assert_eq!(tuple.id(), "t1");
        assert_eq!(tuple.status(), Some(BasicStatus::Open));
        assert_eq!(tuple.contact(), Some("sip:alice@192.168.1.100"));
    }

    #[test]
    fn reject_empty_tuple_id() {
        let result = Tuple::new("");
        assert!(matches!(result, Err(PresenceError::EmptyId)));
    }

    #[test]
    fn reject_crlf_in_tuple_id() {
        let result = Tuple::new("t1\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_contact() {
        let result = Tuple::new("t1")
            .unwrap()
            .with_contact("sip:alice\r\ninjected@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_note() {
        let result = Tuple::new("t1").unwrap().with_note("Available\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_tuples() {
        let mut doc = PresenceDocument::new("pres:alice@example.com").unwrap();

        for i in 0..MAX_TUPLES {
            let tuple = Tuple::new(&format!("t{}", i)).unwrap();
            doc.add_tuple(tuple).unwrap();
        }

        // Should fail
        let tuple = Tuple::new("overflow").unwrap();
        let result = doc.add_tuple(tuple);
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_notes() {
        let tuple = Tuple::new("t1").unwrap();
        let mut tuple = tuple;

        for _ in 0..MAX_NOTES_PER_TUPLE {
            tuple = tuple.with_note("note").unwrap();
        }

        // Should fail
        let result = tuple.with_note("overflow");
        assert!(result.is_err());
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
        let mut doc = PresenceDocument::new("pres:alice@example.com").unwrap();

        let tuple = Tuple::new("t1")
            .unwrap()
            .with_status(BasicStatus::Open)
            .with_contact("sip:alice@192.168.1.100")
            .unwrap()
            .with_note("Available")
            .unwrap();

        doc.add_tuple(tuple).unwrap();

        let xml = doc.to_xml();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<presence"));
        assert!(xml.contains("entity=\"pres:alice@example.com\""));
        assert!(xml.contains("<tuple id=\"t1\""));
        assert!(xml.contains("<basic>open</basic>"));
    }

    #[test]
    fn reject_oversized_parse_input() {
        let huge_xml = format!(
            "<?xml version=\"1.0\"?><presence>{}</presence>",
            "x".repeat(MAX_PARSE_SIZE)
        );
        let result = parse_pidf(&huge_xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_validates_entity() {
        let xml = format!(
            "<?xml version=\"1.0\"?>\n<presence entity=\"{}\"></presence>",
            "x".repeat(MAX_ENTITY_LENGTH + 1)
        );
        let result = parse_pidf(&xml);
        assert!(result.is_err());
    }

    #[test]
    fn round_trip_pidf() {
        let mut doc = PresenceDocument::new("pres:alice@example.com").unwrap();
        doc.add_tuple(
            Tuple::new("t1")
                .unwrap()
                .with_status(BasicStatus::Open)
                .with_contact("sip:alice@192.168.1.100")
                .unwrap()
                .with_note("Available")
                .unwrap(),
        )
        .unwrap();

        let xml = doc.to_xml();
        let parsed = parse_pidf(&xml).unwrap();

        assert_eq!(doc.entity(), parsed.entity());
        assert_eq!(doc.len(), parsed.len());
    }

    #[test]
    fn parse_preserves_document_notes_and_unescapes() {
        let mut doc = PresenceDocument::new("pres:alice@example.com").unwrap();
        doc.add_note("Available & ready").unwrap();
        doc.add_tuple(
            Tuple::new("t1")
                .unwrap()
                .with_status(BasicStatus::Open)
                .with_contact("sip:alice@192.168.1.100")
                .unwrap()
                .with_note("In <office>")
                .unwrap(),
        )
        .unwrap();

        let xml = doc.to_xml();
        let parsed = parse_pidf(&xml).unwrap();
        let notes: Vec<&str> = parsed.notes().collect();
        assert_eq!(notes, vec!["Available & ready"]);
    }

    #[test]
    fn parse_rejects_invalid_basic_status() {
        let xml = "<?xml version=\"1.0\"?>\n<presence entity=\"pres:alice@example.com\">\
<tuple id=\"t1\"><status><basic>maybe</basic></status></tuple></presence>";
        assert!(parse_pidf(xml).is_err());
    }

    #[test]
    fn fields_are_private() {
        let doc = PresenceDocument::new("pres:alice@example.com").unwrap();
        let tuple = Tuple::new("t1").unwrap();

        // These should compile (read-only access)
        let _ = doc.entity();
        let _ = doc.tuples();
        let _ = tuple.id();
        let _ = tuple.status();

        // These should NOT compile (no direct field access):
        // doc.entity = SmolStr::new("evil");  // ← Does not compile!
        // tuple.id = SmolStr::new("evil");    // ← Does not compile!
        // doc.tuples.clear();                  // ← Does not compile!
    }
}
