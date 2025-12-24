// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// RFC 3842 Message Waiting Indication Event Package.
///
/// This module implements RFC 3842, which defines a SIP event package for
/// message waiting indications and message summaries. The "message-summary"
/// event package allows messaging systems to notify users about pending messages.
///
/// # RFC 3842 Overview
///
/// - Event package name: "message-summary"
/// - MIME type: application/simple-message-summary
/// - Default subscription duration: 3600 seconds (1 hour)
/// - Supports multiple message types: voice, fax, pager, multimedia, text
///
/// # Examples
///
/// ```
/// use sip_core::{MessageSummary, MessageContextClass, MessageCounts};
///
/// // Create a message summary with voice messages
/// let mut summary = MessageSummary::new(true);
/// summary.set_account("sip:alice@vmail.example.com");
/// summary.add_message_class(
///     MessageContextClass::Voice,
///     MessageCounts::new(2, 8).with_urgent(0, 2)
/// );
///
/// // Format as application/simple-message-summary
/// let body = summary.to_string();
/// ```
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

/// RFC 3842 Message Summary.
///
/// Represents the complete message waiting indication including status,
/// optional message account, message counts by class, and optional
/// message headers.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageSummary {
    /// Whether messages are waiting (mandatory)
    pub messages_waiting: bool,
    /// Message account URI (conditional - required for group subscriptions)
    pub account: Option<SmolStr>,
    /// Message counts by context class
    pub messages: BTreeMap<MessageContextClass, MessageCounts>,
    /// Optional message headers (for newly received messages)
    pub message_headers: Vec<MessageHeader>,
}

impl MessageSummary {
    /// Creates a new message summary.
    pub fn new(messages_waiting: bool) -> Self {
        Self {
            messages_waiting,
            account: None,
            messages: BTreeMap::new(),
            message_headers: Vec::new(),
        }
    }

    /// Sets the message account URI.
    pub fn set_account(&mut self, account: impl Into<SmolStr>) {
        self.account = Some(account.into());
    }

    /// Adds message counts for a context class.
    pub fn add_message_class(&mut self, class: MessageContextClass, counts: MessageCounts) {
        self.messages.insert(class, counts);
    }

    /// Adds a message header.
    pub fn add_message_header(&mut self, header: MessageHeader) {
        self.message_headers.push(header);
    }

    /// Returns true if there are no message counts.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Returns the total number of new messages across all classes.
    pub fn total_new(&self) -> u32 {
        self.messages.values().map(|c| c.new).sum()
    }

    /// Returns the total number of old messages across all classes.
    pub fn total_old(&self) -> u32 {
        self.messages.values().map(|c| c.old).sum()
    }

    /// Returns true if any messages are urgent.
    pub fn has_urgent(&self) -> bool {
        self.messages
            .values()
            .any(|c| c.urgent_new > 0 || c.urgent_old > 0)
    }
}

impl fmt::Display for MessageSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mandatory status line
        writeln!(
            f,
            "Messages-Waiting: {}",
            if self.messages_waiting { "yes" } else { "no" }
        )?;

        // Conditional account line
        if let Some(ref account) = self.account {
            writeln!(f, "Message-Account: {}", account)?;
        }

        // Message counts by class
        for (class, counts) in &self.messages {
            write!(f, "{}: {}/{}", class.header_name(), counts.new, counts.old)?;

            // Include urgent counts if present
            if counts.urgent_new > 0 || counts.urgent_old > 0 {
                write!(f, " ({}/{})", counts.urgent_new, counts.urgent_old)?;
            }
            writeln!(f)?;
        }

        // Optional message headers
        for msg_header in &self.message_headers {
            if let Some(ref to) = msg_header.to {
                writeln!(f, "To: {}", to)?;
            }
            if let Some(ref from) = msg_header.from {
                writeln!(f, "From: {}", from)?;
            }
            if let Some(ref subject) = msg_header.subject {
                writeln!(f, "Subject: {}", subject)?;
            }
            if let Some(ref date) = msg_header.date {
                writeln!(f, "Date: {}", date)?;
            }
            if let Some(ref priority) = msg_header.priority {
                writeln!(f, "Priority: {}", priority)?;
            }
            if let Some(ref message_id) = msg_header.message_id {
                writeln!(f, "Message-ID: {}", message_id)?;
            }
            if let Some(ref message_context) = msg_header.message_context {
                writeln!(f, "Message-Context: {}", message_context)?;
            }
        }

        Ok(())
    }
}

/// RFC 3842 Message Context Class.
///
/// Defines the type of message (voice, fax, pager, etc.). Each context
/// class has separate new/old and urgent/non-urgent counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MessageContextClass {
    /// Voice messages
    Voice,
    /// Fax messages
    Fax,
    /// Pager messages
    Pager,
    /// Multimedia messages
    Multimedia,
    /// Text messages
    Text,
    /// No specific context
    None,
}

impl MessageContextClass {
    /// Returns the header name for this context class.
    pub fn header_name(&self) -> &str {
        match self {
            MessageContextClass::Voice => "Voice-Message",
            MessageContextClass::Fax => "Fax-Message",
            MessageContextClass::Pager => "Pager-Message",
            MessageContextClass::Multimedia => "Multimedia-Message",
            MessageContextClass::Text => "Text-Message",
            MessageContextClass::None => "None-Message",
        }
    }

    /// Parses a context class from a header name.
    pub fn from_header_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "voice-message" => Some(MessageContextClass::Voice),
            "fax-message" => Some(MessageContextClass::Fax),
            "pager-message" => Some(MessageContextClass::Pager),
            "multimedia-message" => Some(MessageContextClass::Multimedia),
            "text-message" => Some(MessageContextClass::Text),
            "none-message" => Some(MessageContextClass::None),
            _ => None,
        }
    }

    /// Returns the context class identifier.
    pub fn as_str(&self) -> &str {
        match self {
            MessageContextClass::Voice => "voice",
            MessageContextClass::Fax => "fax",
            MessageContextClass::Pager => "pager",
            MessageContextClass::Multimedia => "multimedia",
            MessageContextClass::Text => "text",
            MessageContextClass::None => "none",
        }
    }
}

impl fmt::Display for MessageContextClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Message counts for a context class.
///
/// Per RFC 3842, counts are separated by new/old status and
/// urgent/non-urgent priority. Maximum value is 2^32-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageCounts {
    /// Number of new messages
    pub new: u32,
    /// Number of old messages
    pub old: u32,
    /// Number of urgent new messages
    pub urgent_new: u32,
    /// Number of urgent old messages
    pub urgent_old: u32,
}

impl MessageCounts {
    /// Creates new message counts with new and old totals.
    pub fn new(new: u32, old: u32) -> Self {
        Self {
            new,
            old,
            urgent_new: 0,
            urgent_old: 0,
        }
    }

    /// Sets the urgent message counts (builder pattern).
    pub fn with_urgent(mut self, urgent_new: u32, urgent_old: u32) -> Self {
        self.urgent_new = urgent_new;
        self.urgent_old = urgent_old;
        self
    }

    /// Returns the total number of messages (new + old).
    pub fn total(&self) -> u32 {
        self.new + self.old
    }

    /// Returns the total number of urgent messages.
    pub fn total_urgent(&self) -> u32 {
        self.urgent_new + self.urgent_old
    }

    /// Returns true if there are any new messages.
    pub fn has_new(&self) -> bool {
        self.new > 0
    }

    /// Returns true if there are any urgent messages.
    pub fn has_urgent(&self) -> bool {
        self.urgent_new > 0 || self.urgent_old > 0
    }
}

impl Default for MessageCounts {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Optional message headers for newly received messages.
///
/// Per RFC 3842, these headers provide details about specific messages.
/// Initial NOTIFYs should exclude these to prevent unbounded sizes.
/// Subsequent NOTIFYs include headers only for newly added messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    /// To header
    pub to: Option<SmolStr>,
    /// From header
    pub from: Option<SmolStr>,
    /// Subject header
    pub subject: Option<SmolStr>,
    /// Date header
    pub date: Option<SmolStr>,
    /// Priority header
    pub priority: Option<SmolStr>,
    /// Message-ID header
    pub message_id: Option<SmolStr>,
    /// Message-Context header
    pub message_context: Option<SmolStr>,
}

impl MessageHeader {
    /// Creates a new empty message header.
    pub fn new() -> Self {
        Self {
            to: None,
            from: None,
            subject: None,
            date: None,
            priority: None,
            message_id: None,
            message_context: None,
        }
    }

    /// Sets the To header (builder pattern).
    pub fn with_to(mut self, to: impl Into<SmolStr>) -> Self {
        self.to = Some(to.into());
        self
    }

    /// Sets the From header (builder pattern).
    pub fn with_from(mut self, from: impl Into<SmolStr>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets the Subject header (builder pattern).
    pub fn with_subject(mut self, subject: impl Into<SmolStr>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Sets the Date header (builder pattern).
    pub fn with_date(mut self, date: impl Into<SmolStr>) -> Self {
        self.date = Some(date.into());
        self
    }

    /// Sets the Priority header (builder pattern).
    pub fn with_priority(mut self, priority: impl Into<SmolStr>) -> Self {
        self.priority = Some(priority.into());
        self
    }

    /// Sets the Message-ID header (builder pattern).
    pub fn with_message_id(mut self, message_id: impl Into<SmolStr>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    /// Sets the Message-Context header (builder pattern).
    pub fn with_message_context(mut self, message_context: impl Into<SmolStr>) -> Self {
        self.message_context = Some(message_context.into());
        self
    }
}

impl Default for MessageHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses a message summary from application/simple-message-summary format.
///
/// Per RFC 3842, the format is:
/// - Messages-Waiting: yes/no (mandatory)
/// - Message-Account: URI (conditional)
/// - <Context>-Message: new/old (urgent_new/urgent_old) (optional)
/// - RFC 2822 headers for messages (optional)
pub fn parse_message_summary(body: &str) -> Option<MessageSummary> {
    let mut summary = MessageSummary::new(false);
    let mut current_message_header: Option<MessageHeader> = None;
    let mut found_status = false;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Split on first colon
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let name = parts[0].trim();
        let value = parts[1].trim();

        match name.to_ascii_lowercase().as_str() {
            "messages-waiting" => {
                found_status = true;
                summary.messages_waiting = value.eq_ignore_ascii_case("yes");
            }
            "message-account" => {
                summary.account = Some(SmolStr::new(value));
            }
            name if name.ends_with("-message") => {
                // Parse message counts: new/old (urgent_new/urgent_old)
                if let Some(class) = MessageContextClass::from_header_name(name) {
                    if let Some(counts) = parse_message_counts(value) {
                        summary.messages.insert(class, counts);
                    }
                }
            }
            // RFC 2822 headers for message details
            "to" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(ref mut header) = current_message_header {
                    header.to = Some(SmolStr::new(value));
                }
            }
            "from" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(ref mut header) = current_message_header {
                    header.from = Some(SmolStr::new(value));
                }
            }
            "subject" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(ref mut header) = current_message_header {
                    header.subject = Some(SmolStr::new(value));
                }
            }
            "date" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(ref mut header) = current_message_header {
                    header.date = Some(SmolStr::new(value));
                }
            }
            "priority" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(ref mut header) = current_message_header {
                    header.priority = Some(SmolStr::new(value));
                }
            }
            "message-id" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(ref mut header) = current_message_header {
                    header.message_id = Some(SmolStr::new(value));
                }
            }
            "message-context" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(ref mut header) = current_message_header {
                    header.message_context = Some(SmolStr::new(value));
                }
            }
            _ => {}
        }
    }

    // Add accumulated message header if present
    if let Some(header) = current_message_header {
        summary.message_headers.push(header);
    }

    if found_status {
        Some(summary)
    } else {
        None
    }
}

/// Parses message counts from format: "new/old (urgent_new/urgent_old)"
fn parse_message_counts(s: &str) -> Option<MessageCounts> {
    // Split on space to separate main counts from urgent counts
    let parts: Vec<&str> = s.split_whitespace().collect();

    // Parse main counts (new/old)
    let main_parts: Vec<&str> = parts[0].split('/').collect();
    if main_parts.len() != 2 {
        return None;
    }

    let new = main_parts[0].parse::<u32>().ok()?;
    let old = main_parts[1].parse::<u32>().ok()?;

    let mut counts = MessageCounts::new(new, old);

    // Parse urgent counts if present
    if parts.len() > 1 {
        let urgent_str = parts[1].trim_matches(|c| c == '(' || c == ')');
        let urgent_parts: Vec<&str> = urgent_str.split('/').collect();
        if urgent_parts.len() == 2 {
            if let (Ok(urgent_new), Ok(urgent_old)) = (
                urgent_parts[0].parse::<u32>(),
                urgent_parts[1].parse::<u32>(),
            ) {
                counts.urgent_new = urgent_new;
                counts.urgent_old = urgent_old;
            }
        }
    }

    Some(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_summary_basic() {
        let mut summary = MessageSummary::new(true);
        summary.set_account("sip:alice@vmail.example.com");
        summary.add_message_class(MessageContextClass::Voice, MessageCounts::new(2, 8));

        assert!(summary.messages_waiting);
        assert_eq!(
            summary.account,
            Some(SmolStr::new("sip:alice@vmail.example.com"))
        );
        assert_eq!(summary.total_new(), 2);
        assert_eq!(summary.total_old(), 8);
    }

    #[test]
    fn message_summary_output() {
        let mut summary = MessageSummary::new(true);
        summary.set_account("sip:alice@vmail.example.com");
        summary.add_message_class(
            MessageContextClass::Voice,
            MessageCounts::new(2, 8).with_urgent(0, 2),
        );

        let output = summary.to_string();
        assert!(output.contains("Messages-Waiting: yes"));
        assert!(output.contains("Message-Account: sip:alice@vmail.example.com"));
        assert!(output.contains("Voice-Message: 2/8 (0/2)"));
    }

    #[test]
    fn message_context_class_header_names() {
        assert_eq!(MessageContextClass::Voice.header_name(), "Voice-Message");
        assert_eq!(MessageContextClass::Fax.header_name(), "Fax-Message");
        assert_eq!(MessageContextClass::Text.header_name(), "Text-Message");
    }

    #[test]
    fn message_context_class_from_header() {
        assert_eq!(
            MessageContextClass::from_header_name("Voice-Message"),
            Some(MessageContextClass::Voice)
        );
        assert_eq!(
            MessageContextClass::from_header_name("fax-message"),
            Some(MessageContextClass::Fax)
        );
    }

    #[test]
    fn message_counts_basic() {
        let counts = MessageCounts::new(3, 5);
        assert_eq!(counts.new, 3);
        assert_eq!(counts.old, 5);
        assert_eq!(counts.total(), 8);
        assert!(counts.has_new());
    }

    #[test]
    fn message_counts_with_urgent() {
        let counts = MessageCounts::new(2, 8).with_urgent(1, 2);
        assert_eq!(counts.urgent_new, 1);
        assert_eq!(counts.urgent_old, 2);
        assert_eq!(counts.total_urgent(), 3);
        assert!(counts.has_urgent());
    }

    #[test]
    fn message_header_builder() {
        let header = MessageHeader::new()
            .with_to("alice@example.com")
            .with_from("bob@example.com")
            .with_subject("Hello");

        assert_eq!(header.to, Some(SmolStr::new("alice@example.com")));
        assert_eq!(header.from, Some(SmolStr::new("bob@example.com")));
        assert_eq!(header.subject, Some(SmolStr::new("Hello")));
    }

    #[test]
    fn parse_simple_summary() {
        let body = "Messages-Waiting: yes\n\
                    Message-Account: sip:alice@vmail.example.com\n\
                    Voice-Message: 2/8 (0/2)\n";

        let summary = parse_message_summary(body).unwrap();
        assert!(summary.messages_waiting);
        assert_eq!(
            summary.account,
            Some(SmolStr::new("sip:alice@vmail.example.com"))
        );
        assert_eq!(summary.messages.len(), 1);

        let voice = summary.messages.get(&MessageContextClass::Voice).unwrap();
        assert_eq!(voice.new, 2);
        assert_eq!(voice.old, 8);
        assert_eq!(voice.urgent_new, 0);
        assert_eq!(voice.urgent_old, 2);
    }

    #[test]
    fn parse_summary_with_headers() {
        let body = "Messages-Waiting: yes\n\
                    Voice-Message: 4/8 (1/2)\n\
                    To: alice@atlanta.example.com\n\
                    From: bob@biloxi.example.com\n\
                    Subject: carpool tomorrow?\n";

        let summary = parse_message_summary(body).unwrap();
        assert!(summary.messages_waiting);
        assert_eq!(summary.message_headers.len(), 1);

        let header = &summary.message_headers[0];
        assert_eq!(header.to, Some(SmolStr::new("alice@atlanta.example.com")));
        assert_eq!(header.from, Some(SmolStr::new("bob@biloxi.example.com")));
        assert_eq!(header.subject, Some(SmolStr::new("carpool tomorrow?")));
    }

    #[test]
    fn parse_no_messages() {
        let body = "Messages-Waiting: no\n";

        let summary = parse_message_summary(body).unwrap();
        assert!(!summary.messages_waiting);
        assert!(summary.messages.is_empty());
    }

    #[test]
    fn parse_multiple_classes() {
        let body = "Messages-Waiting: yes\n\
                    Voice-Message: 2/8\n\
                    Fax-Message: 1/3\n\
                    Text-Message: 5/10 (2/0)\n";

        let summary = parse_message_summary(body).unwrap();
        assert_eq!(summary.messages.len(), 3);
        assert!(summary.messages.contains_key(&MessageContextClass::Voice));
        assert!(summary.messages.contains_key(&MessageContextClass::Fax));
        assert!(summary.messages.contains_key(&MessageContextClass::Text));
    }

    #[test]
    fn parse_message_counts_basic() {
        let counts = parse_message_counts("2/8").unwrap();
        assert_eq!(counts.new, 2);
        assert_eq!(counts.old, 8);
        assert_eq!(counts.urgent_new, 0);
        assert_eq!(counts.urgent_old, 0);
    }

    #[test]
    fn parse_message_counts_with_urgent() {
        let counts = parse_message_counts("2/8 (0/2)").unwrap();
        assert_eq!(counts.new, 2);
        assert_eq!(counts.old, 8);
        assert_eq!(counts.urgent_new, 0);
        assert_eq!(counts.urgent_old, 2);
    }

    #[test]
    fn round_trip() {
        let mut summary = MessageSummary::new(true);
        summary.set_account("sip:alice@vmail.example.com");
        summary.add_message_class(
            MessageContextClass::Voice,
            MessageCounts::new(2, 8).with_urgent(0, 2),
        );

        let output = summary.to_string();
        let parsed = parse_message_summary(&output).unwrap();

        assert_eq!(summary.messages_waiting, parsed.messages_waiting);
        assert_eq!(summary.account, parsed.account);
        assert_eq!(summary.messages, parsed.messages);
    }
}
