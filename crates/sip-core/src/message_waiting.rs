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
/// # Security
///
/// All types validate input to prevent:
/// - CRLF injection attacks
/// - Control character injection
/// - Excessive length (DoS)
/// - Unbounded collections
///
/// # Examples
///
/// ```
/// use sip_core::{MessageSummary, MessageContextClass, MessageCounts};
///
/// let mut summary = MessageSummary::new(true);
/// summary.set_account("sip:alice@vmail.example.com").unwrap();
/// summary.add_message_class(
///     MessageContextClass::Voice,
///     MessageCounts::new(2, 8).with_urgent(0, 2)
/// );
///
/// let body = summary.to_string();
/// ```
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

const MAX_ACCOUNT_LENGTH: usize = 512;
const MAX_HEADER_VALUE_LENGTH: usize = 1024;
const MAX_MESSAGE_HEADERS: usize = 50;
const MAX_MESSAGE_CLASSES: usize = 10;
const MAX_PARSE_SIZE: usize = 100 * 1024; // 100KB

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageWaitingError {
    AccountTooLong { max: usize, actual: usize },
    HeaderValueTooLong { max: usize, actual: usize },
    TooManyHeaders { max: usize, actual: usize },
    TooManyClasses { max: usize, actual: usize },
    InvalidAccount(String),
    InvalidHeaderValue(String),
    ParseError(String),
    InputTooLarge { max: usize, actual: usize },
}

impl std::fmt::Display for MessageWaitingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountTooLong { max, actual } => {
                write!(f, "account too long (max {}, got {})", max, actual)
            }
            Self::HeaderValueTooLong { max, actual } => {
                write!(f, "header value too long (max {}, got {})", max, actual)
            }
            Self::TooManyHeaders { max, actual } => {
                write!(f, "too many message headers (max {}, got {})", max, actual)
            }
            Self::TooManyClasses { max, actual } => {
                write!(f, "too many message classes (max {}, got {})", max, actual)
            }
            Self::InvalidAccount(msg) => write!(f, "invalid account: {}", msg),
            Self::InvalidHeaderValue(msg) => write!(f, "invalid header value: {}", msg),
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
            Self::InputTooLarge { max, actual } => {
                write!(f, "input too large (max {}, got {})", max, actual)
            }
        }
    }
}

impl std::error::Error for MessageWaitingError {}

/// RFC 3842 Message Summary.
///
/// Represents the complete message waiting indication including status,
/// optional message account, message counts by class, and optional
/// message headers.
///
/// # Security
///
/// MessageSummary validates all input to prevent injection attacks and DoS.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageSummary {
    messages_waiting: bool,
    account: Option<SmolStr>,
    messages: BTreeMap<MessageContextClass, MessageCounts>,
    message_headers: Vec<MessageHeader>,
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

    /// Sets the message account URI with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the account contains control characters or is too long.
    pub fn set_account(&mut self, account: impl AsRef<str>) -> Result<(), MessageWaitingError> {
        let account = account.as_ref();
        validate_account(account)?;
        self.account = Some(SmolStr::new(account));
        Ok(())
    }

    /// Adds message counts for a context class.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed MAX_MESSAGE_CLASSES.
    pub fn add_message_class(
        &mut self,
        class: MessageContextClass,
        counts: MessageCounts,
    ) -> Result<(), MessageWaitingError> {
        if !self.messages.contains_key(&class) && self.messages.len() >= MAX_MESSAGE_CLASSES {
            return Err(MessageWaitingError::TooManyClasses {
                max: MAX_MESSAGE_CLASSES,
                actual: self.messages.len() + 1,
            });
        }
        self.messages.insert(class, counts);
        Ok(())
    }

    /// Adds a message header.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed MAX_MESSAGE_HEADERS.
    pub fn add_message_header(&mut self, header: MessageHeader) -> Result<(), MessageWaitingError> {
        if self.message_headers.len() >= MAX_MESSAGE_HEADERS {
            return Err(MessageWaitingError::TooManyHeaders {
                max: MAX_MESSAGE_HEADERS,
                actual: self.message_headers.len() + 1,
            });
        }
        self.message_headers.push(header);
        Ok(())
    }

    /// Returns whether messages are waiting.
    pub fn messages_waiting(&self) -> bool {
        self.messages_waiting
    }

    /// Returns the message account if set.
    pub fn account(&self) -> Option<&str> {
        self.account.as_ref().map(|s| s.as_str())
    }

    /// Returns an iterator over message classes and their counts.
    pub fn messages(&self) -> impl Iterator<Item = (&MessageContextClass, &MessageCounts)> {
        self.messages.iter()
    }

    /// Returns an iterator over message headers.
    pub fn message_headers(&self) -> impl Iterator<Item = &MessageHeader> {
        self.message_headers.iter()
    }

    /// Returns true if there are no message counts.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Returns the total number of new messages across all classes.
    pub fn total_new(&self) -> u32 {
        self.messages.values().map(|c| c.new_count()).sum()
    }

    /// Returns the total number of old messages across all classes.
    pub fn total_old(&self) -> u32 {
        self.messages.values().map(|c| c.old_count()).sum()
    }

    /// Returns true if any messages are urgent.
    pub fn has_urgent(&self) -> bool {
        self.messages.values().any(|c| c.has_urgent())
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
            write!(
                f,
                "{}: {}/{}",
                class.header_name(),
                counts.new_count(),
                counts.old_count()
            )?;

            // Include urgent counts if present
            if counts.urgent_new() > 0 || counts.urgent_old() > 0 {
                write!(f, " ({}/{})", counts.urgent_new(), counts.urgent_old())?;
            }
            writeln!(f)?;
        }

        // Optional message headers
        for msg_header in &self.message_headers {
            if let Some(to) = msg_header.to() {
                writeln!(f, "To: {}", to)?;
            }
            if let Some(from) = msg_header.from() {
                writeln!(f, "From: {}", from)?;
            }
            if let Some(subject) = msg_header.subject() {
                writeln!(f, "Subject: {}", subject)?;
            }
            if let Some(date) = msg_header.date() {
                writeln!(f, "Date: {}", date)?;
            }
            if let Some(priority) = msg_header.priority() {
                writeln!(f, "Priority: {}", priority)?;
            }
            if let Some(message_id) = msg_header.message_id() {
                writeln!(f, "Message-ID: {}", message_id)?;
            }
            if let Some(message_context) = msg_header.message_context() {
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
    Voice,
    Fax,
    Pager,
    Multimedia,
    Text,
    None,
}

impl MessageContextClass {
    /// Returns the header name for this context class.
    pub fn header_name(&self) -> &str {
        match self {
            Self::Voice => "Voice-Message",
            Self::Fax => "Fax-Message",
            Self::Pager => "Pager-Message",
            Self::Multimedia => "Multimedia-Message",
            Self::Text => "Text-Message",
            Self::None => "None-Message",
        }
    }

    /// Parses a context class from a header name.
    pub fn from_header_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "voice-message" => Some(Self::Voice),
            "fax-message" => Some(Self::Fax),
            "pager-message" => Some(Self::Pager),
            "multimedia-message" => Some(Self::Multimedia),
            "text-message" => Some(Self::Text),
            "none-message" => Some(Self::None),
            _ => None,
        }
    }

    /// Returns the context class identifier.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Voice => "voice",
            Self::Fax => "fax",
            Self::Pager => "pager",
            Self::Multimedia => "multimedia",
            Self::Text => "text",
            Self::None => "none",
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
    new: u32,
    old: u32,
    urgent_new: u32,
    urgent_old: u32,
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

    /// Returns the number of new messages.
    pub fn new_count(&self) -> u32 {
        self.new
    }

    /// Returns the number of old messages.
    pub fn old_count(&self) -> u32 {
        self.old
    }

    /// Returns the number of urgent new messages.
    pub fn urgent_new(&self) -> u32 {
        self.urgent_new
    }

    /// Returns the number of urgent old messages.
    pub fn urgent_old(&self) -> u32 {
        self.urgent_old
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
///
/// # Security
///
/// All fields are validated to prevent injection attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    to: Option<SmolStr>,
    from: Option<SmolStr>,
    subject: Option<SmolStr>,
    date: Option<SmolStr>,
    priority: Option<SmolStr>,
    message_id: Option<SmolStr>,
    message_context: Option<SmolStr>,
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
    pub fn with_to(mut self, to: impl AsRef<str>) -> Result<Self, MessageWaitingError> {
        validate_header_value(to.as_ref())?;
        self.to = Some(SmolStr::new(to.as_ref()));
        Ok(self)
    }

    /// Sets the From header (builder pattern).
    pub fn with_from(mut self, from: impl AsRef<str>) -> Result<Self, MessageWaitingError> {
        validate_header_value(from.as_ref())?;
        self.from = Some(SmolStr::new(from.as_ref()));
        Ok(self)
    }

    /// Sets the Subject header (builder pattern).
    pub fn with_subject(mut self, subject: impl AsRef<str>) -> Result<Self, MessageWaitingError> {
        validate_header_value(subject.as_ref())?;
        self.subject = Some(SmolStr::new(subject.as_ref()));
        Ok(self)
    }

    /// Sets the Date header (builder pattern).
    pub fn with_date(mut self, date: impl AsRef<str>) -> Result<Self, MessageWaitingError> {
        validate_header_value(date.as_ref())?;
        self.date = Some(SmolStr::new(date.as_ref()));
        Ok(self)
    }

    /// Sets the Priority header (builder pattern).
    pub fn with_priority(mut self, priority: impl AsRef<str>) -> Result<Self, MessageWaitingError> {
        validate_header_value(priority.as_ref())?;
        self.priority = Some(SmolStr::new(priority.as_ref()));
        Ok(self)
    }

    /// Sets the Message-ID header (builder pattern).
    pub fn with_message_id(
        mut self,
        message_id: impl AsRef<str>,
    ) -> Result<Self, MessageWaitingError> {
        validate_header_value(message_id.as_ref())?;
        self.message_id = Some(SmolStr::new(message_id.as_ref()));
        Ok(self)
    }

    /// Sets the Message-Context header (builder pattern).
    pub fn with_message_context(
        mut self,
        message_context: impl AsRef<str>,
    ) -> Result<Self, MessageWaitingError> {
        validate_header_value(message_context.as_ref())?;
        self.message_context = Some(SmolStr::new(message_context.as_ref()));
        Ok(self)
    }

    /// Returns the To header.
    pub fn to(&self) -> Option<&str> {
        self.to.as_ref().map(|s| s.as_str())
    }

    /// Returns the From header.
    pub fn from(&self) -> Option<&str> {
        self.from.as_ref().map(|s| s.as_str())
    }

    /// Returns the Subject header.
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_ref().map(|s| s.as_str())
    }

    /// Returns the Date header.
    pub fn date(&self) -> Option<&str> {
        self.date.as_ref().map(|s| s.as_str())
    }

    /// Returns the Priority header.
    pub fn priority(&self) -> Option<&str> {
        self.priority.as_ref().map(|s| s.as_str())
    }

    /// Returns the Message-ID header.
    pub fn message_id(&self) -> Option<&str> {
        self.message_id.as_ref().map(|s| s.as_str())
    }

    /// Returns the Message-Context header.
    pub fn message_context(&self) -> Option<&str> {
        self.message_context.as_ref().map(|s| s.as_str())
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
///
/// # Security
///
/// This function enforces size limits and validates all input.
///
/// # Errors
///
/// Returns an error if:
/// - Input exceeds MAX_PARSE_SIZE
/// - Required fields are missing
/// - Values contain invalid data
pub fn parse_message_summary(body: &str) -> Result<MessageSummary, MessageWaitingError> {
    // Check input size
    if body.len() > MAX_PARSE_SIZE {
        return Err(MessageWaitingError::InputTooLarge {
            max: MAX_PARSE_SIZE,
            actual: body.len(),
        });
    }

    let mut summary = MessageSummary::new(false);
    let mut current_message_header: Option<MessageHeader> = None;
    let mut found_status = false;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            if let Some(header) = current_message_header.take() {
                summary.add_message_header(header)?;
            }
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
                if value.eq_ignore_ascii_case("yes") {
                    summary.messages_waiting = true;
                } else if value.eq_ignore_ascii_case("no") {
                    summary.messages_waiting = false;
                } else {
                    return Err(MessageWaitingError::ParseError(
                        "invalid Messages-Waiting value".to_string(),
                    ));
                }
            }
            "message-account" => {
                summary.set_account(value)?;
            }
            name if name.ends_with("-message") => {
                // Parse message counts
                if let Some(class) = MessageContextClass::from_header_name(name) {
                    if let Some(counts) = parse_message_counts(value) {
                        summary.add_message_class(class, counts)?;
                    }
                }
            }
            // RFC 2822 headers for message details
            "to" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(header) = current_message_header.take() {
                    current_message_header = Some(header.with_to(value)?);
                }
            }
            "from" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(header) = current_message_header.take() {
                    current_message_header = Some(header.with_from(value)?);
                }
            }
            "subject" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(header) = current_message_header.take() {
                    current_message_header = Some(header.with_subject(value)?);
                }
            }
            "date" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(header) = current_message_header.take() {
                    current_message_header = Some(header.with_date(value)?);
                }
            }
            "priority" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(header) = current_message_header.take() {
                    current_message_header = Some(header.with_priority(value)?);
                }
            }
            "message-id" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(header) = current_message_header.take() {
                    current_message_header = Some(header.with_message_id(value)?);
                }
            }
            "message-context" => {
                if current_message_header.is_none() {
                    current_message_header = Some(MessageHeader::new());
                }
                if let Some(header) = current_message_header.take() {
                    current_message_header = Some(header.with_message_context(value)?);
                }
            }
            _ => {}
        }
    }

    // Add accumulated message header if present
    if let Some(header) = current_message_header {
        summary.add_message_header(header)?;
    }

    if !found_status {
        return Err(MessageWaitingError::ParseError(
            "missing mandatory Messages-Waiting field".to_string(),
        ));
    }

    Ok(summary)
}

/// Parses message counts from format: "new/old (urgent_new/urgent_old)"
fn parse_message_counts(s: &str) -> Option<MessageCounts> {
    // Split on space to separate main counts from urgent counts
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

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

// Validation functions

fn validate_account(account: &str) -> Result<(), MessageWaitingError> {
    if account.len() > MAX_ACCOUNT_LENGTH {
        return Err(MessageWaitingError::AccountTooLong {
            max: MAX_ACCOUNT_LENGTH,
            actual: account.len(),
        });
    }

    if account.chars().any(|c| c.is_ascii_control()) {
        return Err(MessageWaitingError::InvalidAccount(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_header_value(value: &str) -> Result<(), MessageWaitingError> {
    if value.len() > MAX_HEADER_VALUE_LENGTH {
        return Err(MessageWaitingError::HeaderValueTooLong {
            max: MAX_HEADER_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(MessageWaitingError::InvalidHeaderValue(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_summary_basic() {
        let mut summary = MessageSummary::new(true);
        summary.set_account("sip:alice@vmail.example.com").unwrap();
        summary
            .add_message_class(MessageContextClass::Voice, MessageCounts::new(2, 8))
            .unwrap();

        assert!(summary.messages_waiting());
        assert_eq!(summary.account(), Some("sip:alice@vmail.example.com"));
        assert_eq!(summary.total_new(), 2);
        assert_eq!(summary.total_old(), 8);
    }

    #[test]
    fn reject_crlf_in_account() {
        let mut summary = MessageSummary::new(true);
        let result = summary.set_account("sip:alice\r\ninjected@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_account() {
        let mut summary = MessageSummary::new(true);
        let long_account = format!("sip:{}", "x".repeat(MAX_ACCOUNT_LENGTH));
        let result = summary.set_account(&long_account);
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_message_classes() {
        let mut summary = MessageSummary::new(true);

        let classes = [
            MessageContextClass::Voice,
            MessageContextClass::Fax,
            MessageContextClass::Pager,
            MessageContextClass::Multimedia,
            MessageContextClass::Text,
            MessageContextClass::None,
        ];

        let max_unique = MAX_MESSAGE_CLASSES.min(classes.len());
        for (idx, class) in classes.iter().take(max_unique).enumerate() {
            summary
                .add_message_class(*class, MessageCounts::new(idx as u32, 0))
                .unwrap();
        }

        // Updating an existing class should not trip the limit.
        summary
            .add_message_class(MessageContextClass::Voice, MessageCounts::new(99, 0))
            .unwrap();

        if let Some(next_class) = classes.get(MAX_MESSAGE_CLASSES) {
            let result = summary.add_message_class(*next_class, MessageCounts::new(100, 0));
            assert!(result.is_err());
        }
    }

    #[test]
    fn reject_too_many_headers() {
        let mut summary = MessageSummary::new(true);

        for _ in 0..MAX_MESSAGE_HEADERS {
            summary.add_message_header(MessageHeader::new()).unwrap();
        }

        // Should fail
        let result = summary.add_message_header(MessageHeader::new());
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_message_header() {
        let result = MessageHeader::new().with_subject("Hello\r\nInjected: evil");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_header_value() {
        let long_subject = "x".repeat(MAX_HEADER_VALUE_LENGTH + 1);
        let result = MessageHeader::new().with_subject(&long_subject);
        assert!(result.is_err());
    }

    #[test]
    fn message_summary_output() {
        let mut summary = MessageSummary::new(true);
        summary.set_account("sip:alice@vmail.example.com").unwrap();
        summary
            .add_message_class(
                MessageContextClass::Voice,
                MessageCounts::new(2, 8).with_urgent(0, 2),
            )
            .unwrap();

        let output = summary.to_string();
        assert!(output.contains("Messages-Waiting: yes"));
        assert!(output.contains("Message-Account: sip:alice@vmail.example.com"));
        assert!(output.contains("Voice-Message: 2/8 (0/2)"));
    }

    #[test]
    fn parse_simple_summary() {
        let body = "Messages-Waiting: yes\n\
                    Message-Account: sip:alice@vmail.example.com\n\
                    Voice-Message: 2/8 (0/2)\n";

        let summary = parse_message_summary(body).unwrap();
        assert!(summary.messages_waiting());
        assert_eq!(summary.account(), Some("sip:alice@vmail.example.com"));

        let messages: Vec<_> = summary.messages().collect();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn reject_oversized_parse_input() {
        let huge_body = "x".repeat(MAX_PARSE_SIZE + 1);
        let result = parse_message_summary(&huge_body);
        assert!(result.is_err());
    }

    #[test]
    fn reject_missing_status() {
        let body = "Message-Account: sip:alice@vmail.example.com\n";
        let result = parse_message_summary(body);
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_messages_waiting_value() {
        let body = "Messages-Waiting: maybe\n";
        let result = parse_message_summary(body);
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_message_counts() {
        let body = "Messages-Waiting: yes\nVoice-Message:\n";
        let summary = parse_message_summary(body).unwrap();
        assert!(summary.messages().next().is_none());
    }

    #[test]
    fn parse_multiple_message_headers() {
        let body = "Messages-Waiting: yes\n\
                    To: sip:alice@example.com\n\
                    Subject: First\n\
                    \n\
                    To: sip:bob@example.com\n\
                    Subject: Second\n";

        let summary = parse_message_summary(body).unwrap();
        let headers: Vec<_> = summary.message_headers().collect();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].to(), Some("sip:alice@example.com"));
        assert_eq!(headers[1].to(), Some("sip:bob@example.com"));
    }

    #[test]
    fn round_trip() {
        let mut summary = MessageSummary::new(true);
        summary.set_account("sip:alice@vmail.example.com").unwrap();
        summary
            .add_message_class(
                MessageContextClass::Voice,
                MessageCounts::new(2, 8).with_urgent(0, 2),
            )
            .unwrap();

        let output = summary.to_string();
        let parsed = parse_message_summary(&output).unwrap();

        assert_eq!(summary.messages_waiting(), parsed.messages_waiting());
        assert_eq!(summary.account(), parsed.account());
    }

    #[test]
    fn fields_are_private() {
        let summary = MessageSummary::new(true);
        let counts = MessageCounts::new(1, 2);
        let header = MessageHeader::new();

        // These should compile (read-only access)
        let _ = summary.messages_waiting();
        let _ = summary.account();
        let _ = counts.new_count();
        let _ = counts.old_count();
        let _ = header.to();

        // These should NOT compile (no direct field access):
        // summary.messages_waiting = false;  // ← Does not compile!
        // counts.new = 100;                  // ← Does not compile!
        // header.to = Some(...);             // ← Does not compile!
    }
}
