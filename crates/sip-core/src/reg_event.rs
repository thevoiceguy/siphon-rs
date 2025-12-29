// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::fmt;

const MAX_URI_LENGTH: usize = 512;
const MAX_ID_LENGTH: usize = 128;
const MAX_DISPLAY_NAME_LENGTH: usize = 256;
const MAX_CALL_ID_LENGTH: usize = 256;
const MAX_REGISTRATIONS: usize = 100;
const MAX_CONTACTS: usize = 50;

#[derive(Debug, Clone, PartialEq)]
pub enum RegEventsError {
    UriTooLong { max: usize, actual: usize },
    IdTooLong { max: usize, actual: usize },
    DisplayNameTooLong { max: usize, actual: usize },
    CallIdTooLong { max: usize, actual: usize },
    TooManyRegistrations { max: usize, actual: usize },
    TooManyContacts { max: usize, actual: usize },
    InvalidUri(String),
    InvalidId(String),
    InvalidDisplayName(String),
    InvalidCallId(String),
    InvalidQValue(f32),
}

impl std::fmt::Display for RegEventsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UriTooLong { max, actual } => {
                write!(f, "URI too long (max {}, got {})", max, actual)
            }
            Self::IdTooLong { max, actual } => {
                write!(f, "ID too long (max {}, got {})", max, actual)
            }
            Self::TooManyRegistrations { max, actual } => {
                write!(f, "too many registrations (max {}, got {})", max, actual)
            }
            Self::TooManyContacts { max, actual } => {
                write!(f, "too many contacts (max {}, got {})", max, actual)
            }
            Self::InvalidQValue(val) => write!(f, "invalid q-value {} (must be 0.0-1.0)", val),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for RegEventsError {}

/// RFC 3680 Registration Information for the "reg" event package.
///
/// # Security
///
/// RegInfo validates all inputs and escapes XML output to prevent injection attacks.
#[derive(Debug, Clone, PartialEq)]
pub struct RegInfo {
    version: u32,
    state: RegInfoState,
    registrations: Vec<Registration>,
}

impl RegInfo {
    /// Creates a new RegInfo document.
    pub fn new(version: u32, state: RegInfoState) -> Self {
        Self {
            version,
            state,
            registrations: Vec::new(),
        }
    }

    /// Adds a registration to the document.
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum number of registrations is exceeded.
    pub fn add_registration(&mut self, registration: Registration) -> Result<(), RegEventsError> {
        if self.registrations.len() >= MAX_REGISTRATIONS {
            return Err(RegEventsError::TooManyRegistrations {
                max: MAX_REGISTRATIONS,
                actual: self.registrations.len() + 1,
            });
        }
        self.registrations.push(registration);
        Ok(())
    }

    /// Returns the version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the state.
    pub fn state(&self) -> RegInfoState {
        self.state
    }

    /// Returns a reference to the registrations.
    pub fn registrations(&self) -> &[Registration] {
        &self.registrations
    }

    /// Returns true if there are no registrations.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}

/// State of the RegInfo document (full or partial).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegInfoState {
    Full,
    Partial,
}

impl RegInfoState {
    pub fn as_str(&self) -> &str {
        match self {
            RegInfoState::Full => "full",
            RegInfoState::Partial => "partial",
        }
    }
}

/// Represents a single registration (address-of-record with its contacts).
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    aor: SmolStr,
    id: SmolStr,
    state: RegistrationState,
    contacts: Vec<Contact>,
}

impl Registration {
    /// Creates a new registration.
    ///
    /// # Errors
    ///
    /// Returns an error if the AOR or ID is invalid.
    pub fn new(
        aor: impl AsRef<str>,
        id: impl AsRef<str>,
        state: RegistrationState,
    ) -> Result<Self, RegEventsError> {
        validate_uri(aor.as_ref())?;
        validate_id(id.as_ref())?;

        Ok(Self {
            aor: SmolStr::new(aor.as_ref()),
            id: SmolStr::new(id.as_ref()),
            state,
            contacts: Vec::new(),
        })
    }

    /// Adds a contact to this registration.
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum number of contacts is exceeded.
    pub fn add_contact(&mut self, contact: Contact) -> Result<(), RegEventsError> {
        if self.contacts.len() >= MAX_CONTACTS {
            return Err(RegEventsError::TooManyContacts {
                max: MAX_CONTACTS,
                actual: self.contacts.len() + 1,
            });
        }
        self.contacts.push(contact);
        Ok(())
    }

    /// Returns the AOR.
    pub fn aor(&self) -> &str {
        &self.aor
    }

    /// Returns the ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the state.
    pub fn state(&self) -> RegistrationState {
        self.state
    }

    /// Returns a reference to the contacts.
    pub fn contacts(&self) -> &[Contact] {
        &self.contacts
    }

    /// Returns true if there are no contacts.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }
}

/// Registration state per RFC 3680.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    Init,
    Active,
    Terminated,
}

impl RegistrationState {
    pub fn as_str(&self) -> &str {
        match self {
            RegistrationState::Init => "init",
            RegistrationState::Active => "active",
            RegistrationState::Terminated => "terminated",
        }
    }
}

/// Represents a single contact within a registration.
#[derive(Debug, Clone, PartialEq)]
pub struct Contact {
    id: SmolStr,
    state: ContactState,
    event: Option<ContactEvent>,
    uri: SmolStr,
    display_name: Option<SmolStr>,
    expires: Option<u32>,
    retry_after: Option<u32>,
    duration_registered: Option<u32>,
    q: Option<f32>,
    call_id: Option<SmolStr>,
    cseq: Option<u32>,
}

impl Contact {
    /// Creates a new contact with minimal information.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID or URI is invalid.
    pub fn new(
        id: impl AsRef<str>,
        state: ContactState,
        uri: impl AsRef<str>,
    ) -> Result<Self, RegEventsError> {
        validate_id(id.as_ref())?;
        validate_uri(uri.as_ref())?;

        Ok(Self {
            id: SmolStr::new(id.as_ref()),
            state,
            event: None,
            uri: SmolStr::new(uri.as_ref()),
            display_name: None,
            expires: None,
            retry_after: None,
            duration_registered: None,
            q: None,
            call_id: None,
            cseq: None,
        })
    }

    /// Sets the event that triggered this state.
    pub fn with_event(mut self, event: ContactEvent) -> Self {
        self.event = Some(event);
        self
    }

    /// Sets the expiration time.
    pub fn with_expires(mut self, expires: u32) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sets the display name.
    ///
    /// # Errors
    ///
    /// Returns an error if the display name is invalid.
    pub fn with_display_name(mut self, name: impl AsRef<str>) -> Result<Self, RegEventsError> {
        validate_display_name(name.as_ref())?;
        self.display_name = Some(SmolStr::new(name.as_ref()));
        Ok(self)
    }

    /// Sets the Call-ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the Call-ID is invalid.
    pub fn with_call_id(mut self, call_id: impl AsRef<str>) -> Result<Self, RegEventsError> {
        validate_call_id(call_id.as_ref())?;
        self.call_id = Some(SmolStr::new(call_id.as_ref()));
        Ok(self)
    }

    /// Sets the CSeq.
    pub fn with_cseq(mut self, cseq: u32) -> Self {
        self.cseq = Some(cseq);
        self
    }

    /// Sets the q-value (must be 0.0-1.0).
    ///
    /// # Errors
    ///
    /// Returns an error if the q-value is out of range.
    pub fn with_q(mut self, q: f32) -> Result<Self, RegEventsError> {
        if !(0.0..=1.0).contains(&q) {
            return Err(RegEventsError::InvalidQValue(q));
        }
        self.q = Some(q);
        Ok(self)
    }

    /// Sets retry-after.
    pub fn with_retry_after(mut self, retry_after: u32) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Sets duration-registered.
    pub fn with_duration_registered(mut self, duration: u32) -> Self {
        self.duration_registered = Some(duration);
        self
    }

    // Getters
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn state(&self) -> ContactState {
        self.state
    }

    pub fn event(&self) -> Option<ContactEvent> {
        self.event
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn expires(&self) -> Option<u32> {
        self.expires
    }

    pub fn retry_after(&self) -> Option<u32> {
        self.retry_after
    }

    pub fn duration_registered(&self) -> Option<u32> {
        self.duration_registered
    }

    pub fn q(&self) -> Option<f32> {
        self.q
    }

    pub fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }

    pub fn cseq(&self) -> Option<u32> {
        self.cseq
    }
}

/// Contact state per RFC 3680.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactState {
    Active,
    Terminated,
}

impl ContactState {
    pub fn as_str(&self) -> &str {
        match self {
            ContactState::Active => "active",
            ContactState::Terminated => "terminated",
        }
    }
}

/// Contact event that triggered a state change (RFC 3680).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactEvent {
    Registered,
    Created,
    Refreshed,
    Shortened,
    Expired,
    Deactivated,
    Rejected,
    Unregistered,
    Probation,
}

impl ContactEvent {
    pub fn as_str(&self) -> &str {
        match self {
            ContactEvent::Registered => "registered",
            ContactEvent::Created => "created",
            ContactEvent::Refreshed => "refreshed",
            ContactEvent::Shortened => "shortened",
            ContactEvent::Expired => "expired",
            ContactEvent::Deactivated => "deactivated",
            ContactEvent::Rejected => "rejected",
            ContactEvent::Unregistered => "unregistered",
            ContactEvent::Probation => "probation",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "registered" => Some(ContactEvent::Registered),
            "created" => Some(ContactEvent::Created),
            "refreshed" => Some(ContactEvent::Refreshed),
            "shortened" => Some(ContactEvent::Shortened),
            "expired" => Some(ContactEvent::Expired),
            "deactivated" => Some(ContactEvent::Deactivated),
            "rejected" => Some(ContactEvent::Rejected),
            "unregistered" => Some(ContactEvent::Unregistered),
            "probation" => Some(ContactEvent::Probation),
            _ => None,
        }
    }
}

impl std::str::FromStr for ContactEvent {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

// Validation functions

fn validate_uri(uri: &str) -> Result<(), RegEventsError> {
    if uri.is_empty() {
        return Err(RegEventsError::InvalidUri("empty URI".to_string()));
    }
    if uri.len() > MAX_URI_LENGTH {
        return Err(RegEventsError::UriTooLong {
            max: MAX_URI_LENGTH,
            actual: uri.len(),
        });
    }

    if uri.chars().any(|c| c.is_ascii_control()) {
        return Err(RegEventsError::InvalidUri(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_id(id: &str) -> Result<(), RegEventsError> {
    if id.is_empty() {
        return Err(RegEventsError::InvalidId("empty ID".to_string()));
    }

    if id.len() > MAX_ID_LENGTH {
        return Err(RegEventsError::IdTooLong {
            max: MAX_ID_LENGTH,
            actual: id.len(),
        });
    }

    if id.chars().any(|c| c.is_ascii_control()) {
        return Err(RegEventsError::InvalidId(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_display_name(name: &str) -> Result<(), RegEventsError> {
    if name.len() > MAX_DISPLAY_NAME_LENGTH {
        return Err(RegEventsError::DisplayNameTooLong {
            max: MAX_DISPLAY_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(RegEventsError::InvalidDisplayName(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_call_id(call_id: &str) -> Result<(), RegEventsError> {
    if call_id.is_empty() {
        return Err(RegEventsError::InvalidCallId("empty Call-ID".to_string()));
    }
    if call_id.len() > MAX_CALL_ID_LENGTH {
        return Err(RegEventsError::CallIdTooLong {
            max: MAX_CALL_ID_LENGTH,
            actual: call_id.len(),
        });
    }

    if call_id.chars().any(|c| c.is_ascii_control()) {
        return Err(RegEventsError::InvalidCallId(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Escapes XML special characters to prevent injection attacks.
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

/// Formats RegInfo as application/reginfo+xml per RFC 3680.
///
/// # Security
///
/// All output is properly XML-escaped to prevent injection attacks.
impl fmt::Display for RegInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "<?xml version=\"1.0\"?>")?;
        writeln!(
            f,
            "<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"{}\" state=\"{}\">",
            self.version,
            self.state.as_str()
        )?;

        for registration in &self.registrations {
            writeln!(
                f,
                "  <registration aor=\"{}\" id=\"{}\" state=\"{}\">",
                xml_escape(&registration.aor),
                xml_escape(&registration.id),
                registration.state.as_str()
            )?;

            for contact in &registration.contacts {
                write!(
                    f,
                    "    <contact id=\"{}\" state=\"{}\"",
                    xml_escape(&contact.id),
                    contact.state.as_str()
                )?;

                if let Some(event) = &contact.event {
                    write!(f, " event=\"{}\"", event.as_str())?;
                }

                if let Some(expires) = contact.expires {
                    write!(f, " expires=\"{}\"", expires)?;
                }

                if let Some(retry_after) = contact.retry_after {
                    write!(f, " retry-after=\"{}\"", retry_after)?;
                }

                if let Some(duration) = contact.duration_registered {
                    write!(f, " duration-registered=\"{}\"", duration)?;
                }

                if let Some(q) = contact.q {
                    write!(f, " q=\"{}\"", q)?;
                }

                if let Some(ref call_id) = contact.call_id {
                    write!(f, " callid=\"{}\"", xml_escape(call_id))?;
                }

                if let Some(cseq) = contact.cseq {
                    write!(f, " cseq=\"{}\"", cseq)?;
                }

                writeln!(f, ">")?;

                writeln!(f, "      <uri>{}</uri>", xml_escape(&contact.uri))?;

                if let Some(ref display_name) = contact.display_name {
                    writeln!(
                        f,
                        "      <display-name>{}</display-name>",
                        xml_escape(display_name)
                    )?;
                }

                writeln!(f, "    </contact>")?;
            }

            writeln!(f, "  </registration>")?;
        }

        writeln!(f, "</reginfo>")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reginfo_empty() {
        let reginfo = RegInfo::new(1, RegInfoState::Full);
        assert_eq!(reginfo.version(), 1);
        assert!(reginfo.is_empty());
    }

    #[test]
    fn reginfo_with_registration() {
        let mut reginfo = RegInfo::new(1, RegInfoState::Full);

        let registration =
            Registration::new("sip:alice@example.com", "reg1", RegistrationState::Active).unwrap();

        reginfo.add_registration(registration).unwrap();
        assert!(!reginfo.is_empty());
        assert_eq!(reginfo.registrations().len(), 1);
    }

    #[test]
    fn registration_with_contact() {
        let mut registration =
            Registration::new("sip:alice@example.com", "reg1", RegistrationState::Active).unwrap();

        let contact = Contact::new(
            "contact1",
            ContactState::Active,
            "sip:alice@192.168.1.100:5060",
        )
        .unwrap();

        registration.add_contact(contact).unwrap();
        assert!(!registration.is_empty());
        assert_eq!(registration.contacts().len(), 1);
    }

    #[test]
    fn contact_with_details() {
        let contact = Contact::new(
            "contact1",
            ContactState::Active,
            "sip:alice@192.168.1.100:5060",
        )
        .unwrap()
        .with_event(ContactEvent::Registered)
        .with_expires(3600)
        .with_display_name("Alice Smith")
        .unwrap()
        .with_q(0.8)
        .unwrap();

        assert_eq!(contact.event(), Some(ContactEvent::Registered));
        assert_eq!(contact.expires(), Some(3600));
        assert_eq!(contact.display_name(), Some("Alice Smith"));
        assert_eq!(contact.q(), Some(0.8));
    }

    #[test]
    fn reginfo_xml_output() {
        let mut reginfo = RegInfo::new(1, RegInfoState::Full);

        let mut registration =
            Registration::new("sip:alice@example.com", "reg1", RegistrationState::Active).unwrap();

        let contact = Contact::new(
            "contact1",
            ContactState::Active,
            "sip:alice@192.168.1.100:5060",
        )
        .unwrap()
        .with_event(ContactEvent::Registered)
        .with_expires(3600);

        registration.add_contact(contact).unwrap();
        reginfo.add_registration(registration).unwrap();

        let xml = reginfo.to_string();
        assert!(xml.contains("<?xml version=\"1.0\"?>"));
        assert!(xml.contains("<reginfo"));
        assert!(xml.contains("version=\"1\""));
        assert!(xml.contains("state=\"full\""));
        assert!(xml.contains("<registration"));
        assert!(xml.contains("aor=\"sip:alice@example.com\""));
        assert!(xml.contains("<contact"));
        assert!(xml.contains("event=\"registered\""));
        assert!(xml.contains("expires=\"3600\""));
        assert!(xml.contains("<uri>sip:alice@192.168.1.100:5060</uri>"));
    }

    #[test]
    fn contact_event_from_str() {
        assert_eq!(
            ContactEvent::parse("registered"),
            Some(ContactEvent::Registered)
        );
        assert_eq!(ContactEvent::parse("expired"), Some(ContactEvent::Expired));
        assert_eq!(
            ContactEvent::parse("refreshed"),
            Some(ContactEvent::Refreshed)
        );
        assert_eq!(ContactEvent::parse("invalid"), None);
    }

    #[test]
    fn reginfo_state_as_str() {
        assert_eq!(RegInfoState::Full.as_str(), "full");
        assert_eq!(RegInfoState::Partial.as_str(), "partial");
    }

    #[test]
    fn registration_state_as_str() {
        assert_eq!(RegistrationState::Init.as_str(), "init");
        assert_eq!(RegistrationState::Active.as_str(), "active");
        assert_eq!(RegistrationState::Terminated.as_str(), "terminated");
    }

    #[test]
    fn contact_state_as_str() {
        assert_eq!(ContactState::Active.as_str(), "active");
        assert_eq!(ContactState::Terminated.as_str(), "terminated");
    }

    #[test]
    fn contact_terminated_with_expired() {
        let contact = Contact::new(
            "contact1",
            ContactState::Terminated,
            "sip:alice@192.168.1.100:5060",
        )
        .unwrap()
        .with_event(ContactEvent::Expired);

        assert_eq!(contact.state(), ContactState::Terminated);
        assert_eq!(contact.event(), Some(ContactEvent::Expired));
    }

    #[test]
    fn multiple_contacts_in_registration() {
        let mut registration =
            Registration::new("sip:alice@example.com", "reg1", RegistrationState::Active).unwrap();

        let contact1 = Contact::new(
            "contact1",
            ContactState::Active,
            "sip:alice@192.168.1.100:5060",
        )
        .unwrap();

        let contact2 =
            Contact::new("contact2", ContactState::Active, "sip:alice@10.0.0.50:5060").unwrap();

        registration.add_contact(contact1).unwrap();
        registration.add_contact(contact2).unwrap();

        assert_eq!(registration.contacts().len(), 2);
    }

    // Security tests

    #[test]
    fn xml_escape_test() {
        assert_eq!(xml_escape("normal"), "normal");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(xml_escape("'single'"), "&apos;single&apos;");
    }

    #[test]
    fn xml_injection_prevention() {
        let mut reginfo = RegInfo::new(1, RegInfoState::Full);
        let mut registration =
            Registration::new("sip:alice@example.com", "reg1", RegistrationState::Active).unwrap();

        // Try to inject XML
        let contact = Contact::new(
            "contact1",
            ContactState::Active,
            "sip:alice@example.com</uri><script>alert('xss')</script><uri>",
        )
        .unwrap();

        registration.add_contact(contact).unwrap();
        reginfo.add_registration(registration).unwrap();

        let xml = reginfo.to_string();
        // Should be escaped
        assert!(xml.contains("&lt;/uri&gt;&lt;script&gt;"));
        assert!(!xml.contains("</uri><script>"));
    }

    #[test]
    fn reject_crlf_in_uri() {
        let result = Contact::new(
            "contact1",
            ContactState::Active,
            "sip:alice@example.com\r\ninjected",
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_uri() {
        let result = Contact::new("contact1", ContactState::Active, "");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_id() {
        let result = Contact::new(
            "contact1\r\ninjected",
            ContactState::Active,
            "sip:alice@example.com",
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_q_value() {
        let contact =
            Contact::new("contact1", ContactState::Active, "sip:alice@example.com").unwrap();

        assert!(contact.clone().with_q(-0.1).is_err());
        assert!(contact.clone().with_q(1.1).is_err());
        assert!(contact.with_q(999.9).is_err());
    }

    #[test]
    fn accept_valid_q_value() {
        let contact =
            Contact::new("contact1", ContactState::Active, "sip:alice@example.com").unwrap();

        assert!(contact.clone().with_q(0.0).is_ok());
        assert!(contact.clone().with_q(0.5).is_ok());
        assert!(contact.with_q(1.0).is_ok());
    }

    #[test]
    fn reject_too_many_registrations() {
        let mut reginfo = RegInfo::new(1, RegInfoState::Full);

        for i in 0..MAX_REGISTRATIONS {
            let reg = Registration::new(
                &format!("sip:user{}@example.com", i),
                &format!("reg{}", i),
                RegistrationState::Active,
            )
            .unwrap();
            reginfo.add_registration(reg).unwrap();
        }

        let result = reginfo.add_registration(
            Registration::new(
                "sip:overflow@example.com",
                "overflow",
                RegistrationState::Active,
            )
            .unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_contacts() {
        let mut registration =
            Registration::new("sip:alice@example.com", "reg1", RegistrationState::Active).unwrap();

        for i in 0..MAX_CONTACTS {
            let contact = Contact::new(
                &format!("contact{}", i),
                ContactState::Active,
                &format!("sip:alice@192.168.1.{}:5060", i),
            )
            .unwrap();
            registration.add_contact(contact).unwrap();
        }

        let result = registration.add_contact(
            Contact::new("overflow", ContactState::Active, "sip:overflow@example.com").unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_uri() {
        let long_uri = format!("sip:{}@example.com", "x".repeat(MAX_URI_LENGTH));
        let result = Contact::new("contact1", ContactState::Active, &long_uri);
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_call_id() {
        let result = Contact::new("contact1", ContactState::Active, "sip:alice@example.com")
            .unwrap()
            .with_call_id("");
        assert!(result.is_err());
    }

    #[test]
    fn fields_are_private() {
        let reginfo = RegInfo::new(1, RegInfoState::Full);
        let registration =
            Registration::new("sip:alice@example.com", "reg1", RegistrationState::Active).unwrap();
        let contact =
            Contact::new("contact1", ContactState::Active, "sip:alice@example.com").unwrap();

        // These should compile (read-only access)
        let _ = reginfo.version();
        let _ = registration.aor();
        let _ = contact.uri();

        // These should NOT compile:
        // reginfo.version = 2;                // ← Does not compile!
        // registration.contacts.clear();       // ← Does not compile!
        // contact.uri = SmolStr::new("evil");  // ← Does not compile!
    }
}
