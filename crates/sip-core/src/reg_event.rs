use smol_str::SmolStr;
use std::fmt;

/// RFC 3680 Registration Information for the "reg" event package.
///
/// This represents the registration state for one or more address-of-records,
/// typically conveyed in NOTIFY messages with Content-Type: application/reginfo+xml.
///
/// # RFC 3680 Overview
///
/// - Event package name: "reg"
/// - MIME type: application/reginfo+xml
/// - Default subscription duration: 3761 seconds
/// - Notifies subscribers about registration state changes
///
/// # Examples
///
/// ```
/// use sip_core::{RegInfo, Registration, Contact, ContactState, RegInfoState, RegistrationState};
/// use smol_str::SmolStr;
///
/// // Create registration info with one active contact
/// let mut reginfo = RegInfo::new(1, RegInfoState::Full);
///
/// let mut registration = Registration::new(
///     SmolStr::new("sip:alice@example.com"),
///     SmolStr::new("reg1"),
///     RegistrationState::Active
/// );
///
/// let contact = Contact::new(
///     SmolStr::new("contact1"),
///     ContactState::Active,
///     SmolStr::new("sip:alice@192.168.1.100:5060")
/// );
///
/// registration.add_contact(contact);
/// reginfo.add_registration(registration);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RegInfo {
    /// Version number, incremented with each state change
    pub version: u32,
    /// Whether this is full state or partial state
    pub state: RegInfoState,
    /// List of registrations (one per address-of-record)
    pub registrations: Vec<Registration>,
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
    pub fn add_registration(&mut self, registration: Registration) {
        self.registrations.push(registration);
    }

    /// Returns true if there are no registrations.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}

/// State of the RegInfo document (full or partial).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegInfoState {
    /// Full state notification (all contacts)
    Full,
    /// Partial state notification (only changed contacts)
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
///
/// Per RFC 3680, each registration element corresponds to one address-of-record
/// and contains zero or more contact elements.
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    /// Address-of-record URI
    pub aor: SmolStr,
    /// Unique identifier for this registration
    pub id: SmolStr,
    /// Registration state (init, active, terminated)
    pub state: RegistrationState,
    /// List of contacts bound to this address-of-record
    pub contacts: Vec<Contact>,
}

impl Registration {
    /// Creates a new registration.
    pub fn new(aor: SmolStr, id: SmolStr, state: RegistrationState) -> Self {
        Self {
            aor,
            id,
            state,
            contacts: Vec::new(),
        }
    }

    /// Adds a contact to this registration.
    pub fn add_contact(&mut self, contact: Contact) {
        self.contacts.push(contact);
    }

    /// Returns true if there are no contacts.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }
}

/// Registration state per RFC 3680.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    /// Initial state
    Init,
    /// Registration is active
    Active,
    /// Registration has been terminated
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
///
/// Per RFC 3680, each contact element provides information about one
/// specific contact binding.
#[derive(Debug, Clone, PartialEq)]
pub struct Contact {
    /// Unique identifier for this contact
    pub id: SmolStr,
    /// Contact state (active, terminated)
    pub state: ContactState,
    /// Event that triggered this state (registered, created, refreshed, etc.)
    pub event: Option<ContactEvent>,
    /// Contact URI
    pub uri: SmolStr,
    /// Optional display name
    pub display_name: Option<SmolStr>,
    /// Registration expiration time in seconds (optional)
    pub expires: Option<u32>,
    /// Retry-After value in seconds (for rejected contacts)
    pub retry_after: Option<u32>,
    /// Duration until probation ends (for probation state)
    pub duration_registered: Option<u32>,
    /// Q-value (priority)
    pub q: Option<f32>,
    /// Call-ID of the REGISTER request
    pub call_id: Option<SmolStr>,
    /// CSeq of the REGISTER request
    pub cseq: Option<u32>,
}

impl Contact {
    /// Creates a new contact with minimal information.
    pub fn new(id: SmolStr, state: ContactState, uri: SmolStr) -> Self {
        Self {
            id,
            state,
            event: None,
            uri,
            display_name: None,
            expires: None,
            retry_after: None,
            duration_registered: None,
            q: None,
            call_id: None,
            cseq: None,
        }
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
    pub fn with_display_name(mut self, name: impl Into<SmolStr>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Sets the Call-ID.
    pub fn with_call_id(mut self, call_id: impl Into<SmolStr>) -> Self {
        self.call_id = Some(call_id.into());
        self
    }

    /// Sets the CSeq.
    pub fn with_cseq(mut self, cseq: u32) -> Self {
        self.cseq = Some(cseq);
        self
    }

    /// Sets the q-value.
    pub fn with_q(mut self, q: f32) -> Self {
        self.q = Some(q);
        self
    }
}

/// Contact state per RFC 3680.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactState {
    /// Contact is active (registered)
    Active,
    /// Contact has been terminated (unregistered, expired, etc.)
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
    /// Contact was registered (entered active state)
    Registered,
    /// Contact was created
    Created,
    /// Contact registration was refreshed
    Refreshed,
    /// Contact registration duration was shortened
    Shortened,
    /// Contact registration expired
    Expired,
    /// Contact was deactivated
    Deactivated,
    /// Contact registration was rejected
    Rejected,
    /// Contact was explicitly unregistered
    Unregistered,
    /// Contact is in probation period
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

    pub fn from_str(s: &str) -> Option<Self> {
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

/// Formats RegInfo as application/reginfo+xml per RFC 3680.
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
                registration.aor,
                registration.id,
                registration.state.as_str()
            )?;

            for contact in &registration.contacts {
                write!(
                    f,
                    "    <contact id=\"{}\" state=\"{}\"",
                    contact.id,
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
                    write!(f, " callid=\"{}\"", call_id)?;
                }

                if let Some(cseq) = contact.cseq {
                    write!(f, " cseq=\"{}\"", cseq)?;
                }

                writeln!(f, ">")?;

                writeln!(f, "      <uri>{}</uri>", contact.uri)?;

                if let Some(ref display_name) = contact.display_name {
                    writeln!(f, "      <display-name>{}</display-name>", display_name)?;
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
        assert_eq!(reginfo.version, 1);
        assert!(reginfo.is_empty());
    }

    #[test]
    fn reginfo_with_registration() {
        let mut reginfo = RegInfo::new(1, RegInfoState::Full);

        let registration = Registration::new(
            SmolStr::new("sip:alice@example.com"),
            SmolStr::new("reg1"),
            RegistrationState::Active,
        );

        reginfo.add_registration(registration);
        assert!(!reginfo.is_empty());
        assert_eq!(reginfo.registrations.len(), 1);
    }

    #[test]
    fn registration_with_contact() {
        let mut registration = Registration::new(
            SmolStr::new("sip:alice@example.com"),
            SmolStr::new("reg1"),
            RegistrationState::Active,
        );

        let contact = Contact::new(
            SmolStr::new("contact1"),
            ContactState::Active,
            SmolStr::new("sip:alice@192.168.1.100:5060"),
        );

        registration.add_contact(contact);
        assert!(!registration.is_empty());
        assert_eq!(registration.contacts.len(), 1);
    }

    #[test]
    fn contact_with_details() {
        let contact = Contact::new(
            SmolStr::new("contact1"),
            ContactState::Active,
            SmolStr::new("sip:alice@192.168.1.100:5060"),
        )
        .with_event(ContactEvent::Registered)
        .with_expires(3600)
        .with_display_name("Alice Smith")
        .with_q(0.8);

        assert_eq!(contact.event, Some(ContactEvent::Registered));
        assert_eq!(contact.expires, Some(3600));
        assert_eq!(contact.display_name, Some(SmolStr::new("Alice Smith")));
        assert_eq!(contact.q, Some(0.8));
    }

    #[test]
    fn reginfo_xml_output() {
        let mut reginfo = RegInfo::new(1, RegInfoState::Full);

        let mut registration = Registration::new(
            SmolStr::new("sip:alice@example.com"),
            SmolStr::new("reg1"),
            RegistrationState::Active,
        );

        let contact = Contact::new(
            SmolStr::new("contact1"),
            ContactState::Active,
            SmolStr::new("sip:alice@192.168.1.100:5060"),
        )
        .with_event(ContactEvent::Registered)
        .with_expires(3600);

        registration.add_contact(contact);
        reginfo.add_registration(registration);

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
            ContactEvent::from_str("registered"),
            Some(ContactEvent::Registered)
        );
        assert_eq!(
            ContactEvent::from_str("expired"),
            Some(ContactEvent::Expired)
        );
        assert_eq!(
            ContactEvent::from_str("refreshed"),
            Some(ContactEvent::Refreshed)
        );
        assert_eq!(ContactEvent::from_str("invalid"), None);
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
            SmolStr::new("contact1"),
            ContactState::Terminated,
            SmolStr::new("sip:alice@192.168.1.100:5060"),
        )
        .with_event(ContactEvent::Expired);

        assert_eq!(contact.state, ContactState::Terminated);
        assert_eq!(contact.event, Some(ContactEvent::Expired));
    }

    #[test]
    fn multiple_contacts_in_registration() {
        let mut registration = Registration::new(
            SmolStr::new("sip:alice@example.com"),
            SmolStr::new("reg1"),
            RegistrationState::Active,
        );

        let contact1 = Contact::new(
            SmolStr::new("contact1"),
            ContactState::Active,
            SmolStr::new("sip:alice@192.168.1.100:5060"),
        );

        let contact2 = Contact::new(
            SmolStr::new("contact2"),
            ContactState::Active,
            SmolStr::new("sip:alice@10.0.0.50:5060"),
        );

        registration.add_contact(contact1);
        registration.add_contact(contact2);

        assert_eq!(registration.contacts.len(), 2);
    }
}
