use smol_str::SmolStr;

/// SIP request methods supported by the stack.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    Invite,
    Ack,
    Bye,
    Cancel,
    Register,
    Options,
    Info,
    Update,
    Message,
    Prack,
    Refer,
    Subscribe,
    Notify,
    Publish,
    Unknown(SmolStr),
}

impl Method {
    /// Returns the canonical uppercase string representation for this method.
    pub fn as_str(&self) -> &str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Info => "INFO",
            Method::Update => "UPDATE",
            Method::Message => "MESSAGE",
            Method::Prack => "PRACK",
            Method::Refer => "REFER",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Publish => "PUBLISH",
            Method::Unknown(token) => token.as_str(),
        }
    }

    /// Parses a method token, returning Unknown for extension methods.
    pub fn from_token(token: &str) -> Self {
        if token.eq_ignore_ascii_case("OPTIONS") {
            Method::Options
        } else if token.eq_ignore_ascii_case("INVITE") {
            Method::Invite
        } else if token.eq_ignore_ascii_case("ACK") {
            Method::Ack
        } else if token.eq_ignore_ascii_case("BYE") {
            Method::Bye
        } else if token.eq_ignore_ascii_case("CANCEL") {
            Method::Cancel
        } else if token.eq_ignore_ascii_case("REGISTER") {
            Method::Register
        } else if token.eq_ignore_ascii_case("INFO") {
            Method::Info
        } else if token.eq_ignore_ascii_case("UPDATE") {
            Method::Update
        } else if token.eq_ignore_ascii_case("MESSAGE") {
            Method::Message
        } else if token.eq_ignore_ascii_case("PRACK") {
            Method::Prack
        } else if token.eq_ignore_ascii_case("REFER") {
            Method::Refer
        } else if token.eq_ignore_ascii_case("SUBSCRIBE") {
            Method::Subscribe
        } else if token.eq_ignore_ascii_case("NOTIFY") {
            Method::Notify
        } else if token.eq_ignore_ascii_case("PUBLISH") {
            Method::Publish
        } else {
            Method::Unknown(SmolStr::new(token.to_owned()))
        }
    }
}
