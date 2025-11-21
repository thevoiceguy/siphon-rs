/// SIP request methods supported by the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

impl Method {
    /// Returns the canonical uppercase string representation for this method.
    pub const fn as_str(self) -> &'static str {
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
        }
    }
}
