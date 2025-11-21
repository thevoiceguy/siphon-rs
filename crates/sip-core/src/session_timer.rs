/// Represents the `Session-Expires` header (RFC 4028).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExpires {
    pub delta_seconds: u32,
    pub refresher: Option<RefresherRole>,
}

/// Represents the `Min-SE` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinSessionExpires {
    pub delta_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefresherRole {
    Uac,
    Uas,
}

impl RefresherRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            RefresherRole::Uac => "uac",
            RefresherRole::Uas => "uas",
        }
    }
}
