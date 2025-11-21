use smol_str::SmolStr;
use std::time::SystemTime;

/// SIP Date header representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateHeader {
    pub raw: SmolStr,
    pub timestamp: Option<SystemTime>,
}
