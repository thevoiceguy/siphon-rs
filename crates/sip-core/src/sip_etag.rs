use smol_str::SmolStr;

/// Represents the SIP-ETag header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipETagHeader {
    pub value: SmolStr,
}
