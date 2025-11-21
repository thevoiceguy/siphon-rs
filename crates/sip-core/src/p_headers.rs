use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::name_addr::NameAddr;

/// P-Access-Network-Info header (access-type plus params).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PAccessNetworkInfo {
    pub access_type: SmolStr,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

/// P-Visited-Network-ID header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PVisitedNetworkIdHeader {
    pub values: Vec<SmolStr>,
}

/// P-Asserted-Identity header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PAssertedIdentityHeader {
    pub identities: Vec<NameAddr>,
}

/// P-Preferred-Identity header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PPreferredIdentityHeader {
    pub identities: Vec<NameAddr>,
}
