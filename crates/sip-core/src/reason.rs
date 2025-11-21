use std::collections::BTreeMap;

use smol_str::SmolStr;

/// Represents the Reason header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonHeader {
    pub protocol: SmolStr,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}
