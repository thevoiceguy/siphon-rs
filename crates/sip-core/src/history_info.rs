use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::SipUri;

/// Represents a single History-Info entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfoEntry {
    pub uri: SipUri,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

/// History-Info header containing ordered entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfoHeader {
    pub entries: Vec<HistoryInfoEntry>,
}
