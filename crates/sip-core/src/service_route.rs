use crate::name_addr::NameAddr;

/// Represents the Service-Route header (list of NameAddr values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRouteHeader {
    pub routes: Vec<NameAddr>,
}

/// Represents the Path header (list of NameAddr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHeader {
    pub routes: Vec<NameAddr>,
}
