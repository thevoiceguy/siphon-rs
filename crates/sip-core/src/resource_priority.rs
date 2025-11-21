use smol_str::SmolStr;

/// Represents a single namespace.priority value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePriorityValue {
    pub namespace: SmolStr,
    pub priority: SmolStr,
}

/// Represents Resource-Priority/Accept-Resource-Priority headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePriorityHeader {
    pub values: Vec<ResourcePriorityValue>,
}
