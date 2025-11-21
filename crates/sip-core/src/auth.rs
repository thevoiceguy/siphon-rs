use std::collections::BTreeMap;

use smol_str::SmolStr;

/// Represents Authorization / Proxy-Authorization header values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationHeader {
    pub scheme: SmolStr,
    pub params: BTreeMap<SmolStr, SmolStr>,
}

impl AuthorizationHeader {
    pub fn param(&self, name: &str) -> Option<&SmolStr> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }
}
