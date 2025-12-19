use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::{SipUri, TelUri, Uri};

/// Generic SIP name-addr structure used by many headers (From/To/Contact/etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddr {
    pub display_name: Option<SmolStr>,
    pub uri: Uri,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl NameAddr {
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn sip_uri(&self) -> Option<&SipUri> {
        self.uri.as_sip()
    }

    pub fn tel_uri(&self) -> Option<&TelUri> {
        self.uri.as_tel()
    }

    pub fn params(&self) -> impl Iterator<Item = (&SmolStr, &Option<SmolStr>)> {
        self.params.iter()
    }

    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }

    pub fn params_map(&self) -> &BTreeMap<SmolStr, Option<SmolStr>> {
        &self.params
    }
}
