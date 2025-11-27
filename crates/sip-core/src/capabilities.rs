/// RFC 3840 SIP User Agent Capabilities (Callee Capabilities).
///
/// This module implements RFC 3840, which defines mechanisms for SIP user agents
/// to communicate their capabilities and characteristics. Feature tags are used
/// to convey information about media types, supported methods, events, and other
/// capabilities.
///
/// # RFC 3840 Overview
///
/// - Feature tags indicate UA capabilities (audio, video, methods, etc.)
/// - Capabilities are conveyed as Contact header parameters
/// - Used in REGISTER, OPTIONS, and other SIP messages
/// - Enables intelligent routing and feature negotiation
///
/// # Examples
///
/// ```
/// use sip_core::{FeatureTag, FeatureValue, Capability};
///
/// // Create audio capability
/// let audio = Capability::new(FeatureTag::Audio, FeatureValue::Boolean(true));
///
/// // Create methods capability
/// let methods = Capability::new(
///     FeatureTag::Methods,
///     FeatureValue::TokenList(vec!["INVITE".into(), "BYE".into()])
/// );
/// ```
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

/// RFC 3840 feature tags for indicating UA capabilities.
///
/// Feature tags are identifiers that represent specific properties or capabilities
/// of a user agent. Tags defined by RFC 3840 use the "sip." prefix, but this prefix
/// is stripped when encoded as Contact header parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FeatureTag {
    /// Audio media streaming support (sip.audio)
    Audio,
    /// Video media streaming support (sip.video)
    Video,
    /// Application media streaming support (sip.application)
    Application,
    /// Data media streaming support (sip.data)
    Data,
    /// Control media streaming support (sip.control)
    Control,
    /// Text media streaming support (sip.text)
    Text,

    /// Whether the UA is an automaton (sip.automata)
    Automata,
    /// Device class: business or personal (sip.class)
    Class,
    /// Duplex mode: full, half, send-only, receive-only (sip.duplex)
    Duplex,
    /// Mobility: fixed or mobile (sip.mobility)
    Mobility,
    /// Human-readable description (sip.description)
    Description,

    /// Supported event packages (sip.events)
    Events,
    /// Supported priority values (sip.priority)
    Priority,
    /// Supported SIP methods (sip.methods)
    Methods,
    /// Supported URI schemes (sip.schemes)
    Schemes,
    /// Supported SIP extensions (sip.extensions)
    Extensions,

    /// Whether UA is a conference focus (sip.isfocus)
    IsFocus,
    /// Actor type: principal, attendant, msg-taker, information (sip.actor)
    Actor,
    /// Supported languages (sip.language)
    Language,
}

impl FeatureTag {
    /// Returns the feature tag name with "sip." prefix (as used in RFC 3840).
    pub fn as_str(&self) -> &str {
        match self {
            FeatureTag::Audio => "sip.audio",
            FeatureTag::Video => "sip.video",
            FeatureTag::Application => "sip.application",
            FeatureTag::Data => "sip.data",
            FeatureTag::Control => "sip.control",
            FeatureTag::Text => "sip.text",
            FeatureTag::Automata => "sip.automata",
            FeatureTag::Class => "sip.class",
            FeatureTag::Duplex => "sip.duplex",
            FeatureTag::Mobility => "sip.mobility",
            FeatureTag::Description => "sip.description",
            FeatureTag::Events => "sip.events",
            FeatureTag::Priority => "sip.priority",
            FeatureTag::Methods => "sip.methods",
            FeatureTag::Schemes => "sip.schemes",
            FeatureTag::Extensions => "sip.extensions",
            FeatureTag::IsFocus => "sip.isfocus",
            FeatureTag::Actor => "sip.actor",
            FeatureTag::Language => "sip.language",
        }
    }

    /// Returns the Contact header parameter name (without "sip." prefix).
    ///
    /// Per RFC 3840, the "sip." prefix is stripped when encoding as Contact parameters.
    pub fn param_name(&self) -> &str {
        match self {
            FeatureTag::Audio => "audio",
            FeatureTag::Video => "video",
            FeatureTag::Application => "application",
            FeatureTag::Data => "data",
            FeatureTag::Control => "control",
            FeatureTag::Text => "text",
            FeatureTag::Automata => "automata",
            FeatureTag::Class => "class",
            FeatureTag::Duplex => "duplex",
            FeatureTag::Mobility => "mobility",
            FeatureTag::Description => "description",
            FeatureTag::Events => "events",
            FeatureTag::Priority => "priority",
            FeatureTag::Methods => "methods",
            FeatureTag::Schemes => "schemes",
            FeatureTag::Extensions => "extensions",
            FeatureTag::IsFocus => "isfocus",
            FeatureTag::Actor => "actor",
            FeatureTag::Language => "language",
        }
    }

    /// Parses a feature tag from a parameter name (without "sip." prefix).
    pub fn from_param_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "audio" => Some(FeatureTag::Audio),
            "video" => Some(FeatureTag::Video),
            "application" => Some(FeatureTag::Application),
            "data" => Some(FeatureTag::Data),
            "control" => Some(FeatureTag::Control),
            "text" => Some(FeatureTag::Text),
            "automata" => Some(FeatureTag::Automata),
            "class" => Some(FeatureTag::Class),
            "duplex" => Some(FeatureTag::Duplex),
            "mobility" => Some(FeatureTag::Mobility),
            "description" => Some(FeatureTag::Description),
            "events" => Some(FeatureTag::Events),
            "priority" => Some(FeatureTag::Priority),
            "methods" => Some(FeatureTag::Methods),
            "schemes" => Some(FeatureTag::Schemes),
            "extensions" => Some(FeatureTag::Extensions),
            "isfocus" => Some(FeatureTag::IsFocus),
            "actor" => Some(FeatureTag::Actor),
            "language" => Some(FeatureTag::Language),
            _ => None,
        }
    }

    /// Returns true if this feature tag represents a media type capability.
    pub fn is_media_type(&self) -> bool {
        matches!(
            self,
            FeatureTag::Audio
                | FeatureTag::Video
                | FeatureTag::Application
                | FeatureTag::Data
                | FeatureTag::Control
                | FeatureTag::Text
        )
    }

    /// Returns true if this feature tag represents a list-valued capability.
    pub fn is_list_valued(&self) -> bool {
        matches!(
            self,
            FeatureTag::Events
                | FeatureTag::Priority
                | FeatureTag::Methods
                | FeatureTag::Schemes
                | FeatureTag::Extensions
        )
    }
}

impl fmt::Display for FeatureTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Feature tag value types per RFC 3840.
///
/// Feature tags can have different value types:
/// - Boolean: TRUE or FALSE
/// - Token: Named value (e.g., "fixed", "mobile")
/// - TokenList: Multiple token values (e.g., ["INVITE", "BYE"])
/// - String: Quoted string value
/// - Numeric: Integer or decimal number
#[derive(Debug, Clone, PartialEq)]
pub enum FeatureValue {
    /// Boolean value (presence of parameter = true)
    Boolean(bool),
    /// Single token value
    Token(SmolStr),
    /// List of token values
    TokenList(Vec<SmolStr>),
    /// String value
    String(SmolStr),
    /// Numeric value
    Numeric(f64),
}

impl FeatureValue {
    /// Returns true if this is a boolean true value.
    pub fn is_true(&self) -> bool {
        matches!(self, FeatureValue::Boolean(true))
    }

    /// Returns true if this is a boolean false value.
    pub fn is_false(&self) -> bool {
        matches!(self, FeatureValue::Boolean(false))
    }

    /// Returns the token value if this is a Token variant.
    pub fn as_token(&self) -> Option<&SmolStr> {
        match self {
            FeatureValue::Token(t) => Some(t),
            _ => None,
        }
    }

    /// Returns the token list if this is a TokenList variant.
    pub fn as_token_list(&self) -> Option<&[SmolStr]> {
        match self {
            FeatureValue::TokenList(list) => Some(list),
            _ => None,
        }
    }

    /// Returns the string value if this is a String variant.
    pub fn as_string(&self) -> Option<&SmolStr> {
        match self {
            FeatureValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the numeric value if this is a Numeric variant.
    pub fn as_numeric(&self) -> Option<f64> {
        match self {
            FeatureValue::Numeric(n) => Some(*n),
            _ => None,
        }
    }

    /// Converts this feature value to a Contact header parameter value.
    ///
    /// Per RFC 3840:
    /// - Boolean true: no value (parameter name only)
    /// - Boolean false: not included in Contact
    /// - Token: unquoted value
    /// - TokenList: comma-separated quoted values
    /// - String: quoted value
    /// - Numeric: unquoted numeric value
    pub fn to_param_value(&self) -> Option<SmolStr> {
        match self {
            FeatureValue::Boolean(true) => None, // No value for boolean true
            FeatureValue::Boolean(false) => None, // Don't include false values
            FeatureValue::Token(t) => Some(t.clone()),
            FeatureValue::TokenList(list) => {
                if list.is_empty() {
                    return None;
                }
                Some(SmolStr::new(&format!("\"{}\"", list.join(","))))
            }
            FeatureValue::String(s) => Some(SmolStr::new(&format!("\"{}\"", s))),
            FeatureValue::Numeric(n) => Some(SmolStr::new(&n.to_string())),
        }
    }

    /// Parses a feature value from a Contact header parameter value.
    ///
    /// The tag is needed to determine the expected value type.
    pub fn from_param_value(tag: FeatureTag, value: Option<&str>) -> Option<Self> {
        match value {
            None => {
                // No value = boolean true
                Some(FeatureValue::Boolean(true))
            }
            Some(v) => {
                let v = v.trim();

                // List-valued tags
                if tag.is_list_valued() {
                    return Some(FeatureValue::TokenList(parse_token_list(v)));
                }

                // String values (quoted)
                if v.starts_with('"') && v.ends_with('"') {
                    let unquoted = &v[1..v.len() - 1];
                    return Some(FeatureValue::String(SmolStr::new(unquoted)));
                }

                // Numeric values
                if let Ok(num) = v.parse::<f64>() {
                    return Some(FeatureValue::Numeric(num));
                }

                // Token value (unquoted)
                Some(FeatureValue::Token(SmolStr::new(v)))
            }
        }
    }
}

/// Parses a comma-separated token list, handling quoted strings.
fn parse_token_list(s: &str) -> Vec<SmolStr> {
    let s = s.trim();

    // Remove outer quotes if present
    let s = if s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    s.split(',')
        .map(|token| SmolStr::new(token.trim()))
        .filter(|token| !token.is_empty())
        .collect()
}

/// Represents a single capability (feature tag + value).
///
/// A capability is the combination of a feature tag (e.g., sip.audio) and its value
/// (e.g., true). Capabilities are conveyed as Contact header parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    /// The feature tag
    pub tag: FeatureTag,
    /// The feature value
    pub value: FeatureValue,
}

impl Capability {
    /// Creates a new capability.
    pub fn new(tag: FeatureTag, value: FeatureValue) -> Self {
        Self { tag, value }
    }

    /// Creates a boolean capability.
    pub fn boolean(tag: FeatureTag, value: bool) -> Self {
        Self::new(tag, FeatureValue::Boolean(value))
    }

    /// Creates a token capability.
    pub fn token(tag: FeatureTag, value: impl Into<SmolStr>) -> Self {
        Self::new(tag, FeatureValue::Token(value.into()))
    }

    /// Creates a token list capability.
    pub fn token_list(tag: FeatureTag, values: Vec<SmolStr>) -> Self {
        Self::new(tag, FeatureValue::TokenList(values))
    }

    /// Creates a string capability.
    pub fn string(tag: FeatureTag, value: impl Into<SmolStr>) -> Self {
        Self::new(tag, FeatureValue::String(value.into()))
    }

    /// Creates a numeric capability.
    pub fn numeric(tag: FeatureTag, value: f64) -> Self {
        Self::new(tag, FeatureValue::Numeric(value))
    }

    /// Returns the Contact header parameter name for this capability.
    pub fn param_name(&self) -> &str {
        self.tag.param_name()
    }

    /// Returns the Contact header parameter value for this capability.
    pub fn param_value(&self) -> Option<SmolStr> {
        self.value.to_param_value()
    }

    /// Converts this capability to a (name, value) pair for Contact parameters.
    pub fn to_param(&self) -> (SmolStr, Option<SmolStr>) {
        (SmolStr::new(self.param_name()), self.param_value())
    }
}

/// A set of UA capabilities (RFC 3840).
///
/// This represents the complete capability set of a user agent, typically
/// conveyed in the Contact header of REGISTER or OPTIONS messages.
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    capabilities: BTreeMap<FeatureTag, FeatureValue>,
}

impl CapabilitySet {
    /// Creates a new empty capability set.
    pub fn new() -> Self {
        Self {
            capabilities: BTreeMap::new(),
        }
    }

    /// Adds a capability to the set.
    pub fn add(&mut self, capability: Capability) {
        self.capabilities.insert(capability.tag, capability.value);
    }

    /// Adds a boolean capability.
    pub fn add_boolean(&mut self, tag: FeatureTag, value: bool) {
        self.add(Capability::boolean(tag, value));
    }

    /// Adds a token capability.
    pub fn add_token(&mut self, tag: FeatureTag, value: impl Into<SmolStr>) {
        self.add(Capability::token(tag, value));
    }

    /// Adds a token list capability.
    pub fn add_token_list(&mut self, tag: FeatureTag, values: Vec<SmolStr>) {
        self.add(Capability::token_list(tag, values));
    }

    /// Adds a string capability.
    pub fn add_string(&mut self, tag: FeatureTag, value: impl Into<SmolStr>) {
        self.add(Capability::string(tag, value));
    }

    /// Adds a numeric capability.
    pub fn add_numeric(&mut self, tag: FeatureTag, value: f64) {
        self.add(Capability::numeric(tag, value));
    }

    /// Gets a capability value by tag.
    pub fn get(&self, tag: FeatureTag) -> Option<&FeatureValue> {
        self.capabilities.get(&tag)
    }

    /// Returns true if the set contains the given capability tag.
    pub fn has(&self, tag: FeatureTag) -> bool {
        self.capabilities.contains_key(&tag)
    }

    /// Returns an iterator over all capabilities.
    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.capabilities
            .iter()
            .map(|(tag, value)| Capability::new(*tag, value.clone()))
    }

    /// Returns the number of capabilities in the set.
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Returns true if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Converts the capability set to Contact header parameters.
    ///
    /// Returns a map of parameter names to optional values suitable for
    /// inclusion in a Contact header.
    pub fn to_params(&self) -> BTreeMap<SmolStr, Option<SmolStr>> {
        let mut params = BTreeMap::new();
        for capability in self.iter() {
            let (name, value) = capability.to_param();
            // Only include boolean true values (no value) and non-false values
            if !matches!(capability.value, FeatureValue::Boolean(false)) {
                params.insert(name, value);
            }
        }
        params
    }

    /// Parses a capability set from Contact header parameters.
    pub fn from_params(params: &BTreeMap<SmolStr, Option<SmolStr>>) -> Self {
        let mut set = Self::new();

        for (name, value) in params.iter() {
            if let Some(tag) = FeatureTag::from_param_name(name.as_str()) {
                if let Some(feature_value) =
                    FeatureValue::from_param_value(tag, value.as_ref().map(|v| v.as_str()))
                {
                    set.add(Capability::new(tag, feature_value));
                }
            }
        }

        set
    }

    /// Checks if this capability set matches the given requirements.
    ///
    /// A capability set matches if:
    /// - For boolean: required capability is present and true
    /// - For token: values match
    /// - For token list: required tokens are present in the list
    /// - For string: strings match
    /// - For numeric: values match
    pub fn matches(&self, required: &CapabilitySet) -> bool {
        for req_capability in required.iter() {
            match self.get(req_capability.tag) {
                None => return false, // Required capability not present
                Some(our_value) => {
                    if !values_match(&req_capability.value, our_value) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

/// Checks if two feature values match for capability matching.
fn values_match(required: &FeatureValue, available: &FeatureValue) -> bool {
    match (required, available) {
        (FeatureValue::Boolean(req), FeatureValue::Boolean(avail)) => req == avail,
        (FeatureValue::Token(req), FeatureValue::Token(avail)) => {
            req.eq_ignore_ascii_case(avail.as_str())
        }
        (FeatureValue::TokenList(req_list), FeatureValue::TokenList(avail_list)) => {
            // All required tokens must be present in available list
            req_list.iter().all(|req_token| {
                avail_list
                    .iter()
                    .any(|avail_token| req_token.eq_ignore_ascii_case(avail_token.as_str()))
            })
        }
        (FeatureValue::String(req), FeatureValue::String(avail)) => req == avail,
        (FeatureValue::Numeric(req), FeatureValue::Numeric(avail)) => {
            (req - avail).abs() < f64::EPSILON
        }
        _ => false, // Type mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_tag_names() {
        assert_eq!(FeatureTag::Audio.as_str(), "sip.audio");
        assert_eq!(FeatureTag::Video.as_str(), "sip.video");
        assert_eq!(FeatureTag::Methods.as_str(), "sip.methods");
    }

    #[test]
    fn feature_tag_param_names() {
        assert_eq!(FeatureTag::Audio.param_name(), "audio");
        assert_eq!(FeatureTag::Video.param_name(), "video");
        assert_eq!(FeatureTag::IsFocus.param_name(), "isfocus");
    }

    #[test]
    fn feature_tag_from_param_name() {
        assert_eq!(
            FeatureTag::from_param_name("audio"),
            Some(FeatureTag::Audio)
        );
        assert_eq!(
            FeatureTag::from_param_name("VIDEO"),
            Some(FeatureTag::Video)
        );
        assert_eq!(FeatureTag::from_param_name("unknown"), None);
    }

    #[test]
    fn feature_tag_is_media_type() {
        assert!(FeatureTag::Audio.is_media_type());
        assert!(FeatureTag::Video.is_media_type());
        assert!(!FeatureTag::Methods.is_media_type());
    }

    #[test]
    fn feature_tag_is_list_valued() {
        assert!(FeatureTag::Methods.is_list_valued());
        assert!(FeatureTag::Events.is_list_valued());
        assert!(!FeatureTag::Audio.is_list_valued());
    }

    #[test]
    fn boolean_feature_value() {
        let val = FeatureValue::Boolean(true);
        assert!(val.is_true());
        assert!(!val.is_false());
        assert_eq!(val.to_param_value(), None); // Boolean true has no value
    }

    #[test]
    fn token_feature_value() {
        let val = FeatureValue::Token(SmolStr::new("fixed"));
        assert_eq!(val.as_token(), Some(&SmolStr::new("fixed")));
        assert_eq!(val.to_param_value(), Some(SmolStr::new("fixed")));
    }

    #[test]
    fn token_list_feature_value() {
        let val = FeatureValue::TokenList(vec![SmolStr::new("INVITE"), SmolStr::new("BYE")]);
        assert_eq!(val.to_param_value(), Some(SmolStr::new("\"INVITE,BYE\"")));
    }

    #[test]
    fn string_feature_value() {
        let val = FeatureValue::String(SmolStr::new("Test Device"));
        assert_eq!(val.to_param_value(), Some(SmolStr::new("\"Test Device\"")));
    }

    #[test]
    fn numeric_feature_value() {
        let val = FeatureValue::Numeric(100.5);
        assert_eq!(val.to_param_value(), Some(SmolStr::new("100.5")));
    }

    #[test]
    fn parse_feature_value_boolean() {
        let val = FeatureValue::from_param_value(FeatureTag::Audio, None);
        assert_eq!(val, Some(FeatureValue::Boolean(true)));
    }

    #[test]
    fn parse_feature_value_token() {
        let val = FeatureValue::from_param_value(FeatureTag::Mobility, Some("fixed"));
        assert_eq!(val, Some(FeatureValue::Token(SmolStr::new("fixed"))));
    }

    #[test]
    fn parse_feature_value_token_list() {
        let val = FeatureValue::from_param_value(FeatureTag::Methods, Some("\"INVITE,BYE\""));
        assert_eq!(
            val,
            Some(FeatureValue::TokenList(vec![
                SmolStr::new("INVITE"),
                SmolStr::new("BYE"),
            ]))
        );
    }

    #[test]
    fn parse_feature_value_string() {
        let val = FeatureValue::from_param_value(FeatureTag::Description, Some("\"My Phone\""));
        assert_eq!(val, Some(FeatureValue::String(SmolStr::new("My Phone"))));
    }

    #[test]
    fn capability_creation() {
        let cap = Capability::boolean(FeatureTag::Audio, true);
        assert_eq!(cap.tag, FeatureTag::Audio);
        assert!(cap.value.is_true());
    }

    #[test]
    fn capability_to_param() {
        let cap = Capability::boolean(FeatureTag::Audio, true);
        let (name, value) = cap.to_param();
        assert_eq!(name, "audio");
        assert_eq!(value, None); // Boolean true has no value
    }

    #[test]
    fn capability_set_add_and_get() {
        let mut set = CapabilitySet::new();
        set.add_boolean(FeatureTag::Audio, true);
        set.add_boolean(FeatureTag::Video, true);

        assert!(set.has(FeatureTag::Audio));
        assert!(set.has(FeatureTag::Video));
        assert!(!set.has(FeatureTag::Text));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn capability_set_to_params() {
        let mut set = CapabilitySet::new();
        set.add_boolean(FeatureTag::Audio, true);
        set.add_token(FeatureTag::Mobility, "fixed");
        set.add_token_list(
            FeatureTag::Methods,
            vec![SmolStr::new("INVITE"), SmolStr::new("BYE")],
        );

        let params = set.to_params();
        assert_eq!(params.get(&SmolStr::new("audio")), Some(&None));
        assert_eq!(
            params.get(&SmolStr::new("mobility")),
            Some(&Some(SmolStr::new("fixed")))
        );
        assert_eq!(
            params.get(&SmolStr::new("methods")),
            Some(&Some(SmolStr::new("\"INVITE,BYE\"")))
        );
    }

    #[test]
    fn capability_set_from_params() {
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("audio"), None);
        params.insert(SmolStr::new("video"), None);
        params.insert(SmolStr::new("mobility"), Some(SmolStr::new("fixed")));

        let set = CapabilitySet::from_params(&params);
        assert!(set.has(FeatureTag::Audio));
        assert!(set.has(FeatureTag::Video));
        assert!(set.has(FeatureTag::Mobility));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn capability_set_matching_boolean() {
        let mut available = CapabilitySet::new();
        available.add_boolean(FeatureTag::Audio, true);
        available.add_boolean(FeatureTag::Video, true);

        let mut required = CapabilitySet::new();
        required.add_boolean(FeatureTag::Audio, true);

        assert!(available.matches(&required));

        // Require video too
        required.add_boolean(FeatureTag::Video, true);
        assert!(available.matches(&required));

        // Require text (not available)
        required.add_boolean(FeatureTag::Text, true);
        assert!(!available.matches(&required));
    }

    #[test]
    fn capability_set_matching_token() {
        let mut available = CapabilitySet::new();
        available.add_token(FeatureTag::Mobility, "mobile");

        let mut required = CapabilitySet::new();
        required.add_token(FeatureTag::Mobility, "mobile");
        assert!(available.matches(&required));

        required = CapabilitySet::new();
        required.add_token(FeatureTag::Mobility, "fixed");
        assert!(!available.matches(&required));
    }

    #[test]
    fn capability_set_matching_token_list() {
        let mut available = CapabilitySet::new();
        available.add_token_list(
            FeatureTag::Methods,
            vec![
                SmolStr::new("INVITE"),
                SmolStr::new("BYE"),
                SmolStr::new("CANCEL"),
            ],
        );

        let mut required = CapabilitySet::new();
        required.add_token_list(FeatureTag::Methods, vec![SmolStr::new("INVITE")]);
        assert!(available.matches(&required));

        required = CapabilitySet::new();
        required.add_token_list(
            FeatureTag::Methods,
            vec![SmolStr::new("INVITE"), SmolStr::new("BYE")],
        );
        assert!(available.matches(&required));

        required = CapabilitySet::new();
        required.add_token_list(
            FeatureTag::Methods,
            vec![SmolStr::new("INVITE"), SmolStr::new("REGISTER")],
        );
        assert!(!available.matches(&required)); // REGISTER not available
    }

    #[test]
    fn parse_token_list_with_spaces() {
        let tokens = parse_token_list("\"INVITE, BYE, CANCEL\"");
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], "INVITE");
        assert_eq!(tokens[1], "BYE");
        assert_eq!(tokens[2], "CANCEL");
    }

    #[test]
    fn capability_set_iteration() {
        let mut set = CapabilitySet::new();
        set.add_boolean(FeatureTag::Audio, true);
        set.add_boolean(FeatureTag::Video, true);

        let caps: Vec<_> = set.iter().collect();
        assert_eq!(caps.len(), 2);
    }
}
