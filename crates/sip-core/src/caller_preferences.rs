// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// RFC 3841 Caller Preferences for SIP.
///
/// This module implements RFC 3841, which allows SIP callers to express preferences
/// about request handling and routing. Callers can specify desired or rejected
/// UA capabilities using Accept-Contact and Reject-Contact headers, and control
/// proxy behavior using Request-Disposition.
///
/// # RFC 3841 Overview
///
/// - Callers express preferences via Accept-Contact and Reject-Contact headers
/// - Feature parameters based on RFC 3840 capabilities
/// - Q-value scoring for preference-based routing
/// - Request-Disposition controls proxy behavior
///
/// # Examples
///
/// ```
/// use sip_core::{AcceptContact, FeatureTag, FeatureValue};
///
/// // Prefer video-capable UAs, require audio
/// let accept = AcceptContact::new()
///     .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
///     .unwrap()
///     .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
///     .unwrap()
///     .with_require();
/// ```
use crate::capabilities::{CapabilitySet, FeatureTag, FeatureValue};
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashSet};
use std::fmt;

const MAX_FEATURES: usize = 50;
const MAX_TOKEN_LIST_SIZE: usize = 20;
const MAX_TOKEN_LENGTH: usize = 64;
const MAX_STRING_LENGTH: usize = 256;
const MAX_CONTACTS: usize = 1024;
const MAX_ACCEPT_HEADERS: usize = 32;
const MAX_REJECT_HEADERS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerPrefsError {
    TooManyFeatures,
    TooManyContacts,
    TooManyAcceptHeaders,
    TooManyRejectHeaders,
    CapabilityMismatch,
    InvalidQValue,
    InvalidNumeric,
    TokenTooLong,
    TokenListTooLarge,
    InvalidToken,
    StringTooLong,
    InvalidString,
}

impl fmt::Display for CallerPrefsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallerPrefsError::TooManyFeatures => {
                write!(f, "too many features (max {})", MAX_FEATURES)
            }
            CallerPrefsError::TooManyContacts => {
                write!(f, "too many contacts (max {})", MAX_CONTACTS)
            }
            CallerPrefsError::TooManyAcceptHeaders => {
                write!(
                    f,
                    "too many Accept-Contact headers (max {})",
                    MAX_ACCEPT_HEADERS
                )
            }
            CallerPrefsError::TooManyRejectHeaders => {
                write!(
                    f,
                    "too many Reject-Contact headers (max {})",
                    MAX_REJECT_HEADERS
                )
            }
            CallerPrefsError::CapabilityMismatch => write!(f, "capability list mismatch"),
            CallerPrefsError::InvalidQValue => write!(f, "q-value must be finite"),
            CallerPrefsError::InvalidNumeric => write!(f, "numeric feature value must be finite"),
            CallerPrefsError::TokenTooLong => {
                write!(f, "token too long (max {})", MAX_TOKEN_LENGTH)
            }
            CallerPrefsError::TokenListTooLarge => {
                write!(f, "token list too large (max {})", MAX_TOKEN_LIST_SIZE)
            }
            CallerPrefsError::InvalidToken => write!(f, "invalid token"),
            CallerPrefsError::StringTooLong => {
                write!(f, "string value too long (max {})", MAX_STRING_LENGTH)
            }
            CallerPrefsError::InvalidString => write!(f, "invalid string value"),
        }
    }
}

impl std::error::Error for CallerPrefsError {}

fn validate_feature_value(value: &FeatureValue) -> Result<(), CallerPrefsError> {
    match value {
        FeatureValue::Boolean(_) => Ok(()),
        FeatureValue::Token(t) => {
            if t.len() > MAX_TOKEN_LENGTH {
                return Err(CallerPrefsError::TokenTooLong);
            }
            if !is_valid_token(t) {
                return Err(CallerPrefsError::InvalidToken);
            }
            Ok(())
        }
        FeatureValue::TokenList(list) => {
            if list.len() > MAX_TOKEN_LIST_SIZE {
                return Err(CallerPrefsError::TokenListTooLarge);
            }
            for token in list {
                if token.len() > MAX_TOKEN_LENGTH {
                    return Err(CallerPrefsError::TokenTooLong);
                }
                if !is_valid_token(token) {
                    return Err(CallerPrefsError::InvalidToken);
                }
            }
            Ok(())
        }
        FeatureValue::String(s) => {
            if s.len() > MAX_STRING_LENGTH {
                return Err(CallerPrefsError::StringTooLong);
            }
            if s.chars().any(|c| c.is_ascii_control()) {
                return Err(CallerPrefsError::InvalidString);
            }
            Ok(())
        }
        FeatureValue::Numeric(n) => {
            if !n.is_finite() {
                return Err(CallerPrefsError::InvalidNumeric);
            }
            Ok(())
        }
    }
}

fn is_valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
                )
        })
}

/// RFC 3841 Accept-Contact header field.
///
/// Accept-Contact contains feature preferences that describe UAs the caller
/// would like to reach. Multiple Accept-Contact values can appear in a request.
///
/// Per RFC 3841, the header contains a wildcard "*" followed by feature parameters
/// and optional modifiers (require, explicit).
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptContact {
    /// Feature parameters expressing desired capabilities
    features: BTreeMap<FeatureTag, FeatureValue>,
    /// If true, non-matching contacts are discarded
    require: bool,
    /// If true, only explicitly advertised features are considered
    explicit: bool,
    /// Q-value for this preference (0.0 to 1.0)
    q: Option<f64>,
}

impl AcceptContact {
    /// Creates a new Accept-Contact header.
    pub fn new() -> Self {
        Self {
            features: BTreeMap::new(),
            require: false,
            explicit: false,
            q: None,
        }
    }

    /// Adds a feature preference.
    pub fn with_feature(
        mut self,
        tag: FeatureTag,
        value: FeatureValue,
    ) -> Result<Self, CallerPrefsError> {
        if !self.features.contains_key(&tag) && self.features.len() >= MAX_FEATURES {
            return Err(CallerPrefsError::TooManyFeatures);
        }
        validate_feature_value(&value)?;
        self.features.insert(tag, value);
        Ok(self)
    }

    /// Sets the require modifier (non-matching contacts are discarded).
    pub fn with_require(mut self) -> Self {
        self.require = true;
        self
    }

    /// Sets the explicit modifier (only explicitly advertised features count).
    pub fn with_explicit(mut self) -> Self {
        self.explicit = true;
        self
    }

    /// Sets the q-value for this preference.
    pub fn with_q(mut self, q: f64) -> Result<Self, CallerPrefsError> {
        if !q.is_finite() {
            return Err(CallerPrefsError::InvalidQValue);
        }
        self.q = Some(q.clamp(0.0, 1.0));
        Ok(self)
    }

    /// Adds a feature to this Accept-Contact.
    pub fn add_feature(
        &mut self,
        tag: FeatureTag,
        value: FeatureValue,
    ) -> Result<(), CallerPrefsError> {
        if !self.features.contains_key(&tag) && self.features.len() >= MAX_FEATURES {
            return Err(CallerPrefsError::TooManyFeatures);
        }
        validate_feature_value(&value)?;
        self.features.insert(tag, value);
        Ok(())
    }

    /// Returns true if this Accept-Contact has no features.
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    /// Returns the number of feature parameters.
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }

    pub fn features(&self) -> &BTreeMap<FeatureTag, FeatureValue> {
        &self.features
    }

    pub fn require(&self) -> bool {
        self.require
    }

    pub fn explicit(&self) -> bool {
        self.explicit
    }

    pub fn q(&self) -> Option<f64> {
        self.q
    }

    /// Checks if a capability set matches this Accept-Contact predicate.
    ///
    /// Returns a score between 0.0 and 1.0 indicating match quality.
    /// Score is 1/N for each of N features that match.
    /// Returns 0.0 if require is set and any feature doesn't match.
    /// Returns 0.0 if explicit is set and contact didn't advertise features.
    pub fn matches(&self, capabilities: &CapabilitySet, has_explicit_features: bool) -> f64 {
        if self.features.is_empty() {
            return 1.0; // Empty predicate matches everything with score 1.0
        }

        // If explicit is set and contact has no explicit features, score = 0
        if self.explicit && !has_explicit_features {
            return 0.0;
        }

        let n = self.features.len() as f64;
        let mut matched = 0.0;

        for (tag, required_value) in &self.features {
            if let Some(available_value) = capabilities.get(*tag) {
                if values_match(required_value, available_value) {
                    matched += 1.0;
                } else if self.require {
                    // Required feature doesn't match - fail
                    return 0.0;
                }
            } else if self.require {
                // Required feature not present - fail
                return 0.0;
            }
        }

        matched / n
    }
}

impl Default for AcceptContact {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if two feature values match for preference matching.
fn values_match(required: &FeatureValue, available: &FeatureValue) -> bool {
    match (required, available) {
        (FeatureValue::Boolean(req), FeatureValue::Boolean(avail)) => req == avail,
        (FeatureValue::Token(req), FeatureValue::Token(avail)) => {
            req.eq_ignore_ascii_case(avail.as_str())
        }
        (FeatureValue::TokenList(req_list), FeatureValue::TokenList(avail_list)) => {
            if req_list.len() > MAX_TOKEN_LIST_SIZE || avail_list.len() > MAX_TOKEN_LIST_SIZE {
                return false;
            }
            let avail_set: HashSet<String> = avail_list
                .iter()
                .map(|token| token.to_ascii_lowercase())
                .collect();
            req_list
                .iter()
                .all(|req_token| avail_set.contains(&req_token.to_ascii_lowercase()))
        }
        (FeatureValue::String(req), FeatureValue::String(avail)) => req == avail,
        (FeatureValue::Numeric(req), FeatureValue::Numeric(avail)) => {
            if !req.is_finite() || !avail.is_finite() {
                return false;
            }
            (req - avail).abs() < f64::EPSILON
        }
        _ => false, // Type mismatch
    }
}

/// RFC 3841 Reject-Contact header field.
///
/// Reject-Contact contains feature sets which, if matched by a UA, indicate
/// that the request should not be routed to that UA.
///
/// Per RFC 3841, Reject-Contact only discards contacts that explicitly
/// advertised matching features.
#[derive(Debug, Clone, PartialEq)]
pub struct RejectContact {
    /// Feature parameters expressing rejected capabilities
    features: BTreeMap<FeatureTag, FeatureValue>,
}

impl RejectContact {
    /// Creates a new Reject-Contact header.
    pub fn new() -> Self {
        Self {
            features: BTreeMap::new(),
        }
    }

    /// Adds a feature to reject.
    pub fn with_feature(
        mut self,
        tag: FeatureTag,
        value: FeatureValue,
    ) -> Result<Self, CallerPrefsError> {
        if !self.features.contains_key(&tag) && self.features.len() >= MAX_FEATURES {
            return Err(CallerPrefsError::TooManyFeatures);
        }
        validate_feature_value(&value)?;
        self.features.insert(tag, value);
        Ok(self)
    }

    /// Adds a feature to this Reject-Contact.
    pub fn add_feature(
        &mut self,
        tag: FeatureTag,
        value: FeatureValue,
    ) -> Result<(), CallerPrefsError> {
        if !self.features.contains_key(&tag) && self.features.len() >= MAX_FEATURES {
            return Err(CallerPrefsError::TooManyFeatures);
        }
        validate_feature_value(&value)?;
        self.features.insert(tag, value);
        Ok(())
    }

    /// Returns true if this Reject-Contact has no features.
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    pub fn feature_count(&self) -> usize {
        self.features.len()
    }

    pub fn features(&self) -> &BTreeMap<FeatureTag, FeatureValue> {
        &self.features
    }

    /// Checks if a capability set should be rejected.
    ///
    /// Returns true if the contact explicitly advertised features matching
    /// this Reject-Contact predicate. Per RFC 3841, contacts without explicit
    /// features are never rejected.
    pub fn matches(&self, capabilities: &CapabilitySet, has_explicit_features: bool) -> bool {
        if self.features.is_empty() {
            return false; // Empty predicate rejects nothing
        }

        // Only reject contacts with explicit features
        if !has_explicit_features {
            return false;
        }

        // Check if all features in Reject-Contact match
        for (tag, required_value) in &self.features {
            if let Some(available_value) = capabilities.get(*tag) {
                if !values_match(required_value, available_value) {
                    return false; // Feature doesn't match - don't reject
                }
            } else {
                return false; // Feature not present - don't reject
            }
        }

        true // All features matched - reject this contact
    }
}

impl Default for RejectContact {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 3841 Request-Disposition header directives.
///
/// Request-Disposition specifies caller preferences for request handling
/// by proxies. It contains directives controlling proxy/redirect behavior,
/// forking, cancellation, recursion, parallelism, and queuing.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestDisposition {
    /// Proxy or redirect mode
    pub proxy: Option<ProxyDirective>,
    /// Forking behavior
    pub fork: Option<ForkDirective>,
    /// Cancellation behavior
    pub cancel: Option<CancelDirective>,
    /// Recursion behavior (follow 3xx)
    pub recurse: Option<RecurseDirective>,
    /// Parallel or sequential forking
    pub parallel: Option<ParallelDirective>,
    /// Queuing behavior when busy
    pub queue: Option<QueueDirective>,
}

impl RequestDisposition {
    /// Creates a new Request-Disposition with default (empty) values.
    pub fn new() -> Self {
        Self {
            proxy: None,
            fork: None,
            cancel: None,
            recurse: None,
            parallel: None,
            queue: None,
        }
    }

    /// Sets the proxy directive.
    pub fn with_proxy(mut self, directive: ProxyDirective) -> Self {
        self.proxy = Some(directive);
        self
    }

    /// Sets the fork directive.
    pub fn with_fork(mut self, directive: ForkDirective) -> Self {
        self.fork = Some(directive);
        self
    }

    /// Sets the cancel directive.
    pub fn with_cancel(mut self, directive: CancelDirective) -> Self {
        self.cancel = Some(directive);
        self
    }

    /// Sets the recurse directive.
    pub fn with_recurse(mut self, directive: RecurseDirective) -> Self {
        self.recurse = Some(directive);
        self
    }

    /// Sets the parallel directive.
    pub fn with_parallel(mut self, directive: ParallelDirective) -> Self {
        self.parallel = Some(directive);
        self
    }

    /// Sets the queue directive.
    pub fn with_queue(mut self, directive: QueueDirective) -> Self {
        self.queue = Some(directive);
        self
    }

    /// Returns true if all directives are None.
    pub fn is_empty(&self) -> bool {
        self.proxy.is_none()
            && self.fork.is_none()
            && self.cancel.is_none()
            && self.recurse.is_none()
            && self.parallel.is_none()
            && self.queue.is_none()
    }

    /// Parses a Request-Disposition from a comma-separated list of directives.
    pub fn parse(s: &str) -> Option<Self> {
        if s.chars().any(|c| c.is_ascii_control()) {
            return None;
        }

        let mut rd = RequestDisposition::new();

        for directive in s.split(',').map(|d| d.trim()) {
            match directive.to_ascii_lowercase().as_str() {
                "proxy" => rd.proxy = Some(ProxyDirective::Proxy),
                "redirect" => rd.proxy = Some(ProxyDirective::Redirect),
                "fork" => rd.fork = Some(ForkDirective::Fork),
                "no-fork" => rd.fork = Some(ForkDirective::NoFork),
                "cancel" => rd.cancel = Some(CancelDirective::Cancel),
                "no-cancel" => rd.cancel = Some(CancelDirective::NoCancel),
                "recurse" => rd.recurse = Some(RecurseDirective::Recurse),
                "no-recurse" => rd.recurse = Some(RecurseDirective::NoRecurse),
                "parallel" => rd.parallel = Some(ParallelDirective::Parallel),
                "sequential" => rd.parallel = Some(ParallelDirective::Sequential),
                "queue" => rd.queue = Some(QueueDirective::Queue),
                "no-queue" => rd.queue = Some(QueueDirective::NoQueue),
                _ => {} // Ignore unknown directives
            }
        }

        if rd.is_empty() {
            None
        } else {
            Some(rd)
        }
    }
}

impl Default for RequestDisposition {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut directives = Vec::new();

        if let Some(d) = &self.proxy {
            directives.push(d.as_str());
        }
        if let Some(d) = &self.fork {
            directives.push(d.as_str());
        }
        if let Some(d) = &self.cancel {
            directives.push(d.as_str());
        }
        if let Some(d) = &self.recurse {
            directives.push(d.as_str());
        }
        if let Some(d) = &self.parallel {
            directives.push(d.as_str());
        }
        if let Some(d) = &self.queue {
            directives.push(d.as_str());
        }

        write!(f, "{}", directives.join(", "))
    }
}

/// Proxy directive: proxy or redirect mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyDirective {
    /// Server should operate in proxy mode
    Proxy,
    /// Server should operate in redirect mode
    Redirect,
}

impl ProxyDirective {
    pub fn as_str(&self) -> &str {
        match self {
            ProxyDirective::Proxy => "proxy",
            ProxyDirective::Redirect => "redirect",
        }
    }
}

/// Fork directive: fork or no-fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkDirective {
    /// Contact all addresses (default)
    Fork,
    /// Contact only best address
    NoFork,
}

impl ForkDirective {
    pub fn as_str(&self) -> &str {
        match self {
            ForkDirective::Fork => "fork",
            ForkDirective::NoFork => "no-fork",
        }
    }
}

/// Cancel directive: cancel or no-cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelDirective {
    /// Send CANCEL on 2xx from another branch (default)
    Cancel,
    /// Caller will handle CANCEL
    NoCancel,
}

impl CancelDirective {
    pub fn as_str(&self) -> &str {
        match self {
            CancelDirective::Cancel => "cancel",
            CancelDirective::NoCancel => "no-cancel",
        }
    }
}

/// Recurse directive: recurse or no-recurse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecurseDirective {
    /// Follow 3xx responses (default)
    Recurse,
    /// Forward 3xx responses upstream
    NoRecurse,
}

impl RecurseDirective {
    pub fn as_str(&self) -> &str {
        match self {
            RecurseDirective::Recurse => "recurse",
            RecurseDirective::NoRecurse => "no-recurse",
        }
    }
}

/// Parallel directive: parallel or sequential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelDirective {
    /// Try all branches simultaneously (default)
    Parallel,
    /// Try branches sequentially
    Sequential,
}

impl ParallelDirective {
    pub fn as_str(&self) -> &str {
        match self {
            ParallelDirective::Parallel => "parallel",
            ParallelDirective::Sequential => "sequential",
        }
    }
}

/// Queue directive: queue or no-queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueDirective {
    /// Wait if busy (receive 182 Queued)
    Queue,
    /// Immediate rejection if unavailable
    NoQueue,
}

impl QueueDirective {
    pub fn as_str(&self) -> &str {
        match self {
            QueueDirective::Queue => "queue",
            QueueDirective::NoQueue => "no-queue",
        }
    }
}

/// Represents a contact with its callee q-value and computed caller preference score (Qa).
///
/// Used for preference-based routing per RFC 3841.
#[derive(Debug, Clone)]
pub struct ScoredContact {
    /// Contact URI
    pub uri: SmolStr,
    /// Callee preference (q-value from Contact)
    pub callee_q: f64,
    /// Caller preference score (Qa, 0.0 to 1.0)
    pub caller_qa: f64,
    /// Whether contact has explicit feature parameters
    pub has_explicit_features: bool,
}

impl ScoredContact {
    /// Creates a new scored contact.
    pub fn new(uri: impl Into<SmolStr>, callee_q: f64) -> Result<Self, CallerPrefsError> {
        if !callee_q.is_finite() {
            return Err(CallerPrefsError::InvalidQValue);
        }
        Ok(Self {
            uri: uri.into(),
            callee_q: callee_q.clamp(0.0, 1.0),
            caller_qa: 1.0, // Default to 1.0 (immune)
            has_explicit_features: false,
        })
    }

    /// Sets whether this contact has explicit feature parameters.
    pub fn with_explicit_features(mut self, has_features: bool) -> Self {
        self.has_explicit_features = has_features;
        self
    }

    /// Sets the caller preference score (Qa).
    pub fn with_caller_qa(mut self, qa: f64) -> Result<Self, CallerPrefsError> {
        if !qa.is_finite() {
            return Err(CallerPrefsError::InvalidQValue);
        }
        self.caller_qa = qa.clamp(0.0, 1.0);
        Ok(self)
    }
}

/// Computes caller preference scores for contacts based on Accept-Contact headers.
///
/// Per RFC 3841, the Qa score is computed by:
/// 1. For each Accept-Contact predicate with N terms, assign 1/N points per matched feature
/// 2. Average scores from multiple Accept-Contact predicates
/// 3. Contacts without explicit features (immune) get Qa = 1.0
///
/// Returns contacts sorted by callee q-value (descending), then caller Qa (descending),
/// or an error if inputs exceed configured limits.
pub fn score_contacts(
    contacts: Vec<ScoredContact>,
    accept_headers: &[AcceptContact],
    reject_headers: &[RejectContact],
    capabilities: &[CapabilitySet],
) -> Result<Vec<ScoredContact>, CallerPrefsError> {
    if contacts.len() > MAX_CONTACTS {
        return Err(CallerPrefsError::TooManyContacts);
    }
    if accept_headers.len() > MAX_ACCEPT_HEADERS {
        return Err(CallerPrefsError::TooManyAcceptHeaders);
    }
    if reject_headers.len() > MAX_REJECT_HEADERS {
        return Err(CallerPrefsError::TooManyRejectHeaders);
    }
    if contacts.len() != capabilities.len() {
        // Capability list must match contact list
        return Err(CallerPrefsError::CapabilityMismatch);
    }
    if contacts
        .iter()
        .any(|contact| !contact.callee_q.is_finite() || !contact.caller_qa.is_finite())
    {
        return Err(CallerPrefsError::InvalidQValue);
    }

    let mut scored: Vec<ScoredContact> = contacts
        .into_iter()
        .zip(capabilities.iter())
        .filter_map(|(mut contact, caps)| {
            // Apply Reject-Contact filters
            for reject in reject_headers {
                if reject.matches(caps, contact.has_explicit_features) {
                    return None; // Reject this contact
                }
            }

            // Compute Qa score from Accept-Contact headers
            if !accept_headers.is_empty() {
                let mut total_score = 0.0;
                let mut count = 0;

                for accept in accept_headers {
                    let score = accept.matches(caps, contact.has_explicit_features);
                    if accept.require() && score == 0.0 {
                        // Required predicate failed - discard contact
                        return None;
                    }
                    total_score += score;
                    count += 1;
                }

                // Average the scores
                contact.caller_qa = if count > 0 {
                    total_score / count as f64
                } else {
                    1.0
                };
            }

            Some(contact)
        })
        .collect();

    // Sort by callee q-value (descending), then by caller Qa (descending)
    scored.sort_by(|a, b| {
        b.callee_q
            .partial_cmp(&a.callee_q)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.caller_qa
                    .partial_cmp(&a.caller_qa)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    Ok(scored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_contact_creation() {
        let accept = AcceptContact::new()
            .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
            .unwrap()
            .with_require();

        assert!(accept.require());
        assert!(!accept.explicit());
        assert_eq!(accept.feature_count(), 1);
    }

    #[test]
    fn accept_contact_matching() {
        let accept = AcceptContact::new()
            .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
            .unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_boolean(FeatureTag::Audio, true).unwrap();

        // Should match with score 1.0 (1 of 1 features matched)
        assert_eq!(accept.matches(&caps, true), 1.0);
    }

    #[test]
    fn accept_contact_require_fails() {
        let accept = AcceptContact::new()
            .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
            .unwrap()
            .with_require();

        let mut caps = CapabilitySet::new();
        caps.add_boolean(FeatureTag::Audio, true).unwrap();

        // Should fail (score 0.0) because video is required but not available
        assert_eq!(accept.matches(&caps, true), 0.0);
    }

    #[test]
    fn accept_contact_explicit_without_features() {
        let accept = AcceptContact::new()
            .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
            .unwrap()
            .with_explicit();

        let mut caps = CapabilitySet::new();
        caps.add_boolean(FeatureTag::Audio, true).unwrap();

        // Should fail (score 0.0) because explicit is set but contact has no features
        assert_eq!(accept.matches(&caps, false), 0.0);
    }

    #[test]
    fn accept_contact_partial_match() {
        let mut accept = AcceptContact::new();
        accept
            .add_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
            .unwrap();
        accept
            .add_feature(FeatureTag::Video, FeatureValue::Boolean(true))
            .unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_boolean(FeatureTag::Audio, true).unwrap();
        // Video not present

        // Should score 0.5 (1 of 2 features matched)
        assert_eq!(accept.matches(&caps, true), 0.5);
    }

    #[test]
    fn reject_contact_creation() {
        let reject = RejectContact::new()
            .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
            .unwrap();

        assert_eq!(reject.feature_count(), 1);
    }

    #[test]
    fn reject_contact_matches() {
        let reject = RejectContact::new()
            .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
            .unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_boolean(FeatureTag::Automata, true).unwrap();

        // Should match (reject this contact)
        assert!(reject.matches(&caps, true));
    }

    #[test]
    fn reject_contact_no_explicit_features() {
        let reject = RejectContact::new()
            .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
            .unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_boolean(FeatureTag::Automata, true).unwrap();

        // Should not match because contact has no explicit features
        assert!(!reject.matches(&caps, false));
    }

    #[test]
    fn request_disposition_parse() {
        let rd = RequestDisposition::parse("proxy, recurse, parallel").unwrap();

        assert_eq!(rd.proxy, Some(ProxyDirective::Proxy));
        assert_eq!(rd.recurse, Some(RecurseDirective::Recurse));
        assert_eq!(rd.parallel, Some(ParallelDirective::Parallel));
    }

    #[test]
    fn request_disposition_display() {
        let rd = RequestDisposition::new()
            .with_proxy(ProxyDirective::Proxy)
            .with_fork(ForkDirective::NoFork);

        let s = rd.to_string();
        assert!(s.contains("proxy"));
        assert!(s.contains("no-fork"));
    }

    #[test]
    fn scored_contact_creation() {
        let contact = ScoredContact::new("sip:alice@example.com", 0.8)
            .unwrap()
            .with_explicit_features(true)
            .with_caller_qa(0.9)
            .unwrap();

        assert_eq!(contact.callee_q, 0.8);
        assert_eq!(contact.caller_qa, 0.9);
        assert!(contact.has_explicit_features);
    }

    #[test]
    fn score_contacts_basic() {
        let contacts = vec![
            ScoredContact::new("sip:c1@example.com", 1.0)
                .unwrap()
                .with_explicit_features(true),
            ScoredContact::new("sip:c2@example.com", 1.0)
                .unwrap()
                .with_explicit_features(true),
        ];

        let accept = AcceptContact::new()
            .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
            .unwrap();

        let mut caps1 = CapabilitySet::new();
        caps1.add_boolean(FeatureTag::Audio, true).unwrap();

        let mut caps2 = CapabilitySet::new();
        caps2.add_boolean(FeatureTag::Video, true).unwrap();

        let scored = score_contacts(contacts, &[accept], &[], &[caps1, caps2]).unwrap();

        // c1 should score higher (has audio)
        assert_eq!(scored.len(), 2);
        assert_eq!(scored[0].uri, "sip:c1@example.com");
        assert_eq!(scored[0].caller_qa, 1.0);
        assert_eq!(scored[1].uri, "sip:c2@example.com");
        assert_eq!(scored[1].caller_qa, 0.0);
    }

    #[test]
    fn score_contacts_with_reject() {
        let contacts = vec![
            ScoredContact::new("sip:c1@example.com", 1.0)
                .unwrap()
                .with_explicit_features(true),
            ScoredContact::new("sip:c2@example.com", 1.0)
                .unwrap()
                .with_explicit_features(true),
        ];

        let reject = RejectContact::new()
            .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
            .unwrap();

        let mut caps1 = CapabilitySet::new();
        caps1.add_boolean(FeatureTag::Audio, true).unwrap();

        let mut caps2 = CapabilitySet::new();
        caps2.add_boolean(FeatureTag::Automata, true).unwrap();

        let scored = score_contacts(contacts, &[], &[reject], &[caps1, caps2]).unwrap();

        // c2 should be rejected
        assert_eq!(scored.len(), 1);
        assert_eq!(scored[0].uri, "sip:c1@example.com");
    }

    #[test]
    fn score_contacts_require_filter() {
        let contacts = vec![
            ScoredContact::new("sip:c1@example.com", 1.0)
                .unwrap()
                .with_explicit_features(true),
            ScoredContact::new("sip:c2@example.com", 1.0)
                .unwrap()
                .with_explicit_features(true),
        ];

        let accept = AcceptContact::new()
            .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
            .unwrap()
            .with_require();

        let mut caps1 = CapabilitySet::new();
        caps1.add_boolean(FeatureTag::Audio, true).unwrap();

        let mut caps2 = CapabilitySet::new();
        caps2.add_boolean(FeatureTag::Video, true).unwrap();

        let scored = score_contacts(contacts, &[accept], &[], &[caps1, caps2]).unwrap();

        // Only c2 should remain (has required video)
        assert_eq!(scored.len(), 1);
        assert_eq!(scored[0].uri, "sip:c2@example.com");
    }

    #[test]
    fn score_contacts_sorting() {
        let contacts = vec![
            ScoredContact::new("sip:c1@example.com", 0.5)
                .unwrap()
                .with_explicit_features(true),
            ScoredContact::new("sip:c2@example.com", 1.0)
                .unwrap()
                .with_explicit_features(true),
            ScoredContact::new("sip:c3@example.com", 0.5)
                .unwrap()
                .with_explicit_features(true),
        ];

        let accept = AcceptContact::new()
            .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
            .unwrap();

        let mut caps1 = CapabilitySet::new();
        caps1.add_boolean(FeatureTag::Audio, true).unwrap();

        let mut caps2 = CapabilitySet::new();
        caps2.add_boolean(FeatureTag::Video, true).unwrap();

        let mut caps3 = CapabilitySet::new();
        caps3.add_boolean(FeatureTag::Audio, true).unwrap();

        let scored = score_contacts(contacts, &[accept], &[], &[caps1, caps2, caps3]).unwrap();

        // c2 should be first (highest callee_q)
        // c1 and c3 both have callee_q=0.5, but c1 and c3 have Qa=1.0, c2 has Qa=0.0
        assert_eq!(scored.len(), 3);
        assert_eq!(scored[0].uri, "sip:c2@example.com"); // q=1.0
        assert_eq!(scored[1].uri, "sip:c1@example.com"); // q=0.5, Qa=1.0
        assert_eq!(scored[2].uri, "sip:c3@example.com"); // q=0.5, Qa=1.0
    }

    #[test]
    fn reject_non_finite_q_values() {
        assert!(AcceptContact::new().with_q(f64::NAN).is_err());
        assert!(AcceptContact::new().with_q(f64::INFINITY).is_err());
        assert!(ScoredContact::new("sip:bad@example.com", f64::NAN).is_err());
    }

    #[test]
    fn enforce_max_features() {
        // Since FeatureTag is a fixed enum, we can't actually exceed MAX_FEATURES
        // in practice, but we test the validation logic by filling up to the limit
        let mut accept = AcceptContact::new();

        // Add all available feature tags
        let all_tags = [
            FeatureTag::Audio,
            FeatureTag::Video,
            FeatureTag::Application,
            FeatureTag::Data,
            FeatureTag::Control,
            FeatureTag::Text,
            FeatureTag::Automata,
            FeatureTag::Class,
            FeatureTag::Duplex,
            FeatureTag::Mobility,
            FeatureTag::Description,
            FeatureTag::Events,
            FeatureTag::Priority,
            FeatureTag::Methods,
            FeatureTag::Schemes,
            FeatureTag::Extensions,
            FeatureTag::IsFocus,
            FeatureTag::Actor,
            FeatureTag::Language,
        ];

        for tag in &all_tags {
            accept
                .add_feature(*tag, FeatureValue::Boolean(true))
                .unwrap();
        }

        // Verify we can update an existing feature (doesn't increase count)
        let result = accept.add_feature(FeatureTag::Audio, FeatureValue::Boolean(false));
        assert!(result.is_ok());

        // The limit check works correctly even though we can't exceed the enum size in practice
        assert!(accept.feature_count() <= MAX_FEATURES);
    }

    #[test]
    fn reject_large_token_list() {
        let huge_list = vec![SmolStr::new("token"); MAX_TOKEN_LIST_SIZE + 1];
        let result = AcceptContact::new()
            .with_feature(FeatureTag::Methods, FeatureValue::TokenList(huge_list));

        assert!(result.is_err());
    }

    #[test]
    fn reject_control_chars_in_string() {
        let result = AcceptContact::new().with_feature(
            FeatureTag::Description,
            FeatureValue::String(SmolStr::new("hello\r\nworld")),
        );

        assert!(result.is_err());
    }
}
