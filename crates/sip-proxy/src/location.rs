// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Location-service abstraction for proxy target selection (RFC 3261 §16.5).
//!
//! Per §16.5, a proxy that handles requests for a domain it is
//! responsible for consults a "location service" to map the AOR (the
//! Request-URI / To URI of the incoming request) to one or more
//! target URIs to forward the request to. This module defines a
//! transport-agnostic [`LocationService`] trait so the proxy core
//! does not have to know how those bindings are stored, plus helpers
//! to apply the §16.6 step 4 q-value ordering rules.
//!
//! The trait is intentionally minimal — the proxy core needs target
//! URIs and (optionally) a Path header set per RFC 3327 to construct
//! the forwarding Route header. Storage backends (in-memory, Redis,
//! a real registrar) live in higher-layer crates and adapt themselves
//! to this trait.

use async_trait::async_trait;
use sip_core::SipUri;

/// A single registration binding the proxy may forward to.
///
/// Equivalent to `sip-registrar::Binding` from the proxy's
/// perspective: only the fields the proxy needs to make routing
/// decisions are exposed. Higher-layer code that wraps a real
/// registrar adapts its own binding type into `Target`.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// Contact URI to forward the request to.
    pub uri: SipUri,

    /// Quality value (q-parameter from the Contact header), 0.0–1.0.
    /// Per RFC 3261 §16.6 step 4, targets with higher q SHOULD be
    /// tried before targets with lower q; equal-q targets MAY be
    /// forked in parallel.
    pub q_value: f32,

    /// Optional Path header (RFC 3327) — the route set to use when
    /// forwarding to this target. The proxy MUST prepend this to the
    /// outgoing request's Route header set so the response traverses
    /// the recorded path on the way back.
    pub path: Vec<SipUri>,
}

impl Target {
    /// Construct a Target with the default q-value (1.0) and no path.
    pub fn new(uri: SipUri) -> Self {
        Self {
            uri,
            q_value: 1.0,
            path: Vec::new(),
        }
    }

    /// Builder: set the q-value (clamped to 0.0–1.0).
    pub fn with_q_value(mut self, q_value: f32) -> Self {
        self.q_value = q_value.clamp(0.0, 1.0);
        self
    }

    /// Builder: set the Path route set for this target.
    pub fn with_path(mut self, path: Vec<SipUri>) -> Self {
        self.path = path;
        self
    }
}

/// Errors returned by a [`LocationService`] implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationError {
    /// AOR is not registered. The proxy SHOULD respond 404 Not Found
    /// (RFC 3261 §16.6 — but really §10.3 for registrar; for proxies
    /// that fail to find a target, a 480 Temporarily Unavailable is
    /// also valid).
    NotFound { aor: String },

    /// AOR exists but currently has zero non-expired bindings.
    NoActiveBindings { aor: String },

    /// Backend-level failure (DB, network, etc.) — the proxy SHOULD
    /// respond 500 Server Internal Error.
    Backend(String),
}

impl std::fmt::Display for LocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { aor } => write!(f, "AOR not found: {aor}"),
            Self::NoActiveBindings { aor } => {
                write!(f, "no active bindings for AOR: {aor}")
            }
            Self::Backend(msg) => write!(f, "location service backend error: {msg}"),
        }
    }
}

impl std::error::Error for LocationError {}

/// Async storage interface the proxy uses to look up targets for an
/// AOR. Implementations adapt registrar bindings, static
/// configuration, ENUM lookups, etc.
#[async_trait]
pub trait LocationService: Send + Sync {
    /// Look up active targets for `aor`.
    ///
    /// `aor` is the canonical AOR string (typically `sip:user@host`).
    /// Returns the full set of bindings; ordering is left to the
    /// caller (use [`group_by_q_value`] to apply RFC 3261 §16.6 step
    /// 4 ordering).
    async fn lookup(&self, aor: &str) -> Result<Vec<Target>, LocationError>;
}

/// Groups targets by descending q-value into "equal-priority cohorts"
/// per RFC 3261 §16.6 step 4. The proxy SHOULD process the cohorts
/// sequentially: try every target in cohort 0 (highest q-value) in
/// parallel, then on failure of all of them, move to cohort 1, etc.
///
/// Targets with q-value `NaN` or out-of-range values are coerced via
/// [`f32::clamp`] (already enforced at construction time, but defensive).
///
/// The relative order of targets *within* a cohort is preserved from
/// the input (insertion order).
pub fn group_by_q_value(mut targets: Vec<Target>) -> Vec<Vec<Target>> {
    if targets.is_empty() {
        return Vec::new();
    }
    // Coerce any NaN q-values to the lowest priority (0.0) up front so
    // both the sort comparator and the grouping epsilon check see
    // well-ordered values. Without this, `(NaN - x).abs() > epsilon`
    // is always `false` and NaN entries collapse into the previous
    // cohort.
    for target in &mut targets {
        if target.q_value.is_nan() {
            target.q_value = 0.0;
        }
    }
    // Stable-sort by descending q.
    targets.sort_by(|a, b| {
        b.q_value
            .partial_cmp(&a.q_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Group by exact q (within an epsilon to absorb float noise).
    const EPSILON: f32 = 1e-6;
    let mut cohorts: Vec<Vec<Target>> = Vec::new();
    let mut current_q = targets[0].q_value;
    let mut current_cohort: Vec<Target> = Vec::new();
    for target in targets {
        if (target.q_value - current_q).abs() > EPSILON {
            cohorts.push(std::mem::take(&mut current_cohort));
            current_q = target.q_value;
        }
        current_cohort.push(target);
    }
    if !current_cohort.is_empty() {
        cohorts.push(current_cohort);
    }
    cohorts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(uri: &str, q: f32) -> Target {
        Target::new(SipUri::parse(uri).unwrap()).with_q_value(q)
    }

    #[test]
    fn target_clamps_q_value() {
        assert_eq!(
            Target::new(SipUri::parse("sip:a@b").unwrap())
                .with_q_value(2.5)
                .q_value,
            1.0
        );
        assert_eq!(
            Target::new(SipUri::parse("sip:a@b").unwrap())
                .with_q_value(-0.4)
                .q_value,
            0.0
        );
    }

    #[test]
    fn group_by_q_value_empty_input() {
        assert!(group_by_q_value(Vec::new()).is_empty());
    }

    #[test]
    fn group_by_q_value_single_cohort() {
        let cohorts = group_by_q_value(vec![
            target("sip:a@example.com", 1.0),
            target("sip:b@example.com", 1.0),
        ]);
        assert_eq!(cohorts.len(), 1);
        assert_eq!(cohorts[0].len(), 2);
    }

    #[test]
    fn group_by_q_value_descending_priority() {
        // Inserted out of order — must come back highest-q first.
        let cohorts = group_by_q_value(vec![
            target("sip:low@example.com", 0.2),
            target("sip:high@example.com", 0.9),
            target("sip:mid@example.com", 0.5),
        ]);
        assert_eq!(cohorts.len(), 3);
        assert_eq!(cohorts[0][0].uri.as_str(), "sip:high@example.com");
        assert_eq!(cohorts[1][0].uri.as_str(), "sip:mid@example.com");
        assert_eq!(cohorts[2][0].uri.as_str(), "sip:low@example.com");
    }

    #[test]
    fn group_by_q_value_preserves_insertion_order_within_cohort() {
        let cohorts = group_by_q_value(vec![
            target("sip:first@example.com", 0.5),
            target("sip:second@example.com", 0.5),
            target("sip:third@example.com", 0.5),
        ]);
        assert_eq!(cohorts.len(), 1);
        let uris: Vec<&str> = cohorts[0].iter().map(|t| t.uri.as_str()).collect();
        assert_eq!(
            uris,
            vec![
                "sip:first@example.com",
                "sip:second@example.com",
                "sip:third@example.com",
            ],
        );
    }

    #[test]
    fn group_by_q_value_handles_nan_as_lowest_priority() {
        let cohorts = group_by_q_value(vec![
            Target {
                uri: SipUri::parse("sip:nan@example.com").unwrap(),
                q_value: f32::NAN,
                path: Vec::new(),
            },
            target("sip:normal@example.com", 0.5),
        ]);
        // 'normal' must come ahead of 'nan'.
        assert_eq!(cohorts[0][0].uri.as_str(), "sip:normal@example.com");
        assert_eq!(
            cohorts.last().unwrap()[0].uri.as_str(),
            "sip:nan@example.com"
        );
    }
}
