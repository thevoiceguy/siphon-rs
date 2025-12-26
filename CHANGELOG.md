# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Add async trait support for registrar/auth storage (`AsyncLocationStore`, `AsyncCredentialStore`) with adapters for sync/async interop.
- Extend `BasicRegistrar` and `DigestAuthenticator` with async handlers to enable non-blocking storage backends.
- Update memory stores to implement both sync and async traits and add Tokio/async-trait dependencies where required.
- Harden transport metrics labels with strict enums/validation and add a rate-limited tracing metrics implementation.
- Strengthen SIP digest authentication defaults and validation (SHA-256 default, size/nonce bounds, replay window configuration, and parsing hardening) with new tests.

## [0.5.0] - sip-core

### Breaking Changes
- **BREAKING**: `AcceptContact` and `RejectContact` fields are now private
- **BREAKING**: Builder methods (`with_feature`, `with_q`, `add_feature`) now return `Result<T, CallerPrefsError>`
- **BREAKING**: `score_contacts()` now returns `Result<Vec<ScoredContact>, CallerPrefsError>`
- **BREAKING**: `Capability` fields (`tag`, `value`) are now private
- **BREAKING**: All `Capability` and `CapabilitySet` constructors now return `Result<T, CapabilityError>`
- **BREAKING**: `FeatureValue::to_param_value()` and `from_param_value()` now return `Result`
- **BREAKING**: `CapabilitySet::to_params()` and `from_params()` now return `Result`
- **BREAKING**: `ContactHeader::capabilities()` now returns `Result<CapabilitySet, CapabilityError>`

### Security
- **Caller Preferences (RFC 3841)**:
  * MAX_FEATURES = 50 (features per header)
  * MAX_TOKEN_LIST_SIZE = 20 (tokens in list)
  * MAX_TOKEN_LENGTH = 64 (token length)
  * MAX_STRING_LENGTH = 256 (string values)
  * MAX_CONTACTS = 1024 (contacts to score)
  * MAX_ACCEPT_HEADERS = 32 (Accept-Contact headers)
  * MAX_REJECT_HEADERS = 32 (Reject-Contact headers)
  * Control character rejection in string feature values
  * Finite value validation for q-values and numeric features (no NaN/Infinity)
  * Token validation (alphanumeric + safe symbols only)
  * Added `CallerPrefsError` enum for validation errors
- **Capabilities (RFC 3840)**:
  * MAX_TOKEN_LENGTH = 64 (token length)
  * MAX_STRING_LENGTH = 256 (string value length)
  * MAX_TOKEN_LIST_SIZE = 20 (tokens in token list)
  * Control character rejection in tokens and strings
  * Quote character rejection in strings (prevents injection)
  * Finite value validation for numeric features (no NaN/Infinity)
  * Token validation (alphanumeric + safe symbols only)
  * Quote validation (proper opening/closing)
  * Added `CapabilityError` enum for validation errors
  * New validated constructors: `new_token()`, `new_token_list()`, `new_string()`, `new_numeric()`
  * Added `FeatureValue::validate()` method

### Performance
- Optimized token list matching from O(n²) to O(n) using HashSet (both caller_preferences and capabilities)

### Added
- Caller preferences accessor methods: `features()`, `require()`, `explicit()`, `q()`, `feature_count()`
- Capabilities accessor methods: `tag()`, `value()`
- 12 new security validation tests (4 caller_preferences + 8 capabilities)

## [0.4.0] - sip-core

### Security
- **BREAKING**: `NameAddr::new()` now returns `Result<NameAddr, NameAddrError>` for validated construction
- **BREAKING**: Made `NameAddr` fields private to enforce validation
- Added comprehensive input validation with configurable limits (display name: 256 bytes, params: 64 max, param names: 64 bytes, param values: 256 bytes)
- CRLF injection prevention: Reject `\r`, `\n`, and `\0` characters in display names and parameter values
- Parameter name validation: Only allow safe ASCII alphanumerics and specific symbols
- Case-insensitive duplicate parameter detection
- Export `NameAddrError` for error handling

### Changed
- Updated `addr_headers.rs`, `contact.rs`, `route.rs`, `service_route.rs`, `referred_by.rs` to use validated NameAddr API

## [0.2.2] - sip-parse

### Security
- Added `MAX_CONTENT_LENGTH = 64 MB` limit to prevent DoS attacks via memory exhaustion
- Integer overflow protection for Content-Length parsing (parse as u64, check against usize::MAX)
- Reject oversized Content-Length values that exceed security limit
- Enhanced strict parsing modes (`parse_request_strict`, `parse_response_strict`) with exact Content-Length matching
- Comprehensive test coverage for Content-Length edge cases (overflow, oversized, invalid formats)

### Changed
- `parse_name_addr()` now handles `Result` from `NameAddr::new()` and propagates validation errors


## [0.4.0]

### Added
- Core SIP types, headers, URIs, and message primitives
- RFC 3261 transaction layer with transport-aware timers and metrics
- UDP/TCP/TLS transport with rustls and RFC-compliant TLS shutdown
- RFC 3263 DNS resolution (NAPTR/SRV/A/AAAA)
- Dialog management, subscriptions/NOTIFY, PRACK, REFER/Replaces, and tel URI support
- Digest authentication, registrar, and UAC/UAS helpers
- Observability, metrics, and test utilities
- `siphond` multi-mode SIP testing daemon and examples
