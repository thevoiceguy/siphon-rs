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
- Harden Privacy header handling (reject `none` mixed with other values, enforce privacy correctly).
- Normalize Reason header protocol/params and support quoted-string unescape in parsing.
- Preserve PIDF document notes, unescape XML entities, and reject invalid basic status values in presence parsing.
- Improve P-Asserted/P-Preferred-Identity parsing for comma-separated identities and parameters.
- Harden reginfo (RFC 3680) XML generation with validation, private fields, and escaping.

## [0.6.2] - sip-core

### Breaking Changes
- **BREAKING**: `EventHeader` and `SubscriptionStateHeader` fields are now private with accessor methods
- **BREAKING**: `EventHeader::params` changed from `Vec<(SmolStr, Option<SmolStr>)>` to `BTreeMap<SmolStr, Option<SmolStr>>` for duplicate detection

### Security
- **Event Package Headers (RFC 3265)**:
  * MAX_PACKAGE_LENGTH = 64 bytes (event package names)
  * MAX_ID_LENGTH = 256 bytes (event ID parameter)
  * MAX_PARAMS = 20 (parameters per Event header)
  * MAX_PARAM_NAME_LENGTH = 64 bytes
  * MAX_PARAM_VALUE_LENGTH = 256 bytes
  * MAX_STATE_LENGTH = 32 bytes (subscription state names)
  * MAX_REASON_LENGTH = 128 bytes (termination reason)
  * Control character blocking in all string fields (prevents CRLF injection)
  * Case-insensitive duplicate parameter detection via BTreeMap
  * Parameter name validation (alphanumeric + safe symbols only)
  * Added `EventHeaderError` enum with 12 detailed error variants

### Added
- `EventHeader` accessor methods: `package()`, `id()`, `params()`, `get_param()`
- `SubscriptionStateHeader` accessor methods: `state()`, `expires()`, `retry_after()`, `reason()`
- `SubscriptionState::parse()` method (replaces `from_str()` to avoid confusion with trait)
- `FromStr` trait implementation for `SubscriptionState` (enables `.parse()` syntax)
- Case-insensitive parameter lookup via `get_param()`
- 18 comprehensive security tests covering CRLF injection, oversized inputs, duplicate params, control characters
- Module-level documentation with security guarantees and usage examples

### Changed
- `EventHeader::add_param()` now validates parameter names and values
- Parameter lookup is now case-insensitive for robustness
- Params stored in BTreeMap for automatic deduplication and sorted iteration

### Fixed
- Removed method name conflict: renamed `SubscriptionState::from_str()` to `parse()` to avoid clippy warning

## [0.2.4] - sip-parse

### Changed
- Updated `parse_subscription_state()` to use `SubscriptionState::parse()` instead of deprecated `from_str()` method
- Maintains backward compatibility with existing parser behavior

## [0.6.1] - sip-core

### Added
- Implemented actual RFC 1123 date parsing and formatting using `httpdate` crate
- Added 8 comprehensive validation tests for DateHeader (15 total tests)
- Added strict format validation for day names, months, year range (1970-2100), and time components
- Added `DateHeader::now()` - Create DateHeader from current system time
- Added `DateHeader::from_timestamp()` - Create DateHeader from SystemTime
- Added `DateHeader::is_past()` and `DateHeader::is_future()` - Date comparison methods

### Changed
- `DateHeader` fields are now private with accessor methods (`raw()`, `timestamp()`)
- `DateHeader::new()` now performs comprehensive validation and returns `Result<DateHeader, DateHeaderError>`
- Date parsing now actually works (was stub implementation)
- Strengthened format validation: validates day names (Mon-Sun), months (Jan-Dec), day numbers (01-31), year range, time format (HH:MM:SS)

### Fixed
- Restored missing copyright header
- Fixed placeholder implementations that always returned None/hardcoded values
- Fixed clippy warnings (use range contains syntax)

### Dependencies
- Added `httpdate = "1.0"` for RFC 1123 date parsing/formatting

## [0.2.3] - sip-parse

### Changed
- Updated `parse_date_header()` to use new validated `DateHeader::new()` API
- Falls back to current timestamp if date validation fails (maintains backward compatibility)
- Updated test to use `timestamp()` getter instead of direct field access

### Removed
- Removed duplicate `httpdate` dependency (now handled by sip-core)

## [0.6.0] - sip-core

### Breaking Changes
- **BREAKING**: `CpimMessage` and `CpimHeader` fields are now private with accessor methods
- **BREAKING**: `CpimMessage::new()` now returns `Result<CpimMessage, CpimError>`
- **BREAKING**: All builder methods (`with_from`, `with_to`, `with_subject`, etc.) now return `Result<Self, CpimError>`
- **BREAKING**: `CpimMessage::to_string()` now returns `Result<String, CpimError>`
- **BREAKING**: `CpimHeader::new()` now returns `Result<CpimHeader, CpimError>`
- **BREAKING**: `CpimHeader::with_param()` now returns `Result<Self, CpimError>`
- **BREAKING**: `parse_cpim()` now returns `Result<CpimMessage, CpimError>` instead of `Option<CpimMessage>`

### Security
- **CPIM Message Format (RFC 3862)**:
  * MAX_BODY_SIZE = 10 MB (message body limit)
  * MAX_PARSE_SIZE = 20 MB (input size limit)
  * MAX_HEADERS = 50 (message headers)
  * MAX_CONTENT_HEADERS = 20 (content headers)
  * MAX_PARAMS_PER_HEADER = 10 (parameters per header)
  * MAX_HEADER_NAME_LENGTH = 128 bytes
  * MAX_HEADER_VALUE_LENGTH = 1024 bytes
  * MAX_PARAM_NAME_LENGTH = 64 bytes
  * MAX_PARAM_VALUE_LENGTH = 256 bytes
  * MAX_CONTENT_TYPE_LENGTH = 256 bytes
  * Control character blocking in headers, params, and content type
  * CRLF injection prevention in content headers
  * Invalid character detection (`:`, `;`, `=`, `\`, `"` in header names)
  * Parameter validation with separate checks for names and values
  * Content-Type validation (non-empty, length-limited)
  * Added `CpimError` enum with detailed error variants

### Performance
- Added unchecked builder methods for trusted internal use:
  * `CpimMessage::new_unchecked()` - Skip validation when inputs are known valid
  * `CpimMessage::set_header_unchecked()` - Skip header validation
  * `CpimHeader::new_unchecked()` - Skip value validation
- Added `body_as_str()` method that returns `&str` without cloning (preferred over `body_as_string()`)

### Added
- Comprehensive module-level documentation with security guarantees and error handling examples
- CPIM message accessor methods: `headers()`, `content_type()`, `content_headers()`, `body()`
- CPIM header accessor methods: `value()`, `params()`
- `set_body()` method with validation
- `add_content_header()` method for mutable header addition
- `parse_cpim.rs` fuzz target for parser hardening
- 4 doc tests demonstrating usage patterns and error handling

### Fixed
- Removed redundant CRLF validation (already covered by control character check)
- Optimized header validation to avoid duplicate checks

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
