# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- **Security hardening: sip-uas crate** - CRLF injection and DoS prevention:
  * Added `UasError` enum with 7 detailed error variants
  * MAX_REASON_PHRASE_LENGTH = 128 bytes (CRLF injection prevention)
  * MAX_SIP_ETAG_LENGTH = 256 bytes (header injection prevention)
  * MAX_BODY_LENGTH = 1 MB (DoS prevention)
  * Control character validation in reason_phrase and sip_etag
  * `create_ok()` now returns `Result<Response, UasError>`
  * `create_reliable_provisional()` now returns `Result<Response, UasError>`
  * `accept_publish()` now returns `Result<Response, UasError>`
  * `create_notify_sipfrag()` now returns `Result<Request, UasError>`
  * Fixed 6 compilation errors in siphond handlers (adapt to Result API)
  * Fixed 7 test call sites to unwrap Result types
  * All 28 sip-uas tests passing

- **Refactor: clean up unused validation constants** - Remove incomplete security features:
  * Removed 7 unused constants from sip-sdp (MAX_URI_LENGTH, MAX_EMAIL_LENGTH, MAX_PHONE_LENGTH, MAX_BANDWIDTH_TYPE_LENGTH, MAX_BANDWIDTH_ENTRIES, MAX_PORT)
  * Removed 2 unused error variants (InvalidPort, InvalidBandwidth)
  * Removed unused validate_port() function
  * Removed unused test helpers (Origin::test, Connection::test)
  * Marked sip-uas future constants with #[allow(dead_code)] (prepared for integrated.rs)
  * Zero build warnings (was 13 warnings)

- **Docs: fix sip-ratelimit doctest** - Update module example after API hardening to unwrap Result from RateLimitConfig::new() before chaining methods. All doctests passing.

- **Refactor: eliminate production unwrap() calls (91 total)** - Replace panic-inducing unwrap/expect with graceful error handling across the codebase:
  * **bins/siphond handlers (16 fixes)**: bye.rs and refer.rs
    - Replaced `.expect()` with `match` for graceful error handling
    - `header.push()` failures: Log warning and skip problematic headers
    - `Request::new()` failures: Log error, clean up state, abort gracefully
    - `Response::new()` failures: Log error, don't send response
    - Zero crashes from bad requests/dialogs in B2BUA mode
  * **crates/sip-core/watcher_info.rs (4 fixes)**:
    - Replaced char iteration `.unwrap()` with `.ok_or_else()` returning XmlParseError
    - `xml_unescape()` and `extract_attribute()` handle invalid UTF-8 gracefully
    - Zero crashes from malformed XML
  * **crates/sip-auth (5 fixes)**:
    - Replaced header push `.unwrap()` with `?` operator in `DigestAuthenticator::challenge()`
    - Clean error propagation for Via, From, To, Call-ID, CSeq header copies
    - Zero crashes from malformed authentication challenges
  * **crates/sip-registrar (41 fixes)**:
    - Replaced 41 header push `.unwrap()` with `?` operator across all response builders
    - Functions: `build_error_response()`, `build_interval_too_brief()`, `handle_register_async()`, `handle_register()`
    - Zero crashes from malformed REGISTER requests
  * **Philosophy**: In a production SIP stack, one bad request must never crash the server and terminate hundreds of active calls
  * All 235+ tests passing after changes

- **Refactor: eliminate panic risk in AnswerOptions::default()** - Complete unwrap/expect elimination effort:
  * **crates/sip-core/sdp_offer_answer.rs (5 fixes)**:
    - Replaced 5 `.expect()` calls with `.ok()` + `.flatten()` pattern
    - audio_codecs: PCMU, PCMA, telephone-event (3 codecs)
    - video_codecs: H264, VP8 (2 codecs)
    - Failed codec creation results in omission from default list, never panic
  * **Result**: Zero panic risk from Default trait implementations
  * **Total production unwrap/expect eliminations: 96 fixes**
  * All 16 sdp_offer_answer tests passing

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

## [0.6.26] - sip-core - 2025-12-29

### Breaking Changes
- **BREAKING**: `AuthorizationHeader` fields are now private with accessor methods (`scheme()`, `params()`)
- **BREAKING**: `parse_params()` in `route.rs` now returns `Option<BTreeMap>` instead of `BTreeMap`

### Security
- **AuthorizationHeader (RFC 7235) Complete Rewrite**:
  * Private fields (`scheme`, `params`) - prevents validation bypass
  * MAX_SCHEME_LENGTH = 64 bytes
  * MAX_AUTH_PARAMS = 30 parameters
  * MAX_PARAM_NAME_LENGTH = 64 bytes
  * MAX_PARAM_VALUE_LENGTH = 256 bytes
  * Control character blocking in scheme and parameters
  * Token character validation per RFC 7235
  * Duplicate parameter detection via `add_param()` (rejects)
  * Parser-specific `add_param_overwrite()` for last-value-wins behavior
  * Added `AuthorizationError` enum with 6 detailed error variants
  * 22 comprehensive tests for encapsulation and validation

- **Parameter Bounds in parse_params()**:
  * MAX_PARAMS = 64 limit enforced
  * Returns `None` if parameter count exceeds limit
  * Prevents DoS attacks via unbounded parameter collections
  * Applied to Route, Service-Route, Path header parsing

### Added
- `AuthorizationHeader::new()` - Create with validation
- `AuthorizationHeader::from_raw()` - Parser constructor with full validation
- `AuthorizationHeader::add_param()` - Rejects duplicates (for application code)
- `AuthorizationHeader::add_param_overwrite()` - Allows overwrite (for parsers)
- `AuthorizationHeader::scheme()` - Public getter
- `AuthorizationHeader::params()` - Public getter
- Module-level security constants for validation limits

### Changed
- AuthorizationHeader implementation: 21 lines → 565 lines with comprehensive validation
- `parse_params()` return type changed to `Option<BTreeMap>` for bounds checking
- All AuthorizationHeader construction now validates inputs at parse time (fail-fast)

### Fixed
- Prevented validation bypass via direct field access
- Prevented DoS attacks via excessive parameters

## [0.3.1] - sip-parse - 2025-12-29

### Breaking Changes
- **BREAKING**: `split_quoted_commas()` signature changed to take `max_parts: usize` parameter
- **BREAKING**: `parse_service_route()` now returns `Result<ServiceRouteHeader, RouteError>`
- **BREAKING**: `parse_path()` now returns `Result<PathHeader, RouteError>`
- **BREAKING**: `parse_history_info()` now returns `Result<HistoryInfoHeader, HistoryInfoError>`
- **BREAKING**: `parse_geolocation_header()` signature unchanged but uses new bounded split_quoted_commas
- **BREAKING**: `parse_name_addr_list()` now returns `Option<Vec<NameAddr>>`
- **BREAKING**: Removed `parse_token_list()` - replaced with `TokenList::parse()`

### Security
- **Parameterized Collection Bounds**:
  * `split_quoted_commas()` now takes `max_parts` parameter
  * Type-specific limits: MAX_ROUTES, MAX_GEO_VALUES, MAX_HISTORY_ENTRIES, MAX_PARAMS
  * Returns `None` if bounds exceeded
  * Added unbalanced quote detection (returns `None`)
  * Prevents DoS attacks via excessive comma-separated values

- **parse_params() Bounds**:
  * MAX_PARAMS = 64 limit enforced
  * Returns `None` if parameter count exceeds limit
  * Prevents DoS via unbounded parameter collections

- **parse_name_addr_list() Bounds**:
  * MAX_ROUTES limit enforced with early exit
  * Returns `None` if limit exceeded
  * Prevents DoS via unbounded name-addr lists

- **Token Validation**:
  * RFC 3261 token character validation
  * MAX_TOKENS = 64 limit enforced
  * Validates character set: alphanum + `-` `.` `!` `%` `*` `_` `+` `` ` `` `'` `~`
  * Rejects empty tokens and invalid characters

### Added
- `TokenList::parse()` method replacing standalone `parse_token_list()` function
- Quote balance validation in `split_quoted_commas()`
- Comprehensive error messages in Result types (RouteError, HistoryInfoError, GeolocationError)

### Changed
- `parse_service_route()` returns Result for proper error handling
- `parse_path()` returns Result for proper error handling
- `parse_history_info()` returns Result for proper error handling
- `parse_allow_header()` and `parse_supported_header()` use `TokenList::parse()`
- `split_quoted_commas()` is now parameterized and more flexible
- Better error propagation instead of silent fallbacks to defaults

### Fixed
- Prevented DoS attacks via memory exhaustion
- Added parse-time validation (fail-fast design)
- Enforced RFC-compliant input validation

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
