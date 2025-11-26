# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SIPHON-RS is a modern Rust reimplementation of a production-grade SIP (Session Initiation Protocol) stack implementing RFC 3261 and related specifications. The project uses a layered architecture with separate crates for parsing, transport, transactions, dialogs, and application-level services.

## Build and Test Commands

```bash
# Build all workspace crates
cargo build

# Build with all features (includes TLS)
cargo build --all-features

# Run the siphond daemon (default: minimal mode - OPTIONS only)
cargo run -p siphond

# Run siphond as full UAS (all SIP methods)
cargo run -p siphond -- --mode full-uas

# Run siphond as registrar with authentication
cargo run -p siphond -- --mode registrar --auth --auth-realm example.com

# Run siphond as call server
cargo run -p siphond -- --mode call-server --sdp-profile audio-only

# Run siphond as proxy (forwards calls to registered users)
cargo run -p siphond -- --mode proxy --local-uri sip:proxy@192.168.1.81

# Run siphond as B2BUA (bridges calls between registered users)
cargo run -p siphond -- --mode b2bua --local-uri sip:b2bua@192.168.1.81 --tcp-bind 0.0.0.0:5060

# Run siphond with TLS support
cargo run -p siphond -- --mode full-uas --sips-bind 0.0.0.0:5061 --tls-cert cert.pem --tls-key key.pem

# Run all tests
cargo test --all

# Run tests for a specific crate
cargo test -p sip-parse

# Run a single test by name
cargo test test_name

# Run tests with output visible
cargo test -- --nocapture

# Lint with clippy
cargo clippy --all

# Format code
cargo fmt --all

# Check without building
cargo check --all
```

## Fuzzing

The project includes fuzz targets for parser hardening:

```bash
# Install cargo-fuzz (once)
cargo install cargo-fuzz

# Run a specific fuzz target
cd fuzz
cargo fuzz run parse_request

# List available fuzz targets
cargo fuzz list
```

Available fuzz targets: `parse_request`, `parse_response`, `parse_headers`

## Architecture Overview

### Layered Design

```
+-----------------------------------------------------------+
| Applications / TUs: UAC, UAS, Proxy, Registrar, B2BUA     |
+----------------------------+------------------------------+
| Dialog Layer               |  Subscription/Notify Layer   |
+----------------------------+------------------------------+
|     Transaction Layer (Client/Server state machines)      |
+-----------------------------------------------------------+
|     Core: Parsing, Message model, Routing, Timers         |
+-----------------------------------------------------------+
|     Transport: UDP/TCP/TLS + DNS (NAPTR/SRV/A/AAAA)       |
+-----------------------------------------------------------+
```

### Workspace Structure

The project is organized as a Cargo workspace with the following crates:

**Core Layer:**
- `sip-core` - Shared types: `Method`, `SipUri`, `TelUri`, `Uri`, `Request`, `Response`, `Headers`, `SipMessage`, and typed header structures. Includes RFC 3966 tel URI support.
- `sip-parse` - nom-based parser for SIP messages; handles request/response lines, headers, and message serialization. Supports both SIP and tel URIs.

**Transport Layer:**
- `sip-transport` - Async transport manager for UDP, TCP, TLS (rustls). Includes connection pooling and framing
- `sip-dns` - RFC 3263 compliant DNS resolution (NAPTR/SRV/A/AAAA) with priority/weight handling and failover

**Transaction Layer:**
- `sip-transaction` - Implements RFC 3261 client/server transaction state machines with transport-aware timers (T1, T2, T4, A-K). Manages retransmissions and transaction lifecycle
  - Key types: `TransactionManager`, `TransactionKey`, `ClientTransactionUser`, `TransportDispatcher`
  - `TransportAwareTimers`: RFC 3261 §17.1.2.2 compliant timer adjustments (zero wait times for TCP/TLS)
  - `TransactionMetrics`: Performance monitoring with duration tracking, timer statistics, and outcome analysis
  - Handles branch ID generation (`z9hG4bK` magic cookie per RFC 3261)

**Service Layer:**
- `sip-dialog` - RFC 3261 §12 compliant dialog state management with Early/Confirmed/Terminated states, route sets, target refresh, CSeq tracking, and session timers. Also includes RFC 3265 subscription management for event notifications and RFC 3262 RSeq management for reliable provisionals.
- `sip-auth` - RFC 7616/7617 compliant Digest authentication with MD5/SHA-256/SHA-512, qop (auth/auth-int), nonce management, and Proxy-Authenticate support
- `sip-registrar` - RFC 3261 §10 compliant REGISTER handling with location service, binding management, wildcard deregistration, q-value support, and expiry tracking
- `sip-proxy` - Proxy helper primitives (Via header insertion, Record-Route, Max-Forwards checking, Request-URI modification) for building stateful/stateless proxies
- `sip-uas` - UAS (User Agent Server) helpers for receiving and responding to requests with dialog management, including REFER/call transfer support
- `sip-uac` - UAC (User Agent Client) helpers for sending requests with authentication, dialog management, and call transfer capabilities

**Extension Layer:**
- `sip-sdp` - SDP (Session Description Protocol) model (placeholder)
- `sip-observe` - Observability and metrics (tracing integration)
- `sip-testkit` - Integration test harness and sipp bindings

**Binaries:**
- `siphond` - Multi-mode SIP testing daemon (Swiss Army knife for SIP testing):
  - **Minimal Mode**: OPTIONS responder only
  - **Full UAS Mode**: Complete SIP server (INVITE, REGISTER, SUBSCRIBE, REFER, PRACK)
  - **Registrar Mode**: Registration server with authentication and location service
  - **Proxy Mode**: Stateful proxy that forwards INVITE requests to registered users (RFC 3261 §16)
  - **B2BUA Mode**: Back-to-Back User Agent that bridges calls between registered users with response relay
  - **Call Server Mode**: INVITE/BYE handling without registration
  - **Subscription Server Mode**: SUBSCRIBE/NOTIFY for event packages
  - Supports UDP, TCP, and TLS transports
  - Configurable authentication, SDP profiles, and auto-accept behavior
  - See `bins/siphond/README.md` for comprehensive documentation

## Key Concepts

### Message Model

Messages are represented as immutable types:
- `SipMessage` - enum of `Request` or `Response`
- `Request` - contains `RequestLine`, `Headers`, and body `Bytes`
- `Response` - contains `StatusLine`, `Headers`, and body `Bytes`
- `Headers` - map-like structure supporting multiple values per header name

### Transaction Layer

The transaction layer implements RFC 3261 state machines with transport-aware timer optimizations:
- Transactions are keyed by `TransactionKey` (branch parameter, method, is_server flag)
- Branch IDs follow RFC 3261 magic cookie format: `z9hG4bK{random}`
- Timer values (T1, T2, T4) drive state transitions and retransmissions
- `TransactionManager` handles transaction lifecycle and dispatching
- **Transport-Aware Timers**: Automatically adjusts timer values based on transport reliability

State machines:
- Client INVITE: `Calling → Proceeding → Completed → Terminated`
- Server INVITE: `Proceeding → Completed → Confirmed → Terminated`
- Non-INVITE transactions have simpler state machines

#### Transport-Aware Timer Behavior

Per RFC 3261 §17.1.2.2, timer values are adjusted based on transport type:

**UDP (Unreliable Transport):**
- Retransmission timers (A, E, G): Active with exponential backoff
- Wait timers (D, I, J, K): Full duration (5-32 seconds)
- Example: Timer K = 5 seconds (wait for response retransmissions)

**TCP/TLS (Reliable Transport):**
- Retransmission timers (A, E, G): Zero (no retransmissions needed)
- Wait timers (D, I, J, K): Zero (immediate completion)
- Example: Timer K = 0 seconds (instant transaction termination)

**Performance Benefits:**
- TCP/TLS transactions complete **5-37 seconds faster** than UDP
- Reduced memory usage (no timer tracking for wait timers)
- Better scalability (transactions terminate immediately after receiving final response)

**Implementation:**
- FSMs use `TransportAwareTimers` instead of hardcoded durations
- Transport type automatically detected from `TransportContext`
- Timeout timers (B, F, H) remain the same across all transports (64*T1 = 32 seconds)

### Dialog Layer

The dialog layer implements RFC 3261 §12 dialog management:
- Dialogs are identified by Call-ID, local tag, and remote tag (`DialogId`)
- Dialog states: `Early` (1xx response), `Confirmed` (2xx response), `Terminated` (BYE/timeout)
- Separate constructors for UAC and UAS perspectives (`Dialog::new_uac()`, `Dialog::new_uas()`)
- Tracks remote target (Contact URI) and route set (Record-Route headers)
- Manages local and remote CSeq numbers for dialog sequencing
- Supports target refresh from re-INVITE/UPDATE responses
- Includes session timer support (RFC 4028)
- `DialogManager` provides concurrent dialog tracking with DashMap

Key features:
- Dialog matching from incoming requests via Call-ID and tags
- Route set reversal per RFC 3261 for proper request routing
- CSeq validation to detect out-of-order requests
- Cleanup of terminated dialogs

### Subscription and Event Notification Layer (RFC 3265)

The subscription layer manages event subscriptions for SUBSCRIBE/NOTIFY:
- **SubscriptionId**: Unique identifier composed of Call-ID, From tag, To tag, and Event package
- **Subscription**: Tracks subscription state (Active, Pending, Terminated), expires, contact, and CSeq
- **SubscriptionManager**: Thread-safe concurrent subscription tracking with DashMap
- Separate constructors for notifier and subscriber perspectives
- Supports event packages like "refer", "presence", "message-summary"

Key components:
- `SubscriptionId::from_request_response()` - Creates subscription ID from SUBSCRIBE request and response
- `Subscription::new_notifier()` - Creates subscription from notifier (UAS) perspective
- `Subscription::new_subscriber()` - Creates subscription from subscriber (UAC) perspective
- Automatic expiry management and state tracking

### Call Transfer Support (RFC 3515, RFC 3891)

The stack provides complete call transfer capabilities:

**Blind Transfer (RFC 3515):**
- Transferor sends REFER to transferee with Refer-To header
- Creates implicit subscription to "refer" event
- Transferee accepts with 202 Accepted
- Transferee sends NOTIFY messages with sipfrag body reporting progress
- Use case: Direct transfer without consulting target first

**Attended Transfer (RFC 3515 + RFC 3891):**
- Transferor establishes consultation call with transfer target
- Transferor sends REFER with Replaces header (RFC 3891)
- Replaces header identifies the dialog to be replaced
- Transfer target replaces consultation call with new call to transferee
- More reliable as target availability is confirmed

Key features:
- `create_refer()` - Blind transfer REFER generation
- `create_refer_with_replaces()` - Attended transfer with Replaces header
- `accept_refer()` / `reject_refer()` - Handle incoming REFER requests
- `create_notify_sipfrag()` - Generate NOTIFY with message/sipfrag body
- URL-encoded Replaces parameters for compatibility
- Complete progress notification flow

### PRACK Support (RFC 3262)

The stack provides complete support for reliable provisional responses:

**RSeq Management:**
- `RSeqManager` - Tracks RSeq sequence numbers per dialog
- Each dialog has its own RSeq space starting at 1
- Automatic incrementing for each reliable provisional
- Thread-safe concurrent RSeq tracking with DashMap

**UAC (Caller) Side:**
- `create_prack()` - Generate PRACK request from reliable provisional
- Extracts RSeq from 1xx response with RSeq header
- Creates RAck header (RSeq CSeq-number Method)
- Handles early dialog establishment from reliable provisionals

**UAS (Callee) Side:**
- `create_reliable_provisional()` - Generate 180/183 with RSeq header
- Automatic RSeq sequencing via RSeqManager
- Adds Require: 100rel header
- `handle_prack()` - Process incoming PRACK requests
- Validates RAck header format

**Use Cases:**
- Early media with SDP in 183 Session Progress
- QoS preconditions (IMS networks)
- Reliable progress indication
- Multi-stage call setup
- Gateway scenarios requiring guaranteed delivery

**Protocol Features:**
- RSeq sequence space separate from CSeq
- Reliable provisional retransmission until PRACK received
- Duplicate detection via RSeq numbers
- 100 Trying never sent reliably per RFC 3262 §3

### tel URI Support (RFC 3966)

The stack provides complete support for telephone number URIs:

**URI Types:**
- `SipUri` - SIP and SIPS URIs per RFC 3261 (e.g., sip:user@example.com)
- `TelUri` - Telephone number URIs per RFC 3966 (e.g., tel:+1-555-123-4567)
- `Uri` - Unified enum wrapper supporting both SIP and tel URIs

**Global Numbers (E.164):**
- Start with '+' followed by country code
- Example: tel:+1-555-123-4567 (US), tel:+44-20-7946-0958 (UK)
- Visual separators (-, ., space, parentheses) automatically normalized
- MUST NOT include phone-context parameter
- Normalized for dialing and comparison (e.g., +1-555-123-4567 → +15551234567)

**Local Numbers:**
- Do not start with '+'
- Example: tel:5551234;phone-context=example.com
- MUST include phone-context parameter (domain or global number)
- Used for enterprise extensions and local dialing plans

**Parser Integration:**
- `Uri::parse()` automatically detects SIP or tel URI scheme
- `parse_request()` in sip-parse supports tel URIs in Request-URI
- Request-URI changed from `SipUri` to `Uri` for full tel support
- Backward compatible via `impl Into<Uri>` on RequestLine constructor

**Common Parameters:**
- `ext` - Extension number (e.g., tel:+15551234567;ext=1234)
- `isub` - ISDN subaddress
- `phone-context` - Required for local numbers
- `postd` - Post-dial sequence for tone dialing

**Use Cases:**
- PSTN gateway routing (Request-URI: sip:gateway, To: tel:+15551234567)
- Mobile networks (IMS) with native tel URI routing
- Enterprise PBX with local extensions
- Click-to-call web applications
- Interoperability between SIP and PSTN addressing

**Builder Pattern:**
```rust
// Global tel URI
let tel = TelUri::new("+15551234567", true);

// Local tel URI with phone-context
let local = TelUri::new("5551234", false)
    .with_phone_context("example.com");

// With extension
let with_ext = TelUri::new("+15551234567", true)
    .with_parameter("ext", Some("1234"));
```

**Validation:**
- Local numbers without phone-context are rejected
- Global numbers with phone-context are rejected
- Visual separators normalized per RFC 3966 §5.1.1
- Duplicate detection via normalized number comparison

### Authentication Layer

The authentication layer implements RFC 7616/7617 Digest authentication:
- **Algorithms**: MD5, SHA-256, SHA-512 hash algorithms
- **Quality of Protection (qop)**: `auth` (authentication only) and `auth-int` (authentication with integrity)
- **Nonce Management**: NonceManager with automatic expiry tracking and cleanup
- **Challenge Generation**: WWW-Authenticate (401) and Proxy-Authenticate (407) header generation
- **Credential Verification**: Server-side validation with pluggable CredentialStore trait
- **Client Support**: DigestClient for generating Authorization headers from challenges
- **HA1/HA2 Computation**: RFC-compliant hash computation with body integrity support

Key components:
- `DigestAuthenticator<S>` - Server-side authenticator with configurable algorithm, qop, and nonce TTL
- `DigestClient` - Client-side credential generator with nonce count (nc) tracking
- `NonceManager` - Concurrent nonce tracking with DashMap and automatic cleanup
- `MemoryCredentialStore` - In-memory credential storage for testing/development
- `CredentialStore` trait - Pluggable credential backend for production use

### Registrar Layer

The registrar layer implements RFC 3261 §10 REGISTER request handling:
- **Binding Storage**: LocationStore trait with MemoryLocationStore implementation
- **AOR Management**: Address-of-Record (To URI) to Contact URI mapping
- **Expiry Handling**: Configurable min/max/default expiration with automatic cleanup
- **Multi-Contact Support**: Multiple device registrations per AOR
- **Wildcard Deregistration**: Contact: * removes all bindings for an AOR
- **Q-value Support**: Quality parameter (0.0-1.0) for contact prioritization
- **Metadata Tracking**: Call-ID, CSeq, and binding timestamps
- **Authentication Integration**: Optional Digest authentication enforcement

Key components:
- `Binding` - Registration record with AOR, Contact, expiry, Call-ID, CSeq, and q-value
- `LocationStore` trait - Pluggable storage backend with upsert/remove/lookup operations
- `MemoryLocationStore` - Thread-safe in-memory storage with DashMap
- `BasicRegistrar<S, A>` - Registrar with configurable storage and authenticator
- Builder pattern for expiry configuration (default: 3600s, min: 60s, max: 86400s)

Features:
- Contact parameter parsing (expires, q)
- Contact URI extraction (with/without angle brackets)
- Automatic expiry clamping between min and max
- Expired binding cleanup
- Response includes actual granted expiry values

### UAC/UAS Helpers

The UAC and UAS helper layers provide high-level APIs for building SIP applications:

**UAC (User Agent Client) - `sip-uac`:**
- `UserAgentClient` - Helper for sending SIP requests
- Request builders: `create_register()`, `create_invite()`, `create_ack()`, `create_bye()`
- Subscription/event methods: `create_subscribe()`, `create_notify()`, `process_subscribe_response()`
- Call transfer methods: `create_refer()`, `create_refer_with_replaces()`
- PRACK methods: `create_prack()` for acknowledging reliable provisionals
- Authentication handling: `create_authenticated_request()` automatically handles 401/407 challenges
- Dialog integration: `process_invite_response()` creates and stores dialogs from INVITE responses
- Subscription integration: `SubscriptionManager` for tracking event subscriptions
- Tag/branch/Call-ID generation helpers
- Credential management via `DigestClient` integration

Features:
- Automatic CSeq incrementing for authenticated retries
- Display name support for From headers
- Optional SDP body for INVITE requests and ACK
- Full RFC 3264 Offer/Answer support (early and late offer)
  - Early offer: INVITE with SDP, 200 OK with answer, empty ACK
  - Late offer: INVITE without SDP, 200 OK with offer, ACK with answer
- Dialog-aware BYE generation using remote target and route set
- Complete call transfer support (blind and attended transfers)
- SUBSCRIBE/NOTIFY for event subscriptions
- NOTIFY with message/sipfrag body for REFER progress reporting
- PRACK for acknowledging reliable provisional responses (RFC 3262)

**UAS (User Agent Server) - `sip-uas`:**
- `UserAgentServer` - Helper for receiving and responding to SIP requests
- Response builders: `create_trying()`, `create_ringing()`, `create_ok()`, `create_busy()`, `create_decline()`
- Dialog management: `accept_invite()` creates dialog and 200 OK response
- Subscription management: `accept_subscribe()` handles SUBSCRIBE requests
- Call transfer handlers: `accept_refer()`, `reject_refer()` for REFER requests
- Event notifications: `create_notify_sipfrag()` generates progress notifications
- PRACK handlers: `create_reliable_provisional()`, `handle_prack()` for reliable 1xx responses
- Authentication: `create_unauthorized()` generates WWW-Authenticate challenges
- Request handlers: `handle_bye()`, `handle_cancel()`
- Subscription integration: `SubscriptionManager` for tracking event subscriptions
- RSeq management: `RSeqManager` for reliable provisional sequencing
- Automatic To-tag generation for responses

Features:
- Automatic header copying (Via, From, Call-ID, CSeq) from request to response
- Optional SDP body support for 200 OK responses
- Dialog verification for BYE requests
- REFER request handling with Refer-To extraction
- NOTIFY with message/sipfrag body for transfer progress (RFC 3515)
- Reliable provisional responses with RSeq/PRACK (RFC 3262)
- Subscription state management (active/pending/terminated)
- Authentication integration with `Authenticator` trait
- Contact header management in responses

### Performance Metrics

The transaction layer provides comprehensive performance monitoring and analytics:

**TransactionMetrics API:**
- `TransactionMetrics` - Thread-safe metrics collector using `parking_lot::RwLock`
- Automatic collection via `TransactionManager` (no instrumentation needed)
- Manual collection for custom scenarios

**Metrics Collected:**
- **Transaction Durations**: By transport type (UDP/TCP/TLS) and method (INVITE, REGISTER, etc.)
- **Timer Statistics**: Fire counts for all transaction timers (A-K)
- **Transaction Outcomes**: Completed, Timeout, TransportError, Cancelled
- **Aggregate Statistics**: Min/max/average durations, total counts

**Usage:**
```rust
// Automatic collection via TransactionManager
let manager = TransactionManager::new(dispatcher);
// ... transactions occur automatically ...

// Query metrics
let snapshot = manager.metrics().snapshot();
println!("Total transactions: {}", snapshot.total_transactions);

// Get average by transport
if let Some(tcp_stats) = snapshot.by_transport.get(&TransportType::Tcp) {
    println!("TCP avg: {:?}", tcp_stats.avg_duration);
}
```

**Performance Insights:**
- Quantify TCP vs UDP performance benefits (typically 20-30x faster)
- Identify slow transactions or timeout patterns
- Track timer behavior and retransmission counts
- Monitor success rates and failure modes

**Example Output:**
```
Transport Performance Comparison:
├─ UDP: avg 5.45s, min 5s, max 5.9s (10 transactions)
└─ TCP: avg 195ms, min 150ms, max 240ms (10 transactions)
   → TCP is 27.9x faster than UDP
```

**Examples:**
- `cargo run --example metrics_demo` - Interactive metrics demonstration
- `cargo run --example timer_behavior` - Transport-aware timer behavior

### Transport Layer

Transport is abstracted through traits:
- UDP: stateless datagram transport
- TCP: connection pool with automatic framing (CRLF-delimited messages)
- TLS: rustls-based secure transport on port 5061 (SIPS)
- Connection pooling via `ConnectionPool` and `TlsPool`

The transport layer integrates with the transaction layer via `TransportDispatcher` trait.

## Development Guidelines

### Parser Development

- Parser is in `crates/sip-parse` using nom combinators
- Be liberal in what you accept (tolerant of whitespace, case variations)
- Be strict in what you generate (canonical formatting)
- All parser changes should be fuzz-tested
- Property tests in dev-dependencies using proptest for edge cases

### Transaction Layer Development

- Follow RFC 3261 state machine diagrams exactly (Figures 5-9)
- Timer names and values must match spec: T1=500ms, T2=4s, T4=5s, etc.
- Branch parameter must include RFC 3261 magic cookie: `z9hG4bK`
- ACK for 2xx responses is handled outside transaction layer (by dialog layer)
- Use `TransactionManager` for all transaction lifecycle operations

### Transport Development

- All transports are async using tokio
- TCP message framing uses CRLF boundaries (RFC 3261 §7.5)
- Connection reuse per RFC 5923
- TLS uses rustls with SNI
- DNS resolution should follow RFC 3263 (NAPTR → SRV → A/AAAA)

### Testing Strategy

- Unit tests: parser round-trips, header canonicalization, auth hash vectors
- Property tests: proptest for URI/header edge cases
- Fuzz tests: parser hardening with cargo-fuzz
- Integration tests: sipp scenarios (future), interop with Asterisk/FreeSWITCH/Kamailio

### Observability

- Use `tracing` crate for structured logging
- Span context should include: transaction_id, dialog_id, call_id, from_tag, to_tag
- `sip-observe` crate provides `TracingTransportMetrics` for transport-level metrics
- Log at appropriate levels: trace for packet-level, debug for transaction events, info for service-level

## RFC Compliance

### Core RFCs
- **RFC 3261** - SIP base specification (INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS, etc.)
- **RFC 3262** - PRACK (Provisional Response ACKnowledgement) - fully supported with RSeq manager, UAC/UAS helpers
- **RFC 3263** - Locating SIP Servers (NAPTR/SRV/A/AAAA)
- **RFC 3264** - Offer/Answer model with SDP (early and late offer fully supported)
- **RFC 3265/6665** - SUBSCRIBE/NOTIFY event framework (implemented with subscription management)
- **RFC 3515** - REFER method for call transfer (blind and attended transfers supported)
- **RFC 3581** - rport parameter
- **RFC 3891** - Replaces header for attended transfer (URL-encoded parameters)
- **RFC 3966** - tel URI for telephone numbers (global E.164 and local numbers with phone-context)
- **RFC 4028** - Session Timers
- **RFC 5626/5627** - Outbound keep-alive and GRUU
- **RFC 5923** - Connection Reuse
- **RFC 7616/7617** - HTTP Digest and Basic authentication

### Important SIP Behaviors

- **Max-Forwards**: Must decrement; respond 483 if zero
- **Via**: Top Via branch parameter identifies transaction; maintain Via order
- **Route/Record-Route**: Implement loose routing (RFC 3261 §16.12)
- **Branch parameter**: Must start with `z9hG4bK` magic cookie
- **ACK handling**: ACK for 2xx to INVITE creates no transaction (dialog layer handles)
- **Forking**: Stateful proxy may fork to multiple targets; cancel pending on final response
- **Retransmissions**: UDP requires application-layer retransmits per transaction timers

## Configuration

The `siphond` daemon accepts extensive command-line arguments for configuration:

**Core Options:**
- `--mode <MODE>` - Operational mode: minimal (default), full-uas, registrar, call-server, subscription-server
- `--udp-bind` - UDP listen address (default: 0.0.0.0:5060)
- `--tcp-bind` - TCP listen address (default: 0.0.0.0:5060)
- `--sips-bind` - TLS listen address (default: 0.0.0.0:5061)
- `--tls-cert` / `--tls-key` - TLS certificate and key paths (PEM format)
- `--local-uri` - Local SIP URI for From/Contact headers (default: sip:siphond@localhost)
- `--user-agent` - User-Agent header value

**Feature Flags:**
- `--auto-accept-calls` - Automatically accept INVITE requests (default: true)
- `--auto-accept-registrations` - Automatically accept REGISTER requests (default: true)
- `--auto-accept-subscriptions` - Automatically accept SUBSCRIBE requests (default: true)
- `--enable-prack` - Enable PRACK support (default: true)
- `--enable-refer` - Enable REFER support (default: true)

**Authentication:**
- `--auth` - Enable Digest authentication
- `--auth-realm` - Authentication realm (default: siphond.local)
- `--auth-users` - Path to users file (JSON format)

**Registrar:**
- `--reg-default-expiry` - Default registration expiry in seconds (default: 3600)
- `--reg-min-expiry` - Minimum registration expiry (default: 60)
- `--reg-max-expiry` - Maximum registration expiry (default: 86400)

**SDP Configuration:**
- `--sdp-profile` - SDP profile: none, audio-only (default), audio-video, or path to custom SDP file

See `bins/siphond/README.md` for detailed usage examples and troubleshooting.

## Project Status

This is an **alpha** implementation. Current status:
- ✅ Core message types and parsing
- ✅ UDP/TCP/TLS transports with connection pooling
- ✅ Transaction layer with transport-aware state machines and timers (RFC 3261 §17.1.2.2)
- ✅ Transport-aware timer optimization: TCP/TLS transactions complete 5-37 seconds faster than UDP
- ✅ Transaction performance metrics: duration tracking, timer statistics, outcome analysis
- ✅ RFC 3263 DNS resolution (NAPTR/SRV/A/AAAA)
- ✅ Dialog layer with full state management (Early/Confirmed/Terminated)
- ✅ Subscription layer with event notification support (RFC 3265)
- ✅ Call transfer support: REFER method (RFC 3515), Replaces header (RFC 3891)
- ✅ PRACK support: Reliable provisional responses (RFC 3262) with RSeq management
- ✅ tel URI support: RFC 3966 telephone number URIs (global E.164, local with phone-context)
- ✅ Digest authentication (MD5/SHA-256/SHA-512, qop=auth/auth-int)
- ✅ Registrar with location service and binding management
- ✅ UAC helpers (REGISTER, INVITE, ACK, BYE, SUBSCRIBE, NOTIFY, REFER, PRACK with auth, dialog, and RFC 3264 offer/answer)
- ✅ UAS helpers (response builders, dialog creation, request handlers, SUBSCRIBE, REFER, NOTIFY, PRACK, reliable provisionals)
- ✅ Proxy helper primitives (Via, Record-Route, Max-Forwards, Request-URI modification)
- ✅ B2BUA implementation with channel-based response bridging for device-to-device calls
- ✅ Full-featured multi-mode siphond daemon (minimal, full-uas, registrar, proxy, b2bua, call-server, subscription-server)
- ✅ Comprehensive test coverage (235+ tests across all layers: 88 transaction, 22 dialog, 125+ integration)
- ✅ Examples: register_with_auth, invite_call_flow, late_offer_flow, blind_transfer, attended_transfer, prack_flow, tel_uri_flow, timer_behavior, metrics_demo

See `siphon_rs_architecture_kickstart.md` for detailed architecture planning and roadmap.
