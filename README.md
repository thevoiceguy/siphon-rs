# SIPHON-RS
AI helped build this library. It’s either a stroke of genius or a very convincing hallucination. We’ll let you decide which. Use accordingly.

A modern, production-grade SIP (Session Initiation Protocol) stack implementation in Rust, implementing RFC 3261 and related specifications.

## Status: Production use, pre-1.0 🚀

Deployed in production and battle-tested against live carrier trunks (Twilio Secure
Trunking, real PSTN traffic) with HEP/Homer capture in the signaling path. Runtime
behavior is hardened by real-world exposure; the API surface is still pre-1.0 and
breaking changes land between 0.x releases — see [CHANGELOG.md](CHANGELOG.md) for
each release's breaking-change summary.

**Core Features:**
- ✅ Full RFC 3261 transaction layer with state machines
- ✅ Dialog management (RFC 3261 §12)
- ✅ Subscription/NOTIFY support (RFC 3265)
- ✅ Digest authentication (RFC 7616/7617 - MD5, SHA-256, SHA-512)
- ✅ Registrar with location service
- ✅ UAC/UAS helper libraries
- ✅ Multi-transport support (UDP, TCP, TLS 1.2/1.3)
- ✅ RFC-compliant TLS shutdown (close_notify alerts)
- ✅ RFC 3263 DNS resolution (NAPTR/SRV/A/AAAA)
- ✅ Call transfer support (REFER/Replaces - RFC 3515/3891)
- ✅ PRACK support (RFC 3262 - Reliable provisional responses)
- ✅ tel URI support (RFC 3966 - E.164 and local numbers)
- ✅ Transport-aware timers (optimized for TCP/TLS vs UDP)
- ✅ Transaction performance metrics
- ✅ Session timers with automatic refresh (RFC 4028)
- ✅ SDP offer/answer negotiation (RFC 3264)
- ✅ Stateful proxy (RFC 3261 §16 — forking, strict/loose routing, auth aggregation)
- ✅ B2BUA with response bridging
- ✅ STIR/SHAKEN caller identity (RFC 8224/8225 — PASSporT parsing, ES256 verification, X.509 chain validation)
- ✅ HEP3 (Homer) capture emission on every transport
- ✅ Per-source ingress rate limiting (token bucket, configurable)

**Production-Grade Implementation:**
- 🔒 Secure TLS via rustls (modern pure-Rust implementation)
- 📊 Comprehensive observability and metrics
- 🧪 2200+ unit and integration tests
- 📚 Extensive documentation and examples
- 🎯 RFC-compliant and interop-tested

## Quick Start

**siphond** - Multi-mode SIP testing daemon

```bash
# Build
cargo build

# Minimal mode - OPTIONS only
cargo run -p siphond -- --mode minimal

# Full UAS mode - Complete SIP server
cargo run -p siphond -- --mode full-uas

# Registrar mode with authentication
cargo run -p siphond -- --mode registrar --auth --auth-users users.json

# Call server mode
cargo run -p siphond -- --mode call-server --auto-accept-calls

# Stateful proxy - forwards calls to registered users
cargo run -p siphond -- --mode proxy --local-uri sip:proxy@192.168.1.81

# B2BUA - bridges calls between registered users
cargo run -p siphond -- --mode b2bua --local-uri sip:b2bua@192.168.1.81

# See all options
cargo run -p siphond -- --help
```

For detailed usage and examples, see [`bins/siphond/README.md`](bins/siphond/README.md).

## Workspace Layout

```
crates/
  sip-core/          # Core types, headers, URIs, messages
  sip-parse/         # SIP message parser (nom-based)
  sip-transport/     # Multi-transport layer (UDP, TCP, TLS)
  sip-transaction/   # RFC 3261 transaction state machines with transport-aware timers and metrics
  sip-dns/           # RFC 3263 DNS resolution
  sip-dialog/        # Dialog, subscription, and RSeq management
  sip-auth/          # Digest authentication (RFC 7616/7617)
  sip-registrar/     # REGISTER handler and location service
  sip-uas/           # User Agent Server helpers
  sip-uac/           # User Agent Client helpers
  sip-proxy/         # Stateful proxy (RFC 3261 §16: forking, routing, location service)
  sip-sdp/           # SDP model and offer/answer negotiation (RFC 3264)
  sip-identity/      # STIR/SHAKEN caller identity (RFC 8224/8225)
  sip-hep/           # HEP3 (Homer) capture emission
  sip-ratelimit/     # Token-bucket rate limiting
  sip-observe/       # Observability and metrics
  sip-testkit/       # Testing utilities

bins/
  siphond/           # Multi-mode SIP testing daemon
```

## Testing

**Test Suite Status:**
- ✅ **2200+ Unit & Integration Tests** - All passing
- ✅ **UDP/TCP Transport** - 24/24 scenarios passing
- ✅ **IPv6 Support** - All scenarios passing
- ⚠️ **Authentication Tests** - Known SIPp tool limitation (see below); validated in production instead
- ⚠️ **TLS Tests** - Known SIPp tool limitation (see below); validated in production instead

**Important Notes on Test Failures:**

Some automated tests fail due to **known limitations in SIPp v3.7.3** (the test tool), NOT bugs in siphond:

1. **Authentication Tests**: SIPp cannot handle RFC 7616 `qop="auth"` parameter
   - ✅ **Validated in production** - Digest-authenticated REGISTER refreshes and INVITE
     401/407 challenge/retry run continuously against live registrars and gateways
     (RFC 7616 `qop="auth"`, nonce reuse windows)
   - ✅ **Also verified** with pjsua, Linphone, and real SIP clients
   - See [`sip-testkit/sipp/AUTH_TESTING.md`](sip-testkit/sipp/AUTH_TESTING.md) for details

2. **TLS Tests**: SIPp v3.7.3 has OpenSSL/rustls compatibility issues (both TLS 1.2 & 1.3)
   - ✅ **Validated in production** - Live carrier TLS trunks (Twilio Secure Trunking)
     exercise SNI/reference-identity handling, certificate verification, connection
     pooling and reuse, keepalives, and close_notify shutdown daily
   - ✅ **TLS 1.2/1.3 both work** - Full RFC 5246/8446 compliance
   - ✅ **Also verified** with openssl s_client and modern SIP clients
   - See [`sip-testkit/sipp/README.md`](sip-testkit/sipp/README.md) "TLS Testing" section

**Running Tests:**
```bash
# Unit tests
cargo test --all

# Integration tests with SIPp
cd sip-testkit/sipp
./run_scenarios.sh 127.0.0.1 5060

# Test TLS manually (works perfectly)
cargo run -p siphond -- --sips-bind 127.0.0.1:5061 --tls-cert cert.pem --tls-key key.pem
echo "OPTIONS sip:test@127.0.0.1 SIP/2.0..." | openssl s_client -connect 127.0.0.1:5061
```

**TLS Configuration:**
```bash
# Default: TLS 1.3
cargo run -p siphond -- --sips-bind 0.0.0.0:5061 --tls-cert cert.pem --tls-key key.pem

# Force TLS 1.2 for legacy clients
SIPHON_TLS12_ONLY=1 cargo run -p siphond -- --sips-bind 0.0.0.0:5061 --tls-cert cert.pem --tls-key key.pem
```

## Documentation

- **siphond**: See [`bins/siphond/README.md`](bins/siphond/README.md) for detailed daemon documentation
- **Architecture**: See [`CLAUDE.md`](CLAUDE.md) for development guide and architecture overview
- **Releases**: See [`RELEASING.md`](RELEASING.md) for versioning/tagging conventions and the release checklist
- **Examples**: Check `crates/sip-*/examples/` for usage examples

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
