# SIPHON-RS

A modern, production-grade SIP (Session Initiation Protocol) stack implementation in Rust, implementing RFC 3261 and related specifications.

**Features:**
- ✅ Full RFC 3261 transaction layer with state machines
- ✅ Dialog management (RFC 3261 §12)
- ✅ Subscription/NOTIFY support (RFC 3265)
- ✅ Digest authentication (RFC 7616/7617)
- ✅ Registrar with location service
- ✅ UAC/UAS helper libraries
- ✅ Multi-transport support (UDP, TCP, TLS)
- ✅ RFC 3263 DNS resolution (NAPTR/SRV)
- ✅ Call transfer support (REFER/Replaces)
- ✅ PRACK support (RFC 3262)
- ✅ tel URI support (RFC 3966)

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
  sip-transaction/   # RFC 3261 transaction state machines
  sip-dns/           # RFC 3263 DNS resolution
  sip-dialog/        # Dialog, subscription, and RSeq management
  sip-auth/          # Digest authentication (RFC 7616/7617)
  sip-registrar/     # REGISTER handler and location service
  sip-uas/           # User Agent Server helpers
  sip-uac/           # User Agent Client helpers
  sip-proxy/         # Proxy functionality (placeholder)
  sip-sdp/           # SDP model (placeholder)
  sip-observe/       # Observability and metrics
  sip-testkit/       # Testing utilities

bins/
  siphond/           # Multi-mode SIP testing daemon
```

## Documentation

- **siphond**: See [`bins/siphond/README.md`](bins/siphond/README.md) for detailed daemon documentation
- **Architecture**: See [`CLAUDE.md`](CLAUDE.md) for development guide and architecture overview
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
