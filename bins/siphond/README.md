AI helped build this library. It’s either a stroke of genius or a very convincing hallucination. We’ll let you decide which. Use accordingly.

# siphond - SIP Testing Daemon

**A simple SIP server for testing, development, and demonstration of the siphon-rs sip stack**

**Not for production**

siphond is a multi-mode SIP daemon built on the siphon-rs stack, providing comprehensive SIP protocol testing capabilities. It can operate as a minimal OPTIONS responder, full-featured UAS, registrar, proxy, B2BUA, call server, or subscription server.

## Features

- 🎯 **Multiple Operational Modes** - Switch between minimal, full-uas, registrar, proxy, b2bua, call-server, and subscription-server modes
- 📞 **Complete Call Handling** - INVITE/ACK/BYE with dialog management and SDP negotiation
- 📝 **Registration Server** - RFC 3261 compliant registrar with location service
- 🔀 **Proxy Mode** - Stateful SIP proxy with Via/Record-Route handling and location service integration
- 🧭 **In-Dialog Proxying** - ACK/BYE/CANCEL/PRACK/UPDATE forwarding with strict transport selection (RFC 3263 + Contact transport)
- 🔗 **B2BUA Mode** - Back-to-Back User Agent for bridging calls between registered users with response relay
- 🔔 **Event Subscriptions** - SUBSCRIBE/NOTIFY for event packages (RFC 3265)
- 🔄 **Call Transfer** - REFER support for blind and attended transfers (RFC 3515)
- ✅ **Reliable Provisionals** - PRACK support for 180/183 responses (RFC 3262)
- 📦 **Scenario Runner** - JSON-driven scripted call flows for repeatable tests
- ⏲️ **Session Timers** - RFC 4028 session refresh/expiry toggle for UAS testing
- 📨 **Mid-Dialog Methods** - MESSAGE/INFO/UPDATE handlers for signaling tests
- 🧾 **Standard NOTIFY Bodies** - presence, dialog-info, and message-summary payloads
- 🔐 **Authentication** - Digest authentication with MD5/SHA-256/SHA-512
- 🌐 **Multi-Transport** - UDP, TCP, and TLS (SIPS) support
- 🎯 **Deterministic IDs** - Seeded Call-ID/branch/tag generation for stable snapshots
- ⚙️ **Highly Configurable** - 25+ CLI options for fine-grained control

## Quick Start

```bash
# Build siphond
cargo build -p siphond

# Run in minimal mode (OPTIONS only)
./target/debug/siphond --mode minimal

# Run as full UAS (accept everything)
./target/debug/siphond --mode full-uas

# Run as registrar with authentication
./target/debug/siphond --mode registrar --auth --auth-realm example.com

# Run as B2BUA for device-to-device calls
./target/debug/siphond --mode b2bua --local-uri sip:b2bua@192.168.1.81
```

## Operational Modes

### 1. Minimal Mode (Default)

Responds only to OPTIONS requests with capability information.

```bash
siphond --mode minimal
```

**Use Cases:**
- Basic connectivity testing
- Capability discovery
- Minimal footprint testing

**Supported Methods:** OPTIONS

---

### 2. Full UAS Mode

Complete SIP User Agent Server accepting all types of requests.

```bash
siphond --mode full-uas
```

**Supported Methods:** OPTIONS, INVITE, ACK, BYE, REGISTER, SUBSCRIBE, NOTIFY, REFER, PRACK, MESSAGE, INFO, UPDATE

**Features:**
- ✅ Automatic call acceptance
- ✅ Dialog management
- ✅ Registration handling
- ✅ Event subscriptions
- ✅ Call transfer support
- ✅ Reliable provisional responses

**Configuration:**
```bash
siphond --mode full-uas \
  --auto-accept-calls \
  --auto-accept-registrations \
  --auto-accept-subscriptions \
  --enable-prack \
  --enable-refer
```

---

### 3. Registrar Mode

Acts as a SIP registrar (location server) for user registrations.

```bash
siphond --mode registrar
```

**Supported Methods:** OPTIONS, REGISTER

**Features:**
- ✅ Contact binding management
- ✅ Expiry handling (with min/max bounds)
- ✅ Multiple device registration
- ✅ Wildcard deregistration (Contact: *)
- ✅ Q-value support for prioritization
- ✅ Optional Digest authentication

**Configuration:**
```bash
siphond --mode registrar \
  --reg-default-expiry 3600 \
  --reg-min-expiry 60 \
  --reg-max-expiry 86400 \
  --auth \
  --auth-realm example.com
```

---

### 4. Call Server Mode

Specialized for call handling without registration complexity.

```bash
siphond --mode call-server
```

**Supported Methods:** OPTIONS, INVITE, ACK, BYE, INFO, UPDATE

**Features:**
- ✅ Call setup and teardown
- ✅ Dialog state management
- ✅ SDP offer/answer negotiation
- ✅ Early and late offer support

**Configuration:**
```bash
siphond --mode call-server \
  --sdp-profile audio-only \
  --auto-accept-calls
```

---

### 5. Subscription Server Mode

Handles event subscriptions and notifications.

```bash
siphond --mode subscription-server
```

**Supported Methods:** OPTIONS, SUBSCRIBE, NOTIFY

**Features:**
- ✅ Event package subscriptions
- ✅ Subscription state management
- ✅ Expiry tracking
- ✅ Auto-renewal support

**Event Packages:** `refer`, `presence`, `message-summary`, etc.

---

### 6. Proxy Mode

Acts as a stateful SIP proxy forwarding calls to registered users.

```bash
siphond --mode proxy --local-uri sip:proxy@192.168.1.81
```

**Supported Methods:** OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, PRACK, UPDATE

**Features:**
- ✅ Stateful proxy with location service integration
- ✅ Via header insertion with branch ID tracking
- ✅ Record-Route for staying in signaling path
- ✅ Max-Forwards checking and decrement
- ✅ Request-URI rewriting to registered contact
- ✅ Location service lookup for call routing
- ✅ Response relay on the same transport as received
- ✅ Strict transport selection (RFC 3263 + Contact transport parameter)

**Use Cases:**
- Testing proxy behavior
- Call forwarding to registered endpoints
- Multi-device registration testing

**Configuration:**
```bash
siphond --mode proxy \
  --local-uri sip:proxy@192.168.1.81 \
  --tcp-bind 0.0.0.0:5060 \
  --reg-default-expiry 3600
```

**Note:** Media (RTP) is not proxied; signaling only.

---

### 7. B2BUA Mode

Back-to-Back User Agent that bridges calls between two registered users.

```bash
siphond --mode b2bua --local-uri sip:b2bua@192.168.1.81
```

**Supported Methods:** OPTIONS, REGISTER, INVITE, ACK, BYE

**Features:**
- ✅ Complete call bridging between registered users
- ✅ Channel-based response relay (180, 200, etc.)
- ✅ Location service integration
- ✅ Separate UAC and UAS transaction legs
- ✅ Automatic response forwarding from callee to caller
- ✅ SDP pass-through from caller to callee

**Use Cases:**
- Device-to-device call testing
- Call bridging demonstrations
- Multi-party call scenarios
- Testing call flows with real SIP phones

**Configuration:**
```bash
siphond --mode b2bua \
  --local-uri sip:b2bua@192.168.1.81 \
  --tcp-bind 0.0.0.0:5060 \
  --reg-default-expiry 3600
```

**Example Workflow:**
1. Alice registers: `REGISTER sip:b2bua@192.168.1.81` with Contact: `sip:alice@192.168.1.100`
2. Bob registers: `REGISTER sip:b2bua@192.168.1.81` with Contact: `sip:bob@192.168.1.200`
3. Bob calls Alice: `INVITE sip:alice@192.168.1.81`
4. B2BUA:
   - Sends 100 Trying to Bob
   - Looks up Alice's contact in location service
   - Creates outgoing INVITE to Alice's registered contact
   - Relays Alice's 180 Ringing → Bob
   - Relays Alice's 200 OK → Bob
5. Call established between Bob and Alice through B2BUA

**Note:** Currently supports TCP transport only. Media (RTP) flows directly between endpoints (not through B2BUA).

---

## Command-Line Options

### Core Options

| Option | Description | Default |
|--------|-------------|---------|
| `--mode <MODE>` | Operational mode: minimal, full-uas, registrar, proxy, b2bua, call-server, subscription-server | minimal |
| `--udp-bind <ADDR>` | UDP bind address | 0.0.0.0:5060 |
| `--tcp-bind <ADDR>` | TCP bind address | 0.0.0.0:5060 |
| `--sips-bind <ADDR>` | TLS bind address | 0.0.0.0:5061 |
| `--local-uri <URI>` | Local SIP URI for From/Contact headers | sip:siphond@localhost |
| `--user-agent <STR>` | User-Agent header value | siphond/0.2-refactored |
| `--scenario <PATH>` | Run JSON scenario file at startup | - |

### TLS Options

| Option | Description |
|--------|-------------|
| `--tls-cert <PATH>` | TLS certificate file (PEM format) |
| `--tls-key <PATH>` | TLS private key file (PEM format) |

### Feature Flags

| Option | Description | Default |
|--------|-------------|---------|
| `--auto-accept-calls` | Automatically accept INVITE requests | true |
| `--auto-accept-registrations` | Automatically accept REGISTER requests | true |
| `--auto-accept-subscriptions` | Automatically accept SUBSCRIBE requests | true |
| `--enable-prack` | Enable PRACK (reliable provisionals) | true |
| `--enable-refer` | Enable REFER (call transfer) | true |
| `--enable-session-timers` | Enable RFC 4028 session timers | false |

### SDP Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--sdp-profile <PROFILE>` | SDP profile: none, audio-only, audio-video, <path> | audio-only |

### Authentication Options

| Option | Description | Default |
|--------|-------------|---------|
| `--auth` | Enable Digest authentication | false |
| `--auth-realm <STR>` | Authentication realm | siphond.local |
| `--auth-users <PATH>` | Users file (JSON: `{"user": "password"}`) | - |

### Registrar Options

| Option | Description | Default |
|--------|-------------|---------|
| `--reg-default-expiry <SECS>` | Default registration expiry | 3600 |
| `--reg-min-expiry <SECS>` | Minimum registration expiry | 60 |
| `--reg-max-expiry <SECS>` | Maximum registration expiry | 86400 |

---

## Usage Examples

### Example 1: Basic Testing Server

Run a full-featured UAS for general testing:

```bash
siphond --mode full-uas \
  --udp-bind 0.0.0.0:5060 \
  --local-uri sip:test-server@192.168.1.100
```

### Example 2: Registrar with Authentication

Set up a registrar requiring authentication:

```bash
# Create users file
echo '{"alice": "secret123", "bob": "pass456"}' > users.json

# Run registrar
siphond --mode registrar \
  --auth \
  --auth-realm example.com \
  --auth-users users.json \
  --reg-default-expiry 7200
```

### Example 3: Secure TLS Server

Run with TLS transport:

```bash
# Generate test certificates (for development only)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=siphond"

# Run with TLS
siphond --mode full-uas \
  --sips-bind 0.0.0.0:5061 \
  --tls-cert cert.pem \
  --tls-key key.pem
```

### Example 4: Call Server with Custom SDP

Audio/video call server:

```bash
siphond --mode call-server \
  --sdp-profile audio-video \
  --auto-accept-calls \
  --local-uri sip:media-server@192.168.1.100
```

### Example 5: Multi-Transport Configuration

Listen on multiple transports with different ports:

```bash
siphond --mode full-uas \
  --udp-bind 0.0.0.0:5060 \
  --tcp-bind 0.0.0.0:5060 \
  --sips-bind 0.0.0.0:5061 \
  --tls-cert cert.pem \
  --tls-key key.pem
```

### Example 6: Scenario Runner (JSON)

```bash
# Run scripted steps from JSON
siphond --mode full-uas --scenario scenarios/basic-call.json
```

### Example 7: Session Timers

```bash
siphond --mode full-uas --enable-session-timers
```

### Example 8: Deterministic IDs for Stable Tests

```bash
SIPHON_ID_SEED=42 siphond --mode full-uas
```

---

## Testing with SIP Clients

### Testing with SIPp

```bash
# OPTIONS ping test
sipp -sn uac -s test 127.0.0.1:5060 -m 1

# REGISTER test
sipp -sf register.xml 127.0.0.1:5060

# INVITE call flow
sipp -sn uac 127.0.0.1:5060 -m 1
```

### Testing with Linphone

1. Open Linphone
2. Configure account:
   - SIP Server: `127.0.0.1:5060`
   - Username: `testuser`
   - Transport: UDP
3. Register (if registrar mode)
4. Make test calls

### Testing with curl/sipcat

```bash
# Send OPTIONS request (requires sipcat or similar tool)
echo "OPTIONS sip:siphond@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK776asdhds
Max-Forwards: 70
From: <sip:test@127.0.0.1>;tag=1928301774
To: <sip:siphond@127.0.0.1>
Call-ID: test@127.0.0.1
CSeq: 1 OPTIONS
Content-Length: 0

" | nc -u 127.0.0.1 5060
```

---

## Architecture

siphond uses a layered, handler-based architecture:

```
┌─────────────────────────────────────────┐
│         Transport Layer (UDP/TCP/TLS)   │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│         Transaction Manager             │
│         (RFC 3261 State Machines)       │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│         Request Dispatcher              │
│         (Method Routing)                │
└─────────────────┬───────────────────────┘
                  │
       ┌──────────┼──────────┬─────────┐
       ▼          ▼          ▼         ▼
  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────┐
  │OPTIONS │ │INVITE  │ │REGISTER│ │ ...  │
  │Handler │ │Handler │ │Handler │ │      │
  └────────┘ └────────┘ └────────┘ └──────┘
       │          │          │         │
       └──────────┴──────────┴─────────┘
                  │
┌─────────────────▼───────────────────────┐
│         Service Registry                │
│  • Dialog Manager                       │
│  • Subscription Manager                 │
│  • Registrar                           │
│  • Authenticator                       │
└─────────────────────────────────────────┘
```

### Key Components

- **Handlers**: Method-specific request processing (OPTIONS, INVITE, etc.)
- **Dispatcher**: Routes requests to appropriate handlers based on method
- **Service Registry**: Shared services (dialogs, subscriptions, registrar)
- **Configuration**: Mode-based behavior and feature flags

---

## Logging

siphond uses structured logging via `tracing`. Set log level with `RUST_LOG`:

```bash
# Info level (default)
RUST_LOG=info siphond --mode full-uas

# Debug level for detailed output
RUST_LOG=debug siphond --mode full-uas

# Trace level for maximum verbosity
RUST_LOG=trace siphond --mode full-uas

# Module-specific logging
RUST_LOG=siphond=debug,sip_transaction=trace siphond --mode full-uas
```

---

## Troubleshooting

### Port Already in Use

If you see `Address already in use (os error 98)`:

```bash
# Use different ports
siphond --mode full-uas \
  --udp-bind 0.0.0.0:5070 \
  --tcp-bind 0.0.0.0:5070
```

### TLS Certificate Issues

Ensure both certificate and key are provided:

```bash
# Both required
siphond --tls-cert cert.pem --tls-key key.pem
```

### Authentication Not Working

Verify users file format:

```json
{
  "alice": "password123",
  "bob": "secret456"
}
```

### No Response to Requests

Check firewall and binding:

```bash
# Bind to all interfaces
siphond --mode full-uas --udp-bind 0.0.0.0:5060

# Or specific interface
siphond --mode full-uas --udp-bind 192.168.1.100:5060
```

---

## Limitations

⚠️ **Important: siphond is a testing/development tool, NOT production-ready software.**

### ✅ What Works (RFC Compliant)

- **SUBSCRIBE/NOTIFY**: RFC 3265 compliant - initial NOTIFY sent automatically after 200 OK
- **REGISTER**: Full RFC 3261 §10 compliance with location service
- **OPTIONS**: Complete capability advertisement
- **Dialog Management**: Full dialog lifecycle (Early/Confirmed/Terminated)
- **Authentication**: Digest authentication (MD5/SHA-256/SHA-512)
- **Basic Call Flows**: Simple INVITE → 180 → 200 → ACK → BYE works

### ⚠️ Known Incomplete Features

#### INVITE Handler Limitations
- **SDP Negotiation**: Basic SDP generation/answering only; no full codec negotiation or media attribute validation
- **Early Media**: 183 Session Progress with SDP not fully tested
- **PRACK Integration**: RSeq handling stub present but not fully integrated with INVITE state machine

#### REFER Handler Limitations
- **Transfer Behavior**: Transfer INVITE uses a generated SDP offer; advanced transfer policies are not implemented

#### Proxy Mode Limitations
- **Forking**: Parallel/serial forking is not implemented
- **Media**: No media/RTP proxying (signaling only)

#### General Limitations
- **Media/RTP**: No actual media handling - SDP is generated/passed through but no RTP streams
- **Interactive Mode**: Not yet implemented (planned)
- **Scenario Files**: JSON format supported; YAML not supported yet
- **Custom SDP Files**: `--sdp-profile <path>` option not implemented, only presets work
- **User File Loading**: `--auth-users <path>` option not implemented, hardcoded users only

### 🔒 Security Status

The following security features ARE implemented:
- ✅ Rate limiting (per-IP/per-user request limits)
- ✅ Nonce replay protection (automatic nonce expiry)
- ✅ CSeq validation (out-of-order request detection)
- ✅ Transaction DoS protection (configurable transaction limits)
- ✅ Content-Length overflow protection (64 MB hard limit)
- ✅ Connection pool limits (TCP/TLS connection exhaustion prevention)

**Security Notice:** While these protections are in place, siphond has NOT undergone security auditing and should NOT be exposed to untrusted networks or used in production environments.

### 📋 Recommended Use Cases

**✅ Good For:**
- SIP stack development and testing
- Protocol learning and experimentation
- Integration testing with real SIP phones
- Demonstration and proof-of-concept
- Basic call flow verification

**❌ Not Suitable For:**
- Production SIP services
- Public-facing deployments
- Mission-critical applications
- High-volume call handling
- Complex call scenarios (conference, forking, etc.)

---

## Contributing

Contributions welcome! siphond is part of the siphon-rs project.

See [../../CLAUDE.md](../../CLAUDE.md) for development guidelines.

---

## License

MIT License - See [LICENSE](../../LICENSE) for details

---

## Related

- **siphon-rs**: The complete SIP stack
- **sip-parse**: SIP message parser
- **sip-transaction**: Transaction layer
- **sip-dialog**: Dialog management
- **sip-registrar**: Registration server
- **sip-uas/uac**: User agent helpers

---

## Changelog

### v0.2.0 - Major Refactoring
- ✨ Added multi-mode operation
- ✨ Added full UAS capabilities
- ✨ Added registrar mode
- ✨ Added call server mode
- ✨ Added subscription server mode
- ✨ Comprehensive CLI options
- 📚 Complete documentation

### v0.1.0 - Initial Release
- Basic OPTIONS responder
- UDP/TCP/TLS support
