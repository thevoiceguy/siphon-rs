# siphond - SIP Testing Daemon

**A Swiss Army knife SIP server for testing, development, and demonstration.**

siphond is a multi-mode SIP daemon built on the siphon-rs stack, providing comprehensive SIP protocol testing capabilities. It can operate as a minimal OPTIONS responder, full-featured UAS, registrar, call server, or subscription server.

## Features

- 🎯 **Multiple Operational Modes** - Switch between minimal, full-uas, registrar, call-server, and subscription-server modes
- 📞 **Complete Call Handling** - INVITE/ACK/BYE with dialog management and SDP negotiation
- 📝 **Registration Server** - RFC 3261 compliant registrar with location service
- 🔔 **Event Subscriptions** - SUBSCRIBE/NOTIFY for event packages (RFC 3265)
- 🔄 **Call Transfer** - REFER support for blind and attended transfers (RFC 3515)
- ✅ **Reliable Provisionals** - PRACK support for 180/183 responses (RFC 3262)
- 🔐 **Authentication** - Digest authentication with MD5/SHA-256/SHA-512
- 🌐 **Multi-Transport** - UDP, TCP, and TLS (SIPS) support
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

**Supported Methods:** OPTIONS, INVITE, ACK, BYE, REGISTER, SUBSCRIBE, NOTIFY, REFER, PRACK

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

**Supported Methods:** OPTIONS, INVITE, ACK, BYE

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

## Command-Line Options

### Core Options

| Option | Description | Default |
|--------|-------------|---------|
| `--mode <MODE>` | Operational mode: minimal, full-uas, registrar, call-server, subscription-server | minimal |
| `--udp-bind <ADDR>` | UDP bind address | 0.0.0.0:5060 |
| `--tcp-bind <ADDR>` | TCP bind address | 0.0.0.0:5060 |
| `--sips-bind <ADDR>` | TLS bind address | 0.0.0.0:5061 |
| `--local-uri <URI>` | Local SIP URI for From/Contact headers | sip:siphond@localhost |
| `--user-agent <STR>` | User-Agent header value | siphond/0.2-refactored |

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

- **Interactive Mode**: Not yet implemented (planned)
- **Scenario Files**: Not yet implemented (planned)
- **Media/RTP**: No actual media handling (SDP only)
- **NOTIFY Sending**: REFER/SUBSCRIBE don't automatically send NOTIFY yet
- **Custom SDP**: File-based custom SDP not implemented
- **User Loading**: Authentication users file loading not implemented

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
