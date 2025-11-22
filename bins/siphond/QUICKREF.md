# siphond Quick Reference

One-page cheat sheet for siphond.

## Modes

| Mode | Description | Methods Supported |
|------|-------------|-------------------|
| `minimal` | OPTIONS only (default) | OPTIONS |
| `full-uas` | Complete SIP server | OPTIONS, INVITE, ACK, BYE, REGISTER, SUBSCRIBE, NOTIFY, REFER, PRACK |
| `registrar` | Registration server | OPTIONS, REGISTER |
| `call-server` | Calls only | OPTIONS, INVITE, ACK, BYE |
| `subscription-server` | Events only | OPTIONS, SUBSCRIBE, NOTIFY |

## Quick Commands

```bash
# Minimal (default)
siphond

# Full UAS
siphond --mode full-uas

# Registrar with auth
siphond --mode registrar --auth --auth-realm example.com

# Call server
siphond --mode call-server

# Custom port
siphond --udp-bind 0.0.0.0:5070
```

## Common Options

| Option | Default | Description |
|--------|---------|-------------|
| `--mode` | minimal | Operational mode |
| `--udp-bind` | 0.0.0.0:5060 | UDP listen address |
| `--tcp-bind` | 0.0.0.0:5060 | TCP listen address |
| `--sips-bind` | 0.0.0.0:5061 | TLS listen address |
| `--local-uri` | sip:siphond@localhost | Local SIP URI |
| `--user-agent` | siphond/0.2-refactored | User-Agent header |

## Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--auto-accept-calls` | ✅ true | Auto-accept INVITE |
| `--auto-accept-registrations` | ✅ true | Auto-accept REGISTER |
| `--auto-accept-subscriptions` | ✅ true | Auto-accept SUBSCRIBE |
| `--enable-prack` | ✅ true | Enable PRACK |
| `--enable-refer` | ✅ true | Enable REFER |

## Authentication

```bash
# Enable auth
siphond --mode registrar --auth --auth-realm example.com

# With users file
echo '{"alice":"pass123","bob":"secret"}' > users.json
siphond --mode registrar --auth --auth-users users.json
```

## TLS/SIPS

```bash
# Generate cert (dev only!)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"

# Run with TLS
siphond --mode full-uas \
  --sips-bind 0.0.0.0:5061 \
  --tls-cert cert.pem \
  --tls-key key.pem
```

## SDP Profiles

| Profile | Description |
|---------|-------------|
| `none` | No SDP support |
| `audio-only` | PCMU/PCMA audio (default) |
| `audio-video` | Audio + H.264 video |
| `<path>` | Custom SDP from file |

```bash
siphond --mode call-server --sdp-profile audio-video
```

## Registrar Settings

```bash
siphond --mode registrar \
  --reg-default-expiry 3600 \
  --reg-min-expiry 60 \
  --reg-max-expiry 86400
```

## Logging

```bash
# Info (default)
siphond --mode full-uas

# Debug
RUST_LOG=debug siphond --mode full-uas

# Trace (verbose)
RUST_LOG=trace siphond --mode full-uas

# Specific modules
RUST_LOG=siphond=debug,sip_transaction=trace siphond
```

## Testing

### With SIPp

```bash
# Terminal 1
siphond --mode call-server

# Terminal 2
sipp -sn uac 127.0.0.1:5060 -m 1
```

### With netcat

```bash
# Terminal 1
siphond --mode minimal

# Terminal 2
echo -ne "OPTIONS sip:test@127.0.0.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK776asdhds\r\n\
From: <sip:test@127.0.0.1>;tag=1928301774\r\n\
To: <sip:test@127.0.0.1>\r\n\
Call-ID: test@127.0.0.1\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n" | nc -u 127.0.0.1 5060
```

## Common Issues

### Port in use
```bash
siphond --udp-bind 0.0.0.0:5070 --tcp-bind 0.0.0.0:5070
```

### Firewall blocking
```bash
sudo ufw allow 5060/udp
sudo ufw allow 5060/tcp
```

### Bind to specific IP
```bash
siphond --udp-bind 192.168.1.100:5060
```

## Mode Comparison

| Feature | minimal | full-uas | registrar | call-server | subscription-server |
|---------|---------|----------|-----------|-------------|---------------------|
| OPTIONS | ✅ | ✅ | ✅ | ✅ | ✅ |
| INVITE | ❌ | ✅ | ❌ | ✅ | ❌ |
| REGISTER | ❌ | ✅ | ✅ | ❌ | ❌ |
| SUBSCRIBE | ❌ | ✅ | ❌ | ❌ | ✅ |
| REFER | ❌ | ✅ | ❌ | ❌ | ❌ |
| PRACK | ❌ | ✅ | ❌ | ✅* | ❌ |
| Auth | ❌ | ✅* | ✅* | ❌ | ❌ |
| Dialogs | ❌ | ✅ | ❌ | ✅ | ❌ |

\* Optional, enabled with flags

## Use Cases

| Scenario | Command |
|----------|---------|
| Quick OPTIONS test | `siphond` |
| Test call flows | `siphond --mode call-server` |
| Test registration | `siphond --mode registrar` |
| Full SIP testing | `siphond --mode full-uas` |
| Test subscriptions | `siphond --mode subscription-server` |
| Production-like registrar | `siphond --mode registrar --auth --auth-realm example.com` |
| Multi-transport test | `siphond --mode full-uas --tls-cert cert.pem --tls-key key.pem` |

## Help

```bash
# Show all options
siphond --help

# Show version
siphond --version
```

## Documentation

- [README.md](README.md) - Full documentation
- [EXAMPLES.md](EXAMPLES.md) - Usage examples
- [../../CLAUDE.md](../../CLAUDE.md) - Development guide

## Build Commands

```bash
# Build
cargo build -p siphond

# Build with TLS
cargo build -p siphond --features tls

# Run directly
cargo run -p siphond -- --mode full-uas

# Build release
cargo build -p siphond --release
./target/release/siphond --mode full-uas
```

---

**Pro Tip:** Combine multiple options for complex scenarios:

```bash
siphond --mode full-uas \
  --udp-bind 0.0.0.0:5060 \
  --tcp-bind 0.0.0.0:5060 \
  --sips-bind 0.0.0.0:5061 \
  --tls-cert cert.pem \
  --tls-key key.pem \
  --local-uri sip:server@example.com \
  --user-agent "MyServer/1.0" \
  --enable-prack \
  --enable-refer \
  --sdp-profile audio-video
```
