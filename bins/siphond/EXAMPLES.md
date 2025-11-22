# siphond Usage Examples

Practical examples for common siphond use cases.

## Table of Contents

- [Quick Start Examples](#quick-start-examples)
- [Development & Testing](#development--testing)
- [Production-Like Scenarios](#production-like-scenarios)
- [Testing with SIP Clients](#testing-with-sip-clients)
- [Advanced Configuration](#advanced-configuration)

---

## Quick Start Examples

### 1. Basic OPTIONS Responder

Simplest possible configuration - just responds to OPTIONS:

```bash
siphond
```

Or explicitly:

```bash
siphond --mode minimal --udp-bind 0.0.0.0:5060
```

**Test it:**
```bash
# Send OPTIONS with sipp (if installed)
sipp -sn uac -s test 127.0.0.1:5060 -m 1
```

---

### 2. Accept All Calls

Run a full UAS that accepts all incoming INVITE requests:

```bash
siphond --mode full-uas
```

**What happens:**
- INVITE → 100 Trying → 180 Ringing → 200 OK (with SDP)
- Creates and tracks dialogs
- Handles BYE to terminate calls
- Accepts REGISTER, SUBSCRIBE, REFER

---

### 3. Test Registrar

Simple registrar for testing client registration:

```bash
siphond --mode registrar
```

**Test with a SIP client:**
- Server: `127.0.0.1:5060`
- Username: anything (no auth required in this mode)
- Watch the logs to see registrations

---

## Development & Testing

### Scenario 1: Testing Call Flows

Run a call server for testing INVITE/BYE sequences:

```bash
siphond --mode call-server \
  --udp-bind 0.0.0.0:5060 \
  --local-uri sip:test-uas@192.168.1.100 \
  --sdp-profile audio-only
```

**Use with SIPp call scenario:**
```bash
# Run siphond in one terminal
siphond --mode call-server

# In another terminal, run SIPp UAC
sipp -sn uac 127.0.0.1:5060 -m 10
```

---

### Scenario 2: Testing REGISTER Cycles

Registrar with custom expiry for testing re-registration:

```bash
siphond --mode registrar \
  --reg-default-expiry 300 \
  --reg-min-expiry 60 \
  --reg-max-expiry 600 \
  --local-uri sip:registrar@example.com
```

**What to test:**
- Short expiry forces frequent re-registration
- Test wildcard deregistration (Contact: *)
- Test multiple device registration

---

### Scenario 3: Testing SUBSCRIBE/NOTIFY

Subscription server for event packages:

```bash
siphond --mode subscription-server \
  --udp-bind 0.0.0.0:5060 \
  --auto-accept-subscriptions
```

**Test event packages:**
- `Event: refer` (call transfer status)
- `Event: presence` (user presence)
- `Event: message-summary` (voicemail notifications)

---

### Scenario 4: Debugging with Verbose Logging

Maximum verbosity for debugging:

```bash
RUST_LOG=trace siphond --mode full-uas 2>&1 | tee siphond.log
```

**Alternative - module-specific:**
```bash
RUST_LOG=siphond=debug,sip_transaction=trace,sip_dialog=debug siphond --mode full-uas
```

---

## Production-Like Scenarios

### Scenario 5: Secure Registrar with Authentication

Full registrar with Digest authentication:

```bash
# Create users file
cat > users.json << 'EOF'
{
  "alice": "password123",
  "bob": "secret456",
  "charlie": "test789"
}
EOF

# Run registrar
siphond --mode registrar \
  --udp-bind 0.0.0.0:5060 \
  --tcp-bind 0.0.0.0:5060 \
  --auth \
  --auth-realm example.com \
  --auth-users users.json \
  --local-uri sip:registrar@example.com \
  --user-agent "ExampleCom-Registrar/1.0"
```

**Expected behavior:**
- First REGISTER → 401 Unauthorized (with WWW-Authenticate)
- Retry with credentials → 200 OK (with Contact list)

---

### Scenario 6: Multi-Transport Server with TLS

Complete server with UDP, TCP, and TLS:

```bash
# Generate self-signed cert (development only!)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout siphond-key.pem \
  -out siphond-cert.pem \
  -days 365 \
  -subj "/CN=sip.example.com/O=Example Corp"

# Run with all transports
siphond --mode full-uas \
  --udp-bind 0.0.0.0:5060 \
  --tcp-bind 0.0.0.0:5060 \
  --sips-bind 0.0.0.0:5061 \
  --tls-cert siphond-cert.pem \
  --tls-key siphond-key.pem \
  --local-uri sip:sip.example.com
```

**Test TLS:**
```bash
# Configure SIP client for TLS transport
# Server: sip.example.com:5061
# Transport: TLS
```

---

### Scenario 7: Enterprise PBX Simulator

Simulate a small office PBX:

```bash
siphond --mode full-uas \
  --udp-bind 192.168.10.1:5060 \
  --local-uri sip:pbx@office.local \
  --user-agent "OfficePBX/2.0" \
  --auto-accept-calls \
  --auto-accept-registrations \
  --enable-refer \
  --sdp-profile audio-only \
  --reg-default-expiry 3600
```

**Features enabled:**
- Call handling (INVITE/BYE)
- Device registration
- Call transfer (REFER)
- Audio-only media

---

## Testing with SIP Clients

### Example 1: Linphone Desktop

1. **Install Linphone** (https://www.linphone.org/)

2. **Configure Account:**
   ```
   SIP Server: 127.0.0.1:5060
   Username: testuser
   Password: (leave empty if no auth)
   Transport: UDP
   ```

3. **Run siphond:**
   ```bash
   siphond --mode full-uas
   ```

4. **Test:**
   - Register the account (watch siphond logs)
   - Make a call to `sip:echo@127.0.0.1`
   - Check dialog creation in logs

---

### Example 2: SIPp Scenarios

**Basic UAC (caller) test:**
```bash
# Terminal 1: Run siphond
siphond --mode call-server

# Terminal 2: Run SIPp UAC
sipp -sn uac 127.0.0.1:5060 -m 1 -trace_msg
```

**REGISTER test:**
```bash
# Terminal 1: Run siphond
siphond --mode registrar

# Terminal 2: Create register.xml
cat > register.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<scenario name="REGISTER">
  <send retrans="500">
    <![CDATA[
      REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:test@[remote_ip]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:test@[remote_ip]>
      Call-ID: [call_id]
      CSeq: 1 REGISTER
      Contact: <sip:test@[local_ip]:[local_port]>
      Max-Forwards: 70
      Expires: 3600
      Content-Length: 0
    ]]>
  </send>
  <recv response="200" />
</scenario>
EOF

# Terminal 2: Run SIPp
sipp -sf register.xml 127.0.0.1:5060 -m 1
```

---

### Example 3: Testing with curl-like Tools

**Using nc (netcat) for raw SIP:**

```bash
# Start siphond
siphond --mode minimal --udp-bind 127.0.0.1:5060

# Send raw OPTIONS (in another terminal)
(echo -ne "OPTIONS sip:test@127.0.0.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK776asdhds\r\n\
From: <sip:client@127.0.0.1>;tag=1928301774\r\n\
To: <sip:test@127.0.0.1>\r\n\
Call-ID: test-$(date +%s)@127.0.0.1\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n" && sleep 1) | nc -u 127.0.0.1 5060
```

---

## Advanced Configuration

### Example 1: Multiple Instances

Run multiple siphond instances on different ports:

```bash
# Registrar on 5060
siphond --mode registrar --udp-bind 0.0.0.0:5060 &

# Call server on 5061
siphond --mode call-server --udp-bind 0.0.0.0:5061 --tcp-bind 0.0.0.0:5061 &

# Subscription server on 5062
siphond --mode subscription-server --udp-bind 0.0.0.0:5062 &
```

---

### Example 2: Selective Accept/Reject

Only accept calls, reject everything else:

```bash
siphond --mode call-server \
  --auto-accept-calls \
  --no-auto-accept-registrations \
  --no-auto-accept-subscriptions
```

---

### Example 3: Custom Local URI and User-Agent

Emulate specific server:

```bash
siphond --mode full-uas \
  --local-uri sip:asterisk@pbx.company.com \
  --user-agent "Asterisk PBX 18.0.0" \
  --udp-bind 0.0.0.0:5060
```

**Client will see:**
- From: `<sip:asterisk@pbx.company.com>`
- Contact: `<sip:asterisk@pbx.company.com>`
- User-Agent: `Asterisk PBX 18.0.0`

---

### Example 4: Testing Edge Cases

**Zero expiry (immediate deregistration):**
```bash
siphond --mode registrar --reg-min-expiry 0
```

**Very short expiry (stress test re-registration):**
```bash
siphond --mode registrar --reg-default-expiry 10 --reg-min-expiry 5
```

**Disable PRACK and REFER:**
```bash
siphond --mode full-uas --no-enable-prack --no-enable-refer
```

---

## Troubleshooting Examples

### Issue: Port Already in Use

**Problem:** `Address already in use (os error 98)`

**Solution:** Use different port
```bash
siphond --mode full-uas --udp-bind 0.0.0.0:5070 --tcp-bind 0.0.0.0:5070
```

---

### Issue: No Incoming Requests

**Problem:** SIP clients can't reach siphond

**Check 1:** Firewall
```bash
# Allow port 5060
sudo ufw allow 5060/udp
sudo ufw allow 5060/tcp
```

**Check 2:** Binding address
```bash
# Bind to specific interface
ip addr show  # Find your IP
siphond --mode full-uas --udp-bind 192.168.1.100:5060
```

**Check 3:** Test locally first
```bash
# Start server
siphond --mode minimal --udp-bind 127.0.0.1:5060

# Test with nc
echo -e "OPTIONS sip:test@127.0.0.1 SIP/2.0\r\n\r\n" | nc -u 127.0.0.1 5060
```

---

### Issue: Authentication Not Working

**Problem:** 401 but no WWW-Authenticate header

**Check:** Authentication is enabled
```bash
siphond --mode registrar --auth --auth-realm example.com
```

**Verify users file:**
```bash
cat users.json
# Should be valid JSON: {"username": "password"}
```

---

## Next Steps

- See [README.md](README.md) for complete documentation
- See [../../CLAUDE.md](../../CLAUDE.md) for development guidelines
- Explore examples in `crates/sip-uac/examples/` and `crates/sip-uas/examples/`

---

## Contributing Examples

Have a useful siphond configuration or test scenario? Please contribute!

1. Fork the repository
2. Add your example to this file
3. Test it thoroughly
4. Submit a pull request
