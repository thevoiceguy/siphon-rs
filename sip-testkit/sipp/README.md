# SIPp Interop Scenarios

Run these against `siphond` or any SIP server for comprehensive interop testing.

## Prerequisites

Install SIPp:
```bash
# Ubuntu/Debian
sudo apt-get install sip-tester

# macOS
brew install sipp

# Or build from source
# https://github.com/SIPp/sipp
```

## Quick Start

### Automated Test Suite

Run all scenarios automatically:

```bash
# Start siphond in another terminal
cargo run -p siphond -- --bind 0.0.0.0:5060

# Run test suite
cd sip-testkit/sipp
./run_scenarios.sh 127.0.0.1 5060
```

Run extended scenarios:
```bash
# Enable optional feature tests
RUN_MESSAGE=1 RUN_INFO=1 RUN_UPDATE=1 RUN_PRACK=1 \
RUN_SUBSCRIBE=1 RUN_REFER=1 RUN_REINVITE=1 RUN_SESSION_TIMER=1 \
./run_scenarios.sh 127.0.0.1 5060
```

Run proxy-mode scenario:
```bash
# Start siphond in proxy mode on 5060
# Start a SIPp UAS on 5070 (callee)
sipp -sn uas -sf uas_invite.xml -i 127.0.0.1 -p 5070

# Run proxy scenario (targets 127.0.0.1:5070 via CSV)
RUN_PROXY=1 ./run_scenarios.sh 127.0.0.1 5060
```

### Manual Testing

Individual scenario testing:

```bash
# OPTIONS (basic connectivity)
sipp 127.0.0.1:5060 -sf options.xml -m 1 -trace_msg

# INVITE/ACK (basic call setup)
sipp 127.0.0.1:5060 -sf invite.xml -m 1 -trace_msg

# INVITE/ACK/BYE (complete call flow)
sipp 127.0.0.1:5060 -sf invite_bye.xml -m 1 -trace_msg

# REGISTER (user registration)
sipp 127.0.0.1:5060 -sf register.xml -m 1 -trace_msg -s alice

# MESSAGE (out-of-dialog)
sipp 127.0.0.1:5060 -sf message.xml -m 1 -trace_msg

# INFO (in-dialog)
sipp 127.0.0.1:5060 -sf info.xml -m 1 -trace_msg

# UPDATE (in-dialog)
sipp 127.0.0.1:5060 -sf update.xml -m 1 -trace_msg

# Re-INVITE (session refresh/update)
sipp 127.0.0.1:5060 -sf reinvite.xml -m 1 -trace_msg

# PRACK (reliable provisionals)
sipp 127.0.0.1:5060 -sf prack.xml -m 1 -trace_msg

# SUBSCRIBE/NOTIFY (presence)
sipp 127.0.0.1:5060 -sf subscribe_notify.xml -m 1 -trace_msg

# REFER (transfer + NOTIFY)
sipp 127.0.0.1:5060 -sf refer.xml -m 1 -trace_msg

# Session timers (requires --enable-session-timers on siphond)
sipp 127.0.0.1:5060 -sf session_timer.xml -m 1 -trace_msg

# Proxy-mode INVITE/BYE (target host/port set in proxy_target.csv)
sipp 127.0.0.1:5060 -sf proxy_invite_bye.xml -inf proxy_target.csv -m 1 -trace_msg

# CANCEL (call cancellation)
sipp 127.0.0.1:5060 -sf cancel.xml -m 1 -trace_msg

# UAS mode (receive calls)
sipp -sn uas 0.0.0.0:5060 -sf uas_invite.xml
```

## Scenarios

### UAC (Client) Scenarios
- **`options.xml`**: Sends OPTIONS request, expects 200 OK
- **`invite.xml`**: Basic INVITE → 200 → ACK flow with SDP
- **`invite_bye.xml`**: Complete call: INVITE → 200 → ACK → pause → BYE → 200
- **`register.xml`**: REGISTER request (optionally handles 401 challenge)
- **`cancel.xml`**: INVITE → CANCEL flow (tests mid-call cancellation)
- **`message.xml`**: MESSAGE request (out-of-dialog)
- **`info.xml`**: INFO mid-dialog signaling (DTMF relay body)
- **`update.xml`**: UPDATE mid-dialog with SDP
- **`reinvite.xml`**: Re-INVITE for session modification
- **`prack.xml`**: Reliable provisional flow (INVITE with 100rel + PRACK)
- **`subscribe_notify.xml`**: SUBSCRIBE with initial NOTIFY
- **`refer.xml`**: In-dialog REFER with NOTIFY progress
- **`session_timer.xml`**: INVITE with Session-Expires (RFC 4028)
- **`proxy_invite_bye.xml`**: Proxy-mode INVITE/BYE (target via CSV)

**Notes:**
- `prack.xml` requires the server to enable PRACK and honor `Supported: 100rel`.
- `refer.xml` requires REFER support and an established dialog.
- `session_timer.xml` requires the server to enable RFC 4028 session timers.
- `proxy_invite_bye.xml` requires a reachable callee at the CSV host/port.

### UAS (Server) Scenarios
- **`uas_invite.xml`**: Answers incoming INVITE with 100/180/200, handles ACK and BYE

## Advanced Usage

### Load Testing

Generate multiple concurrent calls:
```bash
# 100 calls at 10 calls/second
sipp 127.0.0.1:5060 -sf invite_bye.xml -m 100 -r 10 -rp 1000 -trace_err
```

### Custom Parameters

```bash
# Override service name
sipp 127.0.0.1:5060 -sf options.xml -m 1 -s bob@example.com

# Use TCP transport
sipp 127.0.0.1:5060 -sf options.xml -m 1 -t t1

# Increase verbosity
sipp 127.0.0.1:5060 -sf options.xml -m 1 -trace_msg -trace_screen
```

## Troubleshooting

- **Connection refused**: Ensure siphond is running and bound to correct address
- **Timeout errors**: Check firewall rules, especially for UDP
- **SDP parsing**: Some scenarios include SDP bodies; ensure Content-Length is correct
- **Logs**: Test runner saves logs to `/tmp/sipp_*.log`

## Testing Checklist

Comprehensive interop testing should cover:

- [x] OPTIONS (basic connectivity)
- [x] INVITE/ACK (call establishment)
- [x] INVITE/ACK/BYE (complete call flow)
- [x] REGISTER (user registration)
- [x] CANCEL (call cancellation)
- [ ] Re-INVITE (session refresh)
- [x] PRACK (reliable provisionals - RFC 3262)
- [x] UPDATE (session parameter update)
- [ ] Authentication (401/407 challenges)
- [ ] Multiple codecs in SDP
- [ ] IPv6 support
- [ ] TLS transport (SIPS)
- [x] Re-INVITE (session refresh/update)
- [x] Proxy-mode basic call via request routing
- [x] MESSAGE (out-of-dialog)
- [x] INFO (mid-dialog)
- [x] SUBSCRIBE/NOTIFY (presence)
- [x] REFER (transfer + NOTIFY)
- [x] Session timers (RFC 4028)

## Integration with CI

Add to `.github/workflows/ci.yml`:

```yaml
- name: Interop Tests
  run: |
    # Install SIPp
    sudo apt-get install -y sip-tester

    # Start siphond in background
    cargo run -p siphond -- --bind 0.0.0.0:5060 &
    SIPHOND_PID=$!
    sleep 2

    # Run scenarios
    cd sip-testkit/sipp
    ./run_scenarios.sh 127.0.0.1 5060

    # Cleanup
    kill $SIPHOND_PID
```
