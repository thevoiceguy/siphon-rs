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
# Start siphond in another terminal (INVITE/REGISTER tests need full-uas or call-server)
cargo run -p siphond -- --mode full-uas --udp-bind 0.0.0.0:5060

# Run test suite
cd sip-testkit/sipp
./run_scenarios.sh 127.0.0.1 5060
```

Bind flag note:
- `--udp-bind` listens for SIP over UDP (default `0.0.0.0:5060`).
- `--tcp-bind` listens for SIP over TCP (default `0.0.0.0:5060`).
- `--sips-bind` listens for SIP over TLS (default `0.0.0.0:5061`), and requires `--tls-cert` and `--tls-key`.

SIPp ordering note:
- Some SIPp builds require options before the target host/port; examples below put `127.0.0.1:5060` at the end for compatibility.

Run extended scenarios:
```bash
# Enable optional feature tests
RUN_MESSAGE=1 RUN_INFO=1 RUN_UPDATE=1 RUN_PRACK=1 \
RUN_SUBSCRIBE=1 RUN_REFER=1 RUN_REINVITE=1 RUN_SESSION_TIMER=1 \
./run_scenarios.sh 127.0.0.1 5060
```

Runner controls:
- `PRECHECK_OPTIONS=1` runs an OPTIONS ping before each scenario (default: on).
- `PRECHECK_TIMEOUT_SEC=3` sets the OPTIONS preflight timeout in seconds.
- `SCENARIO_DELAY_MS=250` sleeps between scenarios (milliseconds, default: 250).
- `RUN_ALL=1` enables all optional scenarios in one go.

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
sipp -sf options.xml -m 1 -trace_msg 127.0.0.1:5060

# INVITE/ACK (basic call setup)
sipp -sf invite.xml -m 1 -trace_msg 127.0.0.1:5060

# INVITE/ACK/BYE (complete call flow)
sipp -sf invite_bye.xml -m 1 -trace_msg 127.0.0.1:5060

# REGISTER (user registration)
sipp -sf register.xml -m 1 -trace_msg -s alice 127.0.0.1:5060

# MESSAGE (out-of-dialog)
sipp -sf message.xml -m 1 -trace_msg 127.0.0.1:5060

# INFO (in-dialog)
sipp -sf info.xml -m 1 -trace_msg 127.0.0.1:5060

# UPDATE (in-dialog)
sipp -sf update.xml -m 1 -trace_msg 127.0.0.1:5060

# Re-INVITE (session refresh/update)
sipp -sf reinvite.xml -m 1 -trace_msg 127.0.0.1:5060

# PRACK (reliable provisionals)
sipp -sf prack.xml -m 1 -trace_msg 127.0.0.1:5060

# SUBSCRIBE/NOTIFY (presence)
sipp -sf subscribe_notify.xml -m 1 -trace_msg 127.0.0.1:5060

# REFER (transfer + NOTIFY)
sipp -sf refer.xml -inf refer_target.csv -m 1 -trace_msg 127.0.0.1:5060

# Session timers (requires --enable-session-timers on siphond)
sipp -sf session_timer.xml -m 1 -trace_msg 127.0.0.1:5060

# Proxy-mode INVITE/BYE (target host/port set in proxy_target.csv)
sipp -sf proxy_invite_bye.xml -inf proxy_target.csv -m 1 -trace_msg 127.0.0.1:5060

# CANCEL (call cancellation)
sipp -sf cancel.xml -m 1 -trace_msg 127.0.0.1:5060

# UAS mode (receive calls)
sipp -sn uas -sf uas_invite.xml -i 0.0.0.0 -p 5060
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
- **`refer.xml`**: In-dialog REFER with NOTIFY progress (loops for 100ms waiting for optional NOTIFYs)
- **`refer_target.csv`**: CSV target for REFER transfer INVITE
- **`session_timer.xml`**: INVITE with Session-Expires (RFC 4028)
- **`proxy_invite_bye.xml`**: Proxy-mode INVITE/BYE (target via CSV)

**Notes:**
- `cancel.xml` requires full CANCEL support (200 OK for CANCEL + 487 Request Terminated for INVITE). **Currently fails with siphond** - the server sends 200 OK for CANCEL but doesn't send 487 for the original INVITE.
- `prack.xml` requires the server to enable PRACK and honor `Supported: 100rel`.
- `refer.xml` requires REFER support and an established dialog. The scenario loops for up to 100ms to collect optional NOTIFY messages reporting transfer progress (RFC 3515).
- `refer.xml` uses `refer_target.csv` to set the transfer target host/port (CSV first line must be `SEQUENTIAL` or `RANDOM`).
- `session_timer.xml` requires the server to enable RFC 4028 session timers.
- `proxy_invite_bye.xml` requires a reachable callee at the CSV host/port (CSV first line must be `SEQUENTIAL` or `RANDOM`).

### UAS (Server) Scenarios
- **`uas_invite.xml`**: Answers incoming INVITE with 100/180/200, handles ACK and BYE

## Advanced Usage

### Load Testing

Generate multiple concurrent calls:
```bash
# 100 calls at 10 calls/second
sipp -sf invite_bye.xml -m 100 -r 10 -rp 1000 -trace_err 127.0.0.1:5060
```

### Custom Parameters

```bash
# Override service name
sipp -sf options.xml -m 1 -s bob@example.com 127.0.0.1:5060

# Use TCP transport
sipp -sf options.xml -m 1 -t t1 127.0.0.1:5060

# Increase verbosity
sipp -sf options.xml -m 1 -trace_msg -trace_screen 127.0.0.1:5060
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
