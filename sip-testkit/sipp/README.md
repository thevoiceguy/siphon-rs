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
- `RUN_ALL_EXTENDED=1` includes auth/transport/forking/route-set tests (see notes).
- `RUN_SDP_MULTICODEC=1` runs the multi-codec SDP scenario.
- `RUN_IPV6=1` runs IPv6 core scenarios (requires IPv6 listener).

Run full optional suite:
```bash
RUN_ALL=1 ./run_scenarios.sh 127.0.0.1 5060
```

Run extended suite (auth/transport/forking/route-set):
```bash
RUN_ALL_EXTENDED=1 AUTH_USER=alice AUTH_PASS=secret \
TLS_CERT=/path/to/client.crt TLS_KEY=/path/to/client.key \
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

# INVITE with multiple codecs
sipp -sf invite_multi_codec.xml -m 1 -trace_msg 127.0.0.1:5060

# PRACK (reliable provisionals)
sipp -sf prack.xml -m 1 -trace_msg 127.0.0.1:5060

# SUBSCRIBE/NOTIFY (presence)
sipp -sf subscribe_notify.xml -m 1 -trace_msg 127.0.0.1:5060

# REFER (transfer + NOTIFY)
sipp -sf refer.xml -inf refer_target.csv -m 1 -trace_msg 127.0.0.1:5060

# REFER fail (expect NOTIFY with failure)
sipp -sf refer_fail.xml -m 1 -trace_msg 127.0.0.1:5060

# Session timers (requires --enable-session-timers on siphond)
sipp -sf session_timer.xml -m 1 -trace_msg 127.0.0.1:5060

# Session timer refresh (mid-dialog UPDATE/INVITE)
sipp -sf session_timer_refresh.xml -m 1 -trace_msg 127.0.0.1:5060

# Authenticated REGISTER
sipp -sf auth_register.xml -m 1 -au alice -ap secret -trace_msg 127.0.0.1:5060

# Authenticated INVITE
sipp -sf auth_invite.xml -m 1 -au alice -ap secret -trace_msg 127.0.0.1:5060

# PRACK negative tests
sipp -sf prack_bad_rack.xml -m 1 -trace_msg 127.0.0.1:5060
sipp -sf prack_missing_rack.xml -m 1 -trace_msg 127.0.0.1:5060

# SUBSCRIBE lifecycle (refresh + terminate)
sipp -sf subscribe_lifecycle.xml -m 1 -trace_msg 127.0.0.1:5060

# Out-of-dialog INFO/UPDATE (expect 481/405)
sipp -sf info_out_of_dialog.xml -m 1 -trace_msg 127.0.0.1:5060
sipp -sf update_out_of_dialog.xml -m 1 -trace_msg 127.0.0.1:5060

# Registrar edge cases (wildcard + multiple contacts)
sipp -sf register_wildcard.xml -m 1 -trace_msg 127.0.0.1:5060
sipp -sf register_multiple.xml -m 1 -trace_msg 127.0.0.1:5060

# Route-set handling (requires Record-Route)
sipp -sf route_bye.xml -m 1 -trace_msg 127.0.0.1:5060

# Forking behavior (multiple provisional responses)
sipp -sf forking_invite.xml -m 1 -trace_msg 127.0.0.1:5060

# IPv6 core tests (requires IPv6 listener)
sipp -sf invite_bye_ipv6.xml -m 1 -i ::1 -trace_msg [::1]:5060

# Proxy-mode INVITE/BYE (target host/port set in proxy_target.csv)
sipp -sf proxy_invite_bye.xml -inf proxy_target.csv -m 1 -trace_msg 127.0.0.1:5060

# CANCEL (call cancellation)
sipp -sf cancel.xml -m 1 -trace_msg 127.0.0.1:5060

# Error handling scenarios
sipp -sf max_forwards_zero.xml -m 1 -trace_msg 127.0.0.1:5060  # Expects 483
sipp -sf malformed_sdp.xml -m 1 -trace_msg 127.0.0.1:5060      # Expects 488
sipp -sf unsupported_method.xml -m 1 -trace_msg 127.0.0.1:5060 # Expects 501

# UAS mode (receive calls)
sipp -sn uas -sf uas_invite.xml -i 0.0.0.0 -p 5060
```

## Scenarios

### UAC (Client) Scenarios
- **`options.xml`**: Sends OPTIONS request, expects 200 OK
- **`invite.xml`**: Basic INVITE → 200 → ACK flow with SDP
- **`invite_bye.xml`**: Complete call: INVITE → 200 → ACK → pause → BYE → 200
- **`invite_multi_codec.xml`**: INVITE with multiple codecs in SDP
- **`invite_bye_ipv6.xml`**: IPv6 INVITE/BYE with IP6 SDP
- **`register.xml`**: REGISTER request (optionally handles 401 challenge)
- **`register_wildcard.xml`**: REGISTER with wildcard contact (clear bindings)
- **`register_multiple.xml`**: REGISTER with multiple Contact bindings
- **`cancel.xml`**: INVITE → CANCEL flow (tests mid-call cancellation)
- **`message.xml`**: MESSAGE request (out-of-dialog)
- **`info.xml`**: INFO mid-dialog signaling (DTMF relay body)
- **`info_out_of_dialog.xml`**: INFO out-of-dialog (expects 481/405)
- **`update.xml`**: UPDATE mid-dialog with SDP
- **`update_out_of_dialog.xml`**: UPDATE out-of-dialog (expects 481/405)
- **`reinvite.xml`**: Re-INVITE for session modification
- **`prack.xml`**: Reliable provisional flow (INVITE with 100rel + PRACK)
- **`prack_bad_rack.xml`**: PRACK with mismatched RSeq/RAck (negative test)
- **`prack_missing_rack.xml`**: PRACK missing RAck (negative test)
- **`subscribe_notify.xml`**: SUBSCRIBE with initial NOTIFY
- **`subscribe_lifecycle.xml`**: SUBSCRIBE refresh + terminate sequence
- **`refer.xml`**: In-dialog REFER with NOTIFY progress (loops for 100ms waiting for optional NOTIFYs)
- **`refer_fail.xml`**: REFER with failing transfer (NOTIFY failure)
- **`refer_target.csv`**: CSV target for REFER transfer INVITE
- **`session_timer.xml`**: INVITE with Session-Expires (RFC 4028)
- **`session_timer_refresh.xml`**: Session-Expires refresh mid-dialog
- **`proxy_invite_bye.xml`**: Proxy-mode INVITE/BYE (target via CSV)
- **`auth_register.xml`**: REGISTER with 401 challenge + credentials
- **`auth_invite.xml`**: INVITE with 401/407 challenge + credentials
- **`route_bye.xml`**: Route-set (Record-Route) honored on ACK/BYE
- **`forking_invite.xml`**: Forking behavior (multiple provisional responses)
- **`max_forwards_zero.xml`**: Max-Forwards=0 error handling (expects 483 Too Many Hops)
- **`malformed_sdp.xml`**: Malformed/unsupported SDP (expects 488 Not Acceptable Here)
- **`unsupported_method.xml`**: Unknown SIP method (expects 501 Not Implemented)

**Notes:**
- `cancel.xml` expects 200 OK for CANCEL and 487 Request Terminated for the INVITE.
- `prack.xml` requires the server to enable PRACK and honor `Supported: 100rel`.
- `prack_bad_rack.xml` and `prack_missing_rack.xml` expect the server to reject invalid PRACKs (typically 481/400).
- `invite_multi_codec.xml` expects the server to accept multiple codecs in the SDP offer.
- `invite_bye_ipv6.xml` requires an IPv6 listener and a SIPp run bound to IPv6 (`-i ::1`).
- `refer.xml` requires REFER support and an established dialog. The scenario loops for up to 100ms to collect optional NOTIFY messages reporting transfer progress (RFC 3515).
- `refer.xml` uses `refer_target.csv` to set the transfer target host/port (CSV first line must be `SEQUENTIAL` or `RANDOM`).
- `refer_fail.xml` uses an invalid target and expects a failure NOTIFY.
- `session_timer.xml` requires the server to enable RFC 4028 session timers.
- `session_timer_refresh.xml` expects mid-dialog refresh handling (UPDATE or re-INVITE).
- `proxy_invite_bye.xml` requires a reachable callee at the CSV host/port (CSV first line must be `SEQUENTIAL` or `RANDOM`).
- `auth_register.xml` and `auth_invite.xml` require the server to issue 401/407 challenges and accept `AUTH_USER`/`AUTH_PASS`.
- `route_bye.xml` requires Record-Route support so SIPp can validate the route set.
- `forking_invite.xml` requires a proxy/UAS that forks and sends multiple provisional responses.
- `info_out_of_dialog.xml` and `update_out_of_dialog.xml` expect 481 Call/Transaction Does Not Exist (or equivalent).

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

Items marked [x] have scenarios in this suite; some require extra setup (auth, TLS, IPv6).

- [x] OPTIONS (basic connectivity)
- [x] INVITE/ACK (call establishment)
- [x] INVITE/ACK/BYE (complete call flow)
- [x] REGISTER (user registration)
- [x] CANCEL (call cancellation)
- [x] Re-INVITE (session refresh)
- [x] PRACK (reliable provisionals - RFC 3262)
- [x] PRACK negative (bad/missing RAck)
- [x] UPDATE (session parameter update)
- [x] Authentication (REGISTER/INVITE challenges)
- [x] Proxy-mode basic call via request routing
- [x] MESSAGE (out-of-dialog)
- [x] INFO (mid-dialog)
- [x] INFO out-of-dialog (negative)
- [x] SUBSCRIBE/NOTIFY (presence)
- [x] SUBSCRIBE lifecycle (refresh + terminate)
- [x] REFER (transfer + NOTIFY)
- [x] REFER failure
- [x] Session timers (RFC 4028)
- [x] Session timer refresh
- [x] Registrar edge cases (wildcard/multiple contacts)
- [x] Route-set handling (Record-Route)
- [x] Forking provisional responses
- [x] TCP transport (core tests)
- [x] TLS transport (core tests)
- [x] Multiple codecs in SDP
- [x] IPv6 support
- [x] Max-Forwards=0 handling (483 Too Many Hops)
- [x] Malformed SDP rejection (488 Not Acceptable Here)
- [x] Unsupported method rejection (501 Not Implemented)

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
