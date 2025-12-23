#!/usr/bin/env bash
# SIPp Interop Test Runner
#
# This script runs various SIPp scenarios against a SIP server for interop testing.
# Usage: ./run_scenarios.sh <target_host> <target_port>
#
# Prerequisites:
# - SIPp must be installed (https://github.com/SIPp/sipp)
# - Target SIP server must be running

set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-5060}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

format_target() {
    local host="$1"
    local port="$2"
    if [[ "$host" == *:* && "$host" != \[*\] ]]; then
        echo "[$host]:$port"
    else
        echo "$host:$port"
    fi
}

DEFAULT_TARGET="$(format_target "$TARGET_HOST" "$TARGET_PORT")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "SIPp Interop Test Suite"
echo "========================================"
echo "Target: $DEFAULT_TARGET"
echo ""
echo "Server note:"
echo "  INVITE/REGISTER tests require siphond in full-uas, registrar, or call-server modes."
echo "  Example: cargo run -p siphond -- --mode full-uas --udp-bind $TARGET_HOST:$TARGET_PORT"
echo ""
echo "Optional flags:"
echo "  RUN_MESSAGE=1 RUN_INFO=1 RUN_UPDATE=1 RUN_PRACK=1 RUN_REINVITE=1"
echo "  RUN_SUBSCRIBE=1 RUN_REFER=1 RUN_SESSION_TIMER=1 RUN_CANCEL=1 RUN_PROXY=1"
echo "  RUN_SDP_MULTICODEC=1 RUN_IPV6=1 RUN_ERROR_HANDLING=1"
echo "Proxy vars:"
echo "  PROXY_TARGET_CSV=/path/to/proxy_target.csv"
echo "Refer vars:"
echo "  REFER_TARGET_CSV=/path/to/refer_target.csv"
echo "Auth vars:"
echo "  AUTH_USER=user AUTH_PASS=pass"
echo "Transport vars:"
echo "  TLS_CERT=/path/to/client.crt TLS_KEY=/path/to/client.key"
echo "  TLS_HOST=127.0.0.1 TLS_PORT=5061 TCP_PORT=5060"
echo "IPv6 vars:"
echo "  IPV6_HOST=::1 IPV6_PORT=5060"
echo "Runner vars:"
echo "  SCENARIO_DELAY_MS=250 PRECHECK_OPTIONS=1 PRECHECK_TIMEOUT_SEC=3"
echo "  REACHABILITY_TRANSPORT=any (tcp|udp|any), SKIP_REACHABILITY=1"
echo "  RUN_ALL=1 (enables all optional scenarios)"
echo "  RUN_ALL_EXTENDED=1 (includes auth/transport/forking/route-set tests)"
echo ""

# Check if SIPp is installed
if ! command -v sipp &> /dev/null; then
    echo -e "${RED}ERROR: SIPp not found. Please install SIPp first.${NC}"
    echo "  Ubuntu/Debian: sudo apt-get install sip-tester"
    echo "  macOS: brew install sipp"
    echo "  Or build from source: https://github.com/SIPp/sipp"
    exit 1
fi

# Check if target is reachable
check_reachability() {
    local host="$1"
    local port="$2"
    local transport="$3"
    local opts=()
    if [[ "$host" == *:* ]]; then
        opts+=("-6")
    fi
    case "$transport" in
        tcp)
            nc "${opts[@]}" -z -w1 "$host" "$port" 2>/dev/null
            return $?
            ;;
        udp)
            nc "${opts[@]}" -u -z -w1 "$host" "$port" 2>/dev/null
            return $?
            ;;
        any)
            if nc "${opts[@]}" -z -w1 "$host" "$port" 2>/dev/null; then
                return 0
            fi
            nc "${opts[@]}" -u -z -w1 "$host" "$port" 2>/dev/null
            return $?
            ;;
        *)
            return 1
            ;;
    esac
}

if [[ "${SKIP_REACHABILITY:-0}" != "1" ]]; then
    REACHABILITY_TRANSPORT="${REACHABILITY_TRANSPORT:-any}"
    if ! check_reachability "$TARGET_HOST" "$TARGET_PORT" "$REACHABILITY_TRANSPORT"; then
    echo -e "${YELLOW}WARNING: Target $TARGET_HOST:$TARGET_PORT is not reachable${NC}"
    echo "Make sure your SIP server is running before proceeding."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    fi
fi

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a single scenario
run_scenario() {
    local scenario_file="$1"
    local scenario_name="$2"
    local calls="${3:-1}"
    local service="${4:-test}"
    local extra_args=()
    if [[ $# -gt 4 ]]; then
        extra_args=("${@:5}")
    fi
    local target="${TARGET_OVERRIDE:-$DEFAULT_TARGET}"

    echo -e "${YELLOW}Running: $scenario_name${NC}"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ "${PRECHECK_OPTIONS:-1}" == "1" ]]; then
        echo "  Preflight: OPTIONS ping"
        PRECHECK_TIMEOUT_SEC="${PRECHECK_TIMEOUT_SEC:-3}"
        if ! sipp \
            -sf "$SCRIPT_DIR/options.xml" \
            -m 1 \
            -timeout "${PRECHECK_TIMEOUT_SEC}s" \
            -timeout_error \
            "$DEFAULT_TARGET" \
            &> "/tmp/sipp_${scenario_name}_preflight.log"; then
            echo -e "${RED}✗ FAILED (preflight)${NC}"
            echo "  Log: /tmp/sipp_${scenario_name}_preflight.log"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            echo ""
            return
        fi
    fi

    echo "  Command: sipp -sf $scenario_file -m $calls -s $service ${extra_args[*]} $target"
    echo "  Log: /tmp/sipp_${scenario_name}.log"

    if sipp \
        -sf "$SCRIPT_DIR/$scenario_file" \
        -m "$calls" \
        -s "$service" \
        -trace_msg \
        -trace_err \
        -timeout 10s \
        -timeout_error \
        -max_socket 100 \
        -r 1 \
        -rp 1000 \
        "${extra_args[@]}" \
        "$target" \
        &> "/tmp/sipp_${scenario_name}.log"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Log: /tmp/sipp_${scenario_name}.log"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""

    if [[ -n "${SCENARIO_DELAY_MS:-}" && "${SCENARIO_DELAY_MS}" != "0" ]]; then
        sleep "$(awk "BEGIN {print ${SCENARIO_DELAY_MS}/1000}")"
    fi
}

# Expand RUN_ALL into individual flags
if [[ "${RUN_ALL_EXTENDED:-0}" == "1" ]]; then
    RUN_ALL=1
    RUN_AUTH_REGISTER=1
    RUN_AUTH_INVITE=1
    RUN_TCP_CORE=1
    RUN_TLS_CORE=1
    RUN_FORKING=1
    RUN_ROUTE_SET=1
fi

if [[ "${RUN_ALL:-0}" == "1" ]]; then
    RUN_MESSAGE=1
    RUN_INFO=1
    RUN_UPDATE=1
    RUN_PRACK=1
    RUN_REINVITE=1
    RUN_SUBSCRIBE=1
    RUN_REFER=1
    RUN_SESSION_TIMER=1
    RUN_CANCEL=1
    RUN_PROXY=1
    RUN_SDP_MULTICODEC=1
    RUN_PRACK_BAD=1
    RUN_PRACK_MISSING=1
    RUN_REFER_FAIL=1
    RUN_SUBSCRIBE_LIFECYCLE=1
    RUN_SESSION_TIMER_REFRESH=1
    RUN_NEGATIVE_MID_DIALOG=1
    RUN_REGISTRAR_EDGE=1
    RUN_ERROR_HANDLING=1
fi

# Run scenarios
echo "Running basic scenarios..."
echo ""

run_scenario "options.xml" "OPTIONS" 1
run_scenario "invite.xml" "INVITE_ACK" 1
run_scenario "invite_bye.xml" "INVITE_BYE" 1
run_scenario "register.xml" "REGISTER" 1

# Extended scenarios (opt-in with env flags)
if [[ "${RUN_MESSAGE:-0}" == "1" ]]; then
    run_scenario "message.xml" "MESSAGE" 1
fi

if [[ "${RUN_INFO:-0}" == "1" ]]; then
    run_scenario "info.xml" "INFO" 1
fi

if [[ "${RUN_UPDATE:-0}" == "1" ]]; then
    run_scenario "update.xml" "UPDATE" 1
fi

if [[ "${RUN_PRACK:-0}" == "1" ]]; then
    run_scenario "prack.xml" "PRACK" 1
fi

if [[ "${RUN_PRACK_BAD:-0}" == "1" ]]; then
    run_scenario "prack_bad_rack.xml" "PRACK_BAD_RACK" 1
fi

if [[ "${RUN_PRACK_MISSING:-0}" == "1" ]]; then
    run_scenario "prack_missing_rack.xml" "PRACK_MISSING_RACK" 1
fi

if [[ "${RUN_SUBSCRIBE:-0}" == "1" ]]; then
    run_scenario "subscribe_notify.xml" "SUBSCRIBE_NOTIFY" 1
fi

if [[ "${RUN_SUBSCRIBE_LIFECYCLE:-0}" == "1" ]]; then
    run_scenario "subscribe_lifecycle.xml" "SUBSCRIBE_LIFECYCLE" 1
fi

if [[ "${RUN_REFER:-0}" == "1" ]]; then
    REFER_TARGET_CSV="${REFER_TARGET_CSV:-$SCRIPT_DIR/refer_target.csv}"
    run_scenario "refer.xml" "REFER" 1 "test" -inf "$REFER_TARGET_CSV"
fi

if [[ "${RUN_REFER_FAIL:-0}" == "1" ]]; then
    run_scenario "refer_fail.xml" "REFER_FAIL" 1
fi

if [[ "${RUN_REINVITE:-0}" == "1" ]]; then
    run_scenario "reinvite.xml" "REINVITE" 1
fi

if [[ "${RUN_SDP_MULTICODEC:-0}" == "1" ]]; then
    run_scenario "invite_multi_codec.xml" "INVITE_MULTI_CODEC" 1
fi

if [[ "${RUN_SESSION_TIMER:-0}" == "1" ]]; then
    run_scenario "session_timer.xml" "SESSION_TIMER" 1
fi

if [[ "${RUN_SESSION_TIMER_REFRESH:-0}" == "1" ]]; then
    run_scenario "session_timer_refresh.xml" "SESSION_TIMER_REFRESH" 1
fi

# Optionally run CANCEL scenario (may not be implemented in basic servers)
if [[ "${RUN_CANCEL:-0}" == "1" ]]; then
    run_scenario "cancel.xml" "CANCEL" 1
fi

if [[ "${RUN_PROXY:-0}" == "1" ]]; then
    PROXY_TARGET_CSV="${PROXY_TARGET_CSV:-$SCRIPT_DIR/proxy_target.csv}"
    run_scenario "proxy_invite_bye.xml" "PROXY_INVITE_BYE" 1 "callee" -inf "$PROXY_TARGET_CSV"
fi

if [[ "${RUN_NEGATIVE_MID_DIALOG:-0}" == "1" ]]; then
    run_scenario "info_out_of_dialog.xml" "INFO_OUT_OF_DIALOG" 1
    run_scenario "update_out_of_dialog.xml" "UPDATE_OUT_OF_DIALOG" 1
fi

if [[ "${RUN_REGISTRAR_EDGE:-0}" == "1" ]]; then
    run_scenario "register_wildcard.xml" "REGISTER_WILDCARD" 1
    run_scenario "register_multiple.xml" "REGISTER_MULTIPLE" 1
fi

if [[ "${RUN_AUTH_REGISTER:-0}" == "1" ]]; then
    AUTH_USER="${AUTH_USER:-user}"
    AUTH_PASS="${AUTH_PASS:-pass}"
    run_scenario "auth_register.xml" "AUTH_REGISTER" 1 "test" -au "$AUTH_USER" -ap "$AUTH_PASS"
fi

if [[ "${RUN_AUTH_INVITE:-0}" == "1" ]]; then
    AUTH_USER="${AUTH_USER:-user}"
    AUTH_PASS="${AUTH_PASS:-pass}"
    run_scenario "auth_invite.xml" "AUTH_INVITE" 1 "test" -au "$AUTH_USER" -ap "$AUTH_PASS"
fi

if [[ "${RUN_TCP_CORE:-0}" == "1" ]]; then
    TCP_PORT="${TCP_PORT:-$TARGET_PORT}"
    TARGET_OVERRIDE="$TARGET_HOST:$TCP_PORT" run_scenario "options.xml" "OPTIONS_TCP" 1 "test" -t t1
    TARGET_OVERRIDE="$TARGET_HOST:$TCP_PORT" run_scenario "invite_bye.xml" "INVITE_BYE_TCP" 1 "test" -t t1
    TARGET_OVERRIDE="$TARGET_HOST:$TCP_PORT" run_scenario "register.xml" "REGISTER_TCP" 1 "test" -t t1
fi

if [[ "${RUN_TLS_CORE:-0}" == "1" ]]; then
    TLS_HOST="${TLS_HOST:-$TARGET_HOST}"
    TLS_PORT="${TLS_PORT:-5061}"
    TLS_CERT="${TLS_CERT:-}"
    TLS_KEY="${TLS_KEY:-}"
    TLS_ARGS=("-t" "l1")
    if [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]]; then
        TLS_ARGS+=("-tls_cert" "$TLS_CERT" "-tls_key" "$TLS_KEY")
    fi
    TARGET_OVERRIDE="$TLS_HOST:$TLS_PORT" run_scenario "options.xml" "OPTIONS_TLS" 1 "test" "${TLS_ARGS[@]}"
    TARGET_OVERRIDE="$TLS_HOST:$TLS_PORT" run_scenario "invite_bye.xml" "INVITE_BYE_TLS" 1 "test" "${TLS_ARGS[@]}"
    TARGET_OVERRIDE="$TLS_HOST:$TLS_PORT" run_scenario "register.xml" "REGISTER_TLS" 1 "test" "${TLS_ARGS[@]}"
fi

if [[ "${RUN_ROUTE_SET:-0}" == "1" ]]; then
    run_scenario "route_bye.xml" "ROUTE_BYE" 1
fi

if [[ "${RUN_FORKING:-0}" == "1" ]]; then
    run_scenario "forking_invite.xml" "FORKING_INVITE" 1
fi

if [[ "${RUN_IPV6:-0}" == "1" ]]; then
    IPV6_HOST="${IPV6_HOST:-::1}"
    IPV6_PORT="${IPV6_PORT:-$TARGET_PORT}"
    IPV6_TARGET="[$IPV6_HOST]:$IPV6_PORT"
    TARGET_OVERRIDE="$IPV6_TARGET" run_scenario "options.xml" "OPTIONS_IPV6" 1 "test" -i "$IPV6_HOST"
    TARGET_OVERRIDE="$IPV6_TARGET" run_scenario "invite_bye_ipv6.xml" "INVITE_BYE_IPV6" 1 "test" -i "$IPV6_HOST"
    TARGET_OVERRIDE="$IPV6_TARGET" run_scenario "register.xml" "REGISTER_IPV6" 1 "test" -i "$IPV6_HOST"
fi

if [[ "${RUN_ERROR_HANDLING:-0}" == "1" ]]; then
    run_scenario "max_forwards_zero.xml" "MAX_FORWARDS_ZERO" 1
    run_scenario "malformed_sdp.xml" "MALFORMED_SDP" 1
    run_scenario "unsupported_method.xml" "UNSUPPORTED_METHOD" 1
fi

# Max-Forwards decrement validation (requires proxy mode)
# Note: These tests validate RFC 3261 §8.1.1.6 decrement behavior
# Run with: cargo run -p siphond -- --mode proxy --udp-bind 127.0.0.1:5060
if [[ "${RUN_MAX_FORWARDS_DECREMENT:-0}" == "1" ]]; then
    run_scenario "max_forwards_decrement.xml" "MAX_FORWARDS_DECREMENT" 1
    run_scenario "max_forwards_edge_case.xml" "MAX_FORWARDS_EDGE_CASE" 1
fi

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Total:  $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
else
    echo -e "Failed: $TESTS_FAILED"
fi
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check logs in /tmp/sipp_*.log${NC}"
    exit 1
fi
