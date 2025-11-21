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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "SIPp Interop Test Suite"
echo "========================================"
echo "Target: $TARGET_HOST:$TARGET_PORT"
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
if ! nc -z -w1 "$TARGET_HOST" "$TARGET_PORT" 2>/dev/null; then
    echo -e "${YELLOW}WARNING: Target $TARGET_HOST:$TARGET_PORT is not reachable${NC}"
    echo "Make sure your SIP server is running before proceeding."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
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

    echo -e "${YELLOW}Running: $scenario_name${NC}"
    TESTS_RUN=$((TESTS_RUN + 1))

    if sipp "$TARGET_HOST":"$TARGET_PORT" \
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
        &> "/tmp/sipp_${scenario_name}.log"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Log: /tmp/sipp_${scenario_name}.log"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
}

# Run scenarios
echo "Running basic scenarios..."
echo ""

run_scenario "options.xml" "OPTIONS" 1
run_scenario "invite.xml" "INVITE_ACK" 1
run_scenario "invite_bye.xml" "INVITE_BYE" 1
run_scenario "register.xml" "REGISTER" 1

# Optionally run CANCEL scenario (may not be implemented in basic servers)
if [[ "${RUN_CANCEL:-0}" == "1" ]]; then
    run_scenario "cancel.xml" "CANCEL" 1
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
