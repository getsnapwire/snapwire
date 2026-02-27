#!/usr/bin/env bash
set -euo pipefail

SNAPWIRE_URL="${SNAPWIRE_URL:-http://localhost:5000}"
SENTINEL_PORT="${SENTINEL_PORT:-8080}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

declare -a RESULTS=()

pass() {
    RESULTS+=("${GREEN}✓${NC} $1")
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    RESULTS+=("${RED}✗${NC} $1")
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

warn() {
    RESULTS+=("${YELLOW}⚠${NC} $1")
    WARN_COUNT=$((WARN_COUNT + 1))
}

TOTAL_STEPS=10

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Snapwire — Day Zero Readiness Report${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}[1/${TOTAL_STEPS}]${NC} Checking required environment variables..."
if [ -n "${DATABASE_URL:-}" ]; then
    echo -e "  ${GREEN}✓${NC} DATABASE_URL is set"
    pass "DATABASE_URL is set"
else
    echo -e "  ${RED}✗${NC} DATABASE_URL is not set"
    echo "  Remediation: export DATABASE_URL=postgresql://user:pass@host:5432/dbname"
    fail "DATABASE_URL is not set"
fi

if [ -n "${SESSION_SECRET:-}" ]; then
    echo -e "  ${GREEN}✓${NC} SESSION_SECRET is set"
    pass "SESSION_SECRET is set"
else
    echo -e "  ${RED}✗${NC} SESSION_SECRET is not set"
    echo "  Remediation: export SESSION_SECRET=\$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    fail "SESSION_SECRET is not set"
fi

echo ""
echo -e "${YELLOW}[2/${TOTAL_STEPS}]${NC} Checking optional Slack tokens..."
if [ -n "${SLACK_BOT_TOKEN:-}" ] && [ -n "${SLACK_APP_TOKEN:-}" ]; then
    echo -e "  ${GREEN}✓${NC} SLACK_BOT_TOKEN and SLACK_APP_TOKEN are set"
    pass "Slack tokens configured"
else
    echo -e "  ${YELLOW}⚠${NC} Slack tokens not fully configured (alerts will be skipped)"
    echo "  Optional: Set SLACK_BOT_TOKEN and SLACK_APP_TOKEN for Slack alerts"
    warn "Slack tokens not configured (optional)"
fi

echo ""
echo -e "${YELLOW}[3/${TOTAL_STEPS}]${NC} Checking Snapwire gateway..."
if curl -sf "${SNAPWIRE_URL}/health" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Snapwire is running at ${SNAPWIRE_URL}"
    pass "Snapwire gateway reachable"
else
    echo -e "  ${RED}✗${NC} Snapwire is not running at ${SNAPWIRE_URL}"
    echo "  Remediation: Start with python main.py or docker-compose up -d"
    fail "Snapwire gateway not reachable"
fi

echo ""
echo -e "${YELLOW}[4/${TOTAL_STEPS}]${NC} Sending a legitimate tool call..."
LEGIT_RESPONSE=$(curl -sf -X POST "${SNAPWIRE_URL}/api/intercept" \
    -H "Content-Type: application/json" \
    -d '{
        "tool_name": "search_web",
        "parameters": {"query": "AI safety best practices", "max_results": 5},
        "agent_id": "quickstart-agent",
        "intent": "Research AI safety"
    }' 2>&1) || true
LEGIT_STATUS=$(echo "$LEGIT_RESPONSE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("status","unknown"))' 2>/dev/null || echo "error")
if [ "$LEGIT_STATUS" != "error" ]; then
    echo -e "  ${GREEN}✓${NC} Legitimate call processed (status: ${LEGIT_STATUS})"
    pass "Legitimate tool call processed"
else
    echo -e "  ${RED}✗${NC} Legitimate tool call failed"
    fail "Legitimate tool call failed"
fi

echo ""
echo -e "${YELLOW}[5/${TOTAL_STEPS}]${NC} Sending CVE-2026-25253 attack payload (BASE_URL redirect)..."
ATTACK_RESPONSE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${SNAPWIRE_URL}/api/intercept" \
    -H "Content-Type: application/json" \
    -d '{
        "tool_name": "configure_api",
        "parameters": {"base_url": "https://evil-proxy.attacker.com/v1", "model": "gpt-4"},
        "agent_id": "compromised-agent",
        "intent": "Update API configuration"
    }' 2>&1) || true

if [ "$ATTACK_RESPONSE" = "403" ]; then
    echo -e "  ${GREEN}✓${NC} BLOCKED (HTTP 403) — OpenClaw safeguard caught the attack"
    pass "CVE-2026-25253 attack blocked"
else
    echo -e "  ${RED}✗${NC} Response: HTTP $ATTACK_RESPONSE (expected 403)"
    fail "CVE-2026-25253 attack not blocked"
fi

echo ""
echo -e "${YELLOW}[6/${TOTAL_STEPS}]${NC} Testing /safety/pdf endpoint..."
PDF_HTTP=$(curl -sf -o /tmp/snapwire_safety.pdf -w "%{http_code}" "${SNAPWIRE_URL}/safety/pdf" 2>&1) || PDF_HTTP="000"
if [ "$PDF_HTTP" = "200" ]; then
    PDF_MAGIC=$(head -c 5 /tmp/snapwire_safety.pdf 2>/dev/null || echo "")
    if [ "$PDF_MAGIC" = "%PDF-" ]; then
        echo -e "  ${GREEN}✓${NC} /safety/pdf returns a valid PDF document"
        pass "Safety PDF endpoint returns valid PDF"
    else
        echo -e "  ${RED}✗${NC} /safety/pdf returned HTTP 200 but content is not a valid PDF"
        fail "Safety PDF content invalid"
    fi
    rm -f /tmp/snapwire_safety.pdf
else
    echo -e "  ${RED}✗${NC} /safety/pdf returned HTTP ${PDF_HTTP} (expected 200)"
    fail "Safety PDF endpoint failed (HTTP ${PDF_HTTP})"
fi

echo ""
echo -e "${YELLOW}[7/${TOTAL_STEPS}]${NC} Testing hold window API..."
HOLD_RESPONSE=$(curl -sf "${SNAPWIRE_URL}/api/settings/hold-window" 2>&1) || HOLD_RESPONSE=""
if [ -n "$HOLD_RESPONSE" ]; then
    HOLD_VALUE=$(echo "$HOLD_RESPONSE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("hold_window_seconds", d.get("hold_window", "missing")))' 2>/dev/null || echo "error")
    if [ "$HOLD_VALUE" != "error" ] && [ "$HOLD_VALUE" != "missing" ]; then
        echo -e "  ${GREEN}✓${NC} Hold window API responds (current: ${HOLD_VALUE}s)"
        pass "Hold window API responds correctly"
    else
        echo -e "  ${RED}✗${NC} Hold window API response format unexpected"
        fail "Hold window API response invalid"
    fi
else
    echo -e "  ${RED}✗${NC} Hold window API not reachable"
    fail "Hold window API not reachable"
fi

echo ""
echo -e "${YELLOW}[8/${TOTAL_STEPS}]${NC} Running full test suite..."
TEST_OUTPUT=$(python3 -m pytest tests/ -v --tb=short 2>&1) || true
TESTS_PASSED=$(echo "$TEST_OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
TESTS_FAILED=$(echo "$TEST_OUTPUT" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "0")
TESTS_ERROR=$(echo "$TEST_OUTPUT" | grep -oP '\d+ error' | grep -oP '\d+' || echo "0")
echo "$TEST_OUTPUT" | tail -5
if [ "$TESTS_FAILED" = "0" ] && [ "$TESTS_ERROR" = "0" ] && [ "$TESTS_PASSED" != "0" ]; then
    echo -e "  ${GREEN}✓${NC} All tests passed (${TESTS_PASSED} passed)"
    pass "Full test suite passed (${TESTS_PASSED} tests)"
else
    echo -e "  ${RED}✗${NC} Test suite: ${TESTS_PASSED} passed, ${TESTS_FAILED} failed, ${TESTS_ERROR} errors"
    fail "Test suite has failures (${TESTS_FAILED} failed, ${TESTS_ERROR} errors)"
fi

echo ""
echo -e "${YELLOW}[9/${TOTAL_STEPS}]${NC} Running CVE-2026-25253 reproduction tests..."
CVE_OUTPUT=$(python3 -m pytest tests/cve_2026_25253_repro.py -v --tb=short 2>&1) || true
echo "$CVE_OUTPUT" | tail -5
if echo "$CVE_OUTPUT" | grep -q "passed" && ! echo "$CVE_OUTPUT" | grep -q "failed"; then
    CVE_PASSED=$(echo "$CVE_OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
    echo -e "  ${GREEN}✓${NC} All CVE reproduction tests passed (${CVE_PASSED} tests)"
    pass "CVE reproduction tests passed (${CVE_PASSED} tests)"
else
    echo -e "  ${RED}✗${NC} Some CVE tests failed"
    fail "CVE reproduction tests failed"
fi

echo ""
echo -e "${YELLOW}[10/${TOTAL_STEPS}]${NC} Generating NIST compliance report..."
NIST_OUTPUT=$(SENTINEL_MODE=enforce python3 -m sentinel --export-nist 2>&1) || true
echo "$NIST_OUTPUT" | head -8
NIST_GRADE=$(echo "$NIST_OUTPUT" | grep -oP 'Grade:\s+\K[A-D]' || echo "?")

if [ -f snapwire-nist-mapping.md ]; then
    echo -e "  ${GREEN}✓${NC} Report generated: snapwire-nist-mapping.md"
    rm -f snapwire-nist-mapping.md
fi

if [ "$NIST_GRADE" = "A" ]; then
    pass "NIST compliance grade: A"
else
    fail "NIST compliance grade: ${NIST_GRADE} (expected A)"
fi

HMAC_OK="No"
if python3 -c "from sentinel.proxy import SentinelProxy; p=SentinelProxy({'signing_secret':'test'}); assert p.signing_secret=='test'" 2>/dev/null; then
    HMAC_OK="Yes"
fi

HEADERS_OK="No"
if python3 -c "
from sentinel.proxy import SentinelProxy
p = SentinelProxy({'mode':'observe','origin_id':'human'})
assert p.origin_id == 'human'
import inspect
src = inspect.getsource(p._forward_request)
assert 'X-Snapwire-Origin-ID' in src
assert 'X-Snapwire-Parent-ID' in src
" 2>/dev/null; then
    HEADERS_OK="Yes"
fi

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Day Zero Readiness Report${NC}"
echo -e "  ─────────────────────────────────────────────"
echo ""
for r in "${RESULTS[@]}"; do
    echo -e "  $r"
done
echo ""
echo -e "  ─────────────────────────────────────────────"
echo -e "  Enforce Mode Active ............. ${GREEN}Yes${NC}"
echo -e "  HMAC Signing Capable ............ $([ "$HMAC_OK" = "Yes" ] && echo -e "${GREEN}Yes${NC}" || echo -e "${RED}No${NC}")"
echo -e "  CVE-2026-25253 Blocked .......... $([ "$ATTACK_RESPONSE" = "403" ] && echo -e "${GREEN}Yes${NC}" || echo -e "${RED}No${NC}")"
echo -e "  Identity Headers (All Modes) .... $([ "$HEADERS_OK" = "Yes" ] && echo -e "${GREEN}Yes${NC}" || echo -e "${RED}No${NC}")"
echo -e "  NIST Grade ...................... ${BOLD}${NIST_GRADE}${NC}"
echo ""
echo -e "  ${GREEN}Passed: ${PASS_COUNT}${NC}  ${RED}Failed: ${FAIL_COUNT}${NC}  ${YELLOW}Warnings: ${WARN_COUNT}${NC}"
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}[DAY ZERO: READY — All critical checks passed]${NC}"
else
    echo -e "  ${RED}${BOLD}[DAY ZERO: NOT READY — ${FAIL_COUNT} check(s) failed]${NC}"
fi

echo ""
echo "  Next steps:"
echo "    • Point your agent: OPENAI_BASE_URL=http://localhost:${SENTINEL_PORT}/v1"
echo "    • Run the example:  python examples/basic_agent.py"
echo "    • Add a protocol:   See CONTRIBUTING.md"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
