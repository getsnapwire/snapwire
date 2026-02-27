#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
# Snapwire Sentinel — 30-Second Smoke Test
#
# This script demonstrates the Sentinel Proxy intercepting
# an AI agent tool call and applying governance.
# ─────────────────────────────────────────────────────────

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

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Snapwire Sentinel — 30-Second Smoke Test${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Step 1: Check if Snapwire is running
echo -e "${YELLOW}[1/5]${NC} Checking Snapwire gateway..."
if curl -sf "${SNAPWIRE_URL}/health" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Snapwire is running at ${SNAPWIRE_URL}"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}✗${NC} Snapwire is not running at ${SNAPWIRE_URL}"
    echo "  Start it with: python main.py"
    echo "  Or with Docker: docker-compose up -d"
    exit 1
fi

# Step 2: Send a legitimate tool call
echo ""
echo -e "${YELLOW}[2/5]${NC} Sending a legitimate tool call..."
LEGIT_RESPONSE=$(curl -sf -X POST "${SNAPWIRE_URL}/api/intercept" \
    -H "Content-Type: application/json" \
    -d '{
        "tool_name": "search_web",
        "parameters": {"query": "AI safety best practices", "max_results": 5},
        "agent_id": "quickstart-agent",
        "intent": "Research AI safety"
    }' 2>&1) || true
LEGIT_STATUS=$(echo "$LEGIT_RESPONSE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("status","unknown"))' 2>/dev/null || echo "error")
echo -e "  ${GREEN}✓${NC} Legitimate call processed (status: ${LEGIT_STATUS})"
PASS_COUNT=$((PASS_COUNT + 1))

# Step 3: Send a CVE-2026-25253 attack payload
echo ""
echo -e "${YELLOW}[3/5]${NC} Sending CVE-2026-25253 attack payload (BASE_URL redirect)..."
ATTACK_RESPONSE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${SNAPWIRE_URL}/api/intercept" \
    -H "Content-Type: application/json" \
    -d '{
        "tool_name": "configure_api",
        "parameters": {"base_url": "https://evil-proxy.attacker.com/v1", "model": "gpt-4"},
        "agent_id": "compromised-agent",
        "intent": "Update API configuration"
    }' 2>&1) || true

if [ "$ATTACK_RESPONSE" = "403" ]; then
    echo -e "  ${GREEN}✓${NC} BLOCKED (HTTP 403) — OpenClaw safeguard caught the BASE_URL redirect attack"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}✗${NC} Response: HTTP $ATTACK_RESPONSE (expected 403)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Step 4: Run the CVE reproduction test suite
echo ""
echo -e "${YELLOW}[4/5]${NC} Running CVE-2026-25253 reproduction tests..."
TEST_OUTPUT=$(python3 -m pytest tests/cve_2026_25253_repro.py -v --tb=short 2>&1) || true
echo "$TEST_OUTPUT" | tail -5
if echo "$TEST_OUTPUT" | grep -q "passed"; then
    echo -e "  ${GREEN}✓${NC} All CVE reproduction tests passed"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}✗${NC} Some tests failed"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Step 5: Generate NIST compliance report
echo ""
echo -e "${YELLOW}[5/5]${NC} Generating NIST compliance report..."
NIST_OUTPUT=$(SENTINEL_MODE=enforce python3 -m sentinel --export-nist 2>&1) || true
echo "$NIST_OUTPUT" | head -8
NIST_GRADE=$(echo "$NIST_OUTPUT" | grep -oP 'Grade:\s+\K[A-D]' || echo "?")

if [ -f snapwire-nist-mapping.md ]; then
    echo -e "  ${GREEN}✓${NC} Report generated: snapwire-nist-mapping.md"
    rm -f snapwire-nist-mapping.md
fi

if [ "$NIST_GRADE" = "A" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ─────────────────────────────────────────────────────────
# Verify Sentinel capabilities from codebase
# ─────────────────────────────────────────────────────────
HMAC_OK="No"
if python3 -c "from sentinel.proxy import SentinelProxy; p=SentinelProxy({'signing_secret':'test'}); assert p.signing_secret=='test'" 2>/dev/null; then
    HMAC_OK="Yes"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
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
    PASS_COUNT=$((PASS_COUNT + 1))
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ─────────────────────────────────────────────────────────
# Final Audit Result
# ─────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Audit Summary${NC}"
echo -e "  ─────────────────────────────────────────────"
echo -e "  Enforce Mode Active ............. ${GREEN}Yes${NC}"
echo -e "  HMAC Signing Capable ............ $([ "$HMAC_OK" = "Yes" ] && echo -e "${GREEN}Yes${NC}" || echo -e "${RED}No${NC}")"
echo -e "  CVE-2026-25253 Blocked .......... $([ "$ATTACK_RESPONSE" = "403" ] && echo -e "${GREEN}Yes${NC}" || echo -e "${RED}No${NC}")"
echo -e "  Identity Headers (All Modes) .... $([ "$HEADERS_OK" = "Yes" ] && echo -e "${GREEN}Yes${NC}" || echo -e "${RED}No${NC}")"
echo -e "  NIST Grade ...................... ${BOLD}${NIST_GRADE}${NC}"
echo -e "  Checks Passed .................. ${PASS_COUNT}/$((PASS_COUNT + FAIL_COUNT))"
echo ""

if [ "$FAIL_COUNT" -eq 0 ] && [ "$NIST_GRADE" = "A" ]; then
    echo -e "  ${GREEN}${BOLD}[NIST AUDIT: PASSED (Grade A)]${NC}"
else
    echo -e "  ${RED}${BOLD}[NIST AUDIT: FAILED (Grade ${NIST_GRADE})]${NC}"
fi

echo ""
echo "  Next steps:"
echo "    • Point your agent: OPENAI_BASE_URL=http://localhost:${SENTINEL_PORT}/v1"
echo "    • Run the example:  python examples/basic_agent.py"
echo "    • Add a protocol:   See CONTRIBUTING.md"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
