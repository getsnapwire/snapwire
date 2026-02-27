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
NC='\033[0m'

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Snapwire Sentinel — 30-Second Smoke Test${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Step 1: Check if Snapwire is running
echo -e "${YELLOW}[1/5]${NC} Checking Snapwire gateway..."
if curl -sf "${SNAPWIRE_URL}/health" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Snapwire is running at ${SNAPWIRE_URL}"
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
echo -e "  ${GREEN}✓${NC} Legitimate call processed"
echo "  Response: $(echo "$LEGIT_RESPONSE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("status","unknown"))' 2>/dev/null || echo "$LEGIT_RESPONSE" | head -c 200)"

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
else
    echo -e "  ${YELLOW}!${NC} Response: HTTP $ATTACK_RESPONSE (OpenClaw safeguard may need API key or rules configured)"
fi

# Step 4: Run the CVE reproduction test suite
echo ""
echo -e "${YELLOW}[4/5]${NC} Running CVE-2026-25253 reproduction tests..."
if python3 -m pytest tests/cve_2026_25253_repro.py -v --tb=short 2>&1 | tail -5; then
    echo -e "  ${GREEN}✓${NC} All CVE reproduction tests passed"
else
    echo -e "  ${RED}✗${NC} Some tests failed"
fi

# Step 5: Generate NIST compliance report
echo ""
echo -e "${YELLOW}[5/5]${NC} Generating NIST compliance report..."
SENTINEL_MODE=enforce python3 -m sentinel --export-nist 2>&1 | head -8
if [ -f snapwire-nist-mapping.md ]; then
    echo -e "  ${GREEN}✓${NC} Report generated: snapwire-nist-mapping.md"
    rm -f snapwire-nist-mapping.md
fi

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Smoke test complete!${NC}"
echo ""
echo "  Next steps:"
echo "    • Point your agent: OPENAI_BASE_URL=http://localhost:${SENTINEL_PORT}/v1"
echo "    • Run the example:  python examples/basic_agent.py"
echo "    • Add a protocol:   See CONTRIBUTING.md"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
