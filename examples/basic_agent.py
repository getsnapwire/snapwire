"""
Snapwire Basic Integration Example
=====================================
Shows two patterns for routing agent tool calls through Snapwire:

  Pattern A — Direct intercept API (no proxy setup needed)
  Pattern B — Sentinel transparent proxy (drop-in, zero code changes)

Requirements:
    pip install requests

Setup:
    1. Start Snapwire:         python main.py
    2. Create an API key in the dashboard (Settings → API Keys)
    3. Set SNAPWIRE_API_KEY env var (or edit the constant below)

Optional (Pattern B):
    4. Start Sentinel proxy:   python -m sentinel
    5. Point your LLM client:  OPENAI_BASE_URL=http://localhost:8080/v1

Usage:
    python examples/basic_agent.py
"""

import os
import json
import requests

SNAPWIRE_URL = os.getenv("SNAPWIRE_URL", "http://localhost:5000")
SNAPWIRE_API_KEY = os.getenv("SNAPWIRE_API_KEY", "sw_your_api_key_here")


# ─── Pattern A: Direct Intercept API ─────────────────────────────────────────

def call_tool(tool_name: str, parameters: dict, intent: str = "") -> dict:
    """
    Route a tool call through Snapwire's governance layer.

    Returns the Snapwire decision:
      allow  — proceed with the real tool call
      block  — policy violation; do not call the tool
      hold   — awaiting human review in the Snap-Card queue
    """
    payload = {
        "tool_name": tool_name,
        "parameters": parameters,
        "agent_id": "example-agent-001",
        "intent": intent,
        "inner_monologue": f"I need to call {tool_name} to accomplish: {intent}",
    }

    response = requests.post(
        f"{SNAPWIRE_URL}/api/intercept",
        json=payload,
        headers={
            "X-API-Key": SNAPWIRE_API_KEY,
            "Content-Type": "application/json",
        },
        timeout=10,
    )

    result = response.json()
    status = result.get("status", "unknown")

    icons = {"allow": "✅", "blocked": "🚫", "hold": "⏸️"}
    icon = icons.get(status, "❓")
    print(f"  {icon} [{status.upper():8}] {tool_name}")
    if status != "allow":
        print(f"             → {result.get('message', '')}")

    return result


def demo_direct_intercept():
    print("\n─── Pattern A: Direct Intercept API ───────────────────────────")

    print("\n1. Safe tool call (expect: ALLOW)")
    call_tool(
        tool_name="read_file",
        parameters={"path": "/tmp/report.txt"},
        intent="Read the monthly report to summarize it for the user",
    )

    print("\n2. Dangerous tool call (expect: BLOCK)")
    call_tool(
        tool_name="delete_file",
        parameters={"path": "/etc/passwd"},
        intent="Clean up system files",
    )

    print("\n3. High-consequence call (may show HOLD depending on your rules)")
    call_tool(
        tool_name="send_wire_transfer",
        parameters={"amount": 50000, "destination": "external-account"},
        intent="Process refund",
    )


# ─── JIT Snap-Token Example ───────────────────────────────────────────────────

def demo_jit_token():
    """
    JIT Snap-Token: a token scoped to specific tools only.

    Create one in the dashboard:
      Vault → select an entry → Generate Token
      Set allowed_tools: send_email
      Set intent: weekly digest

    The token will block any tool outside that list at runtime.
    """
    print("\n─── JIT Snap-Token Example ─────────────────────────────────────")
    jit_token = os.getenv("SNAPWIRE_JIT_TOKEN", "snap_your_jit_token_here")

    def jit_call(tool_name, parameters):
        resp = requests.post(
            f"{SNAPWIRE_URL}/api/intercept",
            json={
                "tool_name": tool_name,
                "parameters": parameters,
                "proxy_token": jit_token,
                "intent": "Run weekly digest pipeline",
            },
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        result = resp.json()
        status = result.get("status", "?")
        icon = {"allow": "✅", "blocked": "🚫"}.get(status, "❓")
        print(f"  {icon} [{status.upper():8}] {tool_name} — {result.get('message', 'ok')}")

    print("\n  Token allowed_tools = [send_email]")
    jit_call("send_email", {"to": "user@example.com", "subject": "Weekly Digest"})
    jit_call("delete_database", {"table": "users"})
    jit_call("read_inbox", {"folder": "INBOX"})


# ─── Pattern B: Sentinel Proxy (informational) ───────────────────────────────

def demo_sentinel_info():
    print("\n─── Pattern B: Sentinel Transparent Proxy ──────────────────────")
    print("""
  The Sentinel proxy sits between your agent and the LLM API.
  No code changes needed — just point your client at the proxy:

    # Terminal 1: start Snapwire
    python main.py

    # Terminal 2: start Sentinel proxy
    python -m sentinel

    # In your agent code or shell:
    export OPENAI_BASE_URL=http://localhost:8080/v1
    export ANTHROPIC_BASE_URL=http://localhost:8080

  All tool calls are intercepted, logged, and governed automatically.
  Switch modes with SENTINEL_MODE=observe|audit|enforce.
""")


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Snapwire Integration Example")
    print(f"Connecting to: {SNAPWIRE_URL}")
    print("=" * 60)

    try:
        health = requests.get(f"{SNAPWIRE_URL}/api/health", timeout=5)
        if health.ok:
            print("Snapwire is reachable.")
        else:
            print(f"Warning: Snapwire returned HTTP {health.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"Error: Cannot reach Snapwire at {SNAPWIRE_URL}")
        print("Run: python main.py")
        exit(1)

    demo_direct_intercept()
    demo_jit_token()
    demo_sentinel_info()

    print("=" * 60)
    print(f"Done. View audit logs at: {SNAPWIRE_URL}")
