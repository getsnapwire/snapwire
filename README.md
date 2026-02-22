<p align="center">
  <img src="static/badge-snapwire.svg" alt="Protected by Snapwire" />
</p>

<h1 align="center">Snapwire</h1>
<p align="center"><strong>The Safety Fuse for Your AI Agents</strong></p>

<p align="center">
  Real-time spend monitoring, deterministic loop detection, and credential proxy for autonomous AI agents.<br/>
  Designed to detect and intercept loops based on user-defined velocity limits.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#how-snapwire-compares">Compare</a> &middot;
  <a href="#audit-cli">Audit CLI</a> &middot;
  <a href="#custom-rules">Custom Rules</a> &middot;
  <a href="#api">API</a> &middot;
  <a href="#compliance-readiness">Compliance</a> &middot;
  <a href="#self-hosting">Self-Hosting</a> &middot;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## What Snapwire Does

Snapwire sits between your AI agents and the tools they call. Before any agent can send an email, modify a file, call an API, or take any action, Snapwire intercepts the call, checks it against your rules, and either approves it automatically or holds it for your review.

**Deterministic features (no AI involved):**
- **Fuse Breaker** — Detects hallucination loops (same tool + same args 3x in 30s) and auto-blocks. No more $200 "thinking" loops while you sleep.
- **Live Burn Meter** — Real-time cost tracking with daily burn rate and 30-day spend projections.
- **Snap-Tokens** — Proxy tokens (`snap_` prefixed) replace raw API keys. Agents never see real credentials. One-click revocation.
- **The Snap** — Emergency kill-switch. Revoke all active Snap-Tokens with one click.
- **Schema Validation Guard** — Per-tool JSON schema enforcement with strict/flexible modes.
- **Snap-Card Review Queue** — Blocked actions shown as structured cards with Reject, Edit & Release, and Trust 24h actions.

**Heuristic features (AI-powered, advisory only):**
- **Goal Drift Alerts** — Flags behavioral shifts in agent reasoning for human review. Outputs are advisory signals, not guarantees.
- **Automation Rules** — LLM-powered evaluation of tool calls against custom natural-language rules.

> All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator.

---

## Quick Start

### Option 1: Docker (recommended for self-hosting)

```bash
git clone https://github.com/snapwire-ai/snapwire.git
cd snapwire
cp .env.example .env
# Edit .env with your settings
docker build -t snapwire .
docker run -p 5000:5000 --env-file .env snapwire
```

### Option 2: Run directly

```bash
git clone https://github.com/snapwire-ai/snapwire.git
cd snapwire
pip install .
cp .env.example .env
# Edit .env with your settings
python main.py
```

Visit `http://localhost:5000` — the setup wizard will guide you through first-run configuration.

### Option 3: Python SDK

```bash
pip install snapwire
```

```python
from agentic_firewall import AgenticFirewall

fw = AgenticFirewall(base_url="http://localhost:5000", api_key="your-api-key")

result = fw.intercept(
    tool_name="send_email",
    parameters={"to": "user@example.com", "body": "Hello"},
    intent="Sending welcome email to new user",
    agent_id="onboarding-agent"
)

if result["action"] == "allow":
    pass  # proceed with the tool call
elif result["action"] == "block":
    print(f"Blocked: {result['reason']}")
elif result["action"] == "pending":
    print("Held for human review")
```

---

## Audit CLI

Scan your existing agent logs for recursive loops and estimate wasted spend — no server required.

```bash
python snapwire_audit.py --file your_logs.json
```

```
============================================================
  SNAPWIRE AUDIT REPORT
============================================================
  File:           your_logs.json
  Total calls:    156
  Loops found:    3
============================================================

  LOOP #1
    Agent:      research-agent
    Tool:       web_search
    Repeats:    5x in 30s
    Wasted:     4 redundant call(s)
    Est. cost:  $0.12
============================================================
  TOTAL WASTED CALLS:    11
  ESTIMATED BURN:        $0.33
============================================================
```

Options:
- `--cost 0.03` — Set estimated cost per call (default: $0.01)
- `--window 60` — Detection window in seconds (default: 30)
- `--threshold 5` — Minimum repeats to flag (default: 3)
- `--json` — Output as JSON for pipeline integration

Try it with the included sample: `python snapwire_audit.py --file examples/sample_logs.json`

**Log format** — JSON array with `timestamp`, `tool_name`, `parameters`, and optional `agent_id`:

```json
[
  {
    "timestamp": "2026-02-21T10:00:01Z",
    "tool_name": "web_search",
    "parameters": {"query": "latest news"},
    "agent_id": "my-agent"
  }
]
```

---

## Custom Rules

Snapwire ships with rule stubs in the `/rules/` directory. Each follows a consistent `evaluate()` interface so you can fork, customize, and contribute your own.

| Rule | Status | Description |
|------|--------|-------------|
| `env_protection.py` | Implemented | Blocks access to env vars, `.env` files, and secret paths |
| `budget_cap.py` | Stub | Per-session dollar limit on estimated agent spend |
| `block_pii.py` | Stub | Detects and blocks PII patterns in tool parameters |
| `crypto_lock.py` | Stub | Prevents agents from signing transactions or moving funds |
| `domain_allowlist.py` | Stub | Restricts outbound requests to approved domains |

### Writing your own rule

```python
"""
Rule: My Custom Rule
Status: IMPLEMENTED
"""

def evaluate(tool_call):
    """
    Args:
        tool_call: dict with 'tool_name', 'parameters', 'intent', 'agent_id'

    Returns:
        dict with 'allowed' (bool), 'reason' (str), 'risk_level' (str)
    """
    if some_condition(tool_call):
        return {
            "allowed": False,
            "reason": "Blocked by my custom rule",
            "risk_level": "high"
        }
    return {"allowed": True, "reason": "Passed", "risk_level": "low"}
```

Fork the repo, add your rule to `/rules/`, and submit a PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## API

### Intercept a tool call

```bash
curl -X POST http://localhost:5000/api/intercept \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "tool_name": "send_email",
    "parameters": {"to": "user@example.com", "body": "Hello world"},
    "intent": "Sending a welcome email",
    "agent_id": "onboarding-agent"
  }'
```

**Response (allowed):**
```json
{
  "action": "allow",
  "tool_name": "send_email",
  "reasoning": "Tool call passes all active rules"
}
```

**Response (blocked):**
```json
{
  "action": "block",
  "tool_name": "send_email",
  "reasoning": "Blocked by budget_cap rule: session spend exceeds $50 limit"
}
```

### Key endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/intercept` | POST | Main interception gateway |
| `/api/overview` | GET | Dashboard stats and burn meter |
| `/api/loop-detector/events` | GET | Fuse breaker event history |
| `/api/vault/proxy-tokens` | POST | Create a Snap-Token |
| `/api/vault/proxy-tokens/revoke-all` | POST | The Snap — emergency revoke all |
| `/api/tools/<id>/risk-score` | GET | Risk confidence index for a tool |
| `/api/rules/export` | POST | Export rules as branded JSON |
| `/api/rules/import` | POST | Import rule packs |
| `/health` | GET | Health check |

Full API documentation available at `/docs` when running the server.

---

## Self-Hosting

Snapwire is designed to run on your infrastructure. Your API keys and agent data never leave your servers.

### Environment variables

Copy `.env.example` and configure:

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | No | PostgreSQL connection string (falls back to SQLite) |
| `SESSION_SECRET` | No | Session encryption key (auto-generated if not set) |
| `ANTHROPIC_API_KEY` | No | For AI-powered rule evaluation and goal drift analysis |
| `OPENAI_API_KEY` | No | Alternative to Anthropic for AI features |
| `PORT` | No | Server port (default: 5000) |
| `LLM_PROVIDER` | No | Force `anthropic` or `openai` (auto-detected from keys) |

### Docker

```bash
docker build -t snapwire .
docker run -p 5000:5000 \
  -e DATABASE_URL=postgresql://user:pass@host:5432/snapwire \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  snapwire
```

### Production

For production deployments, use Gunicorn (included in the Docker image):

```bash
gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 120 --reuse-port main:app
```

---

## Badge

Add this to your README to show your agents are governed:

```markdown
[![Protected by Snapwire](https://github.com/snapwire-ai/snapwire/raw/main/static/badge-snapwire.svg)](https://github.com/snapwire-ai/snapwire)
```

[![Protected by Snapwire](https://github.com/snapwire-ai/snapwire/raw/main/static/badge-snapwire.svg)](https://github.com/snapwire-ai/snapwire)

---

## How Snapwire Compares

| Feature | **LiteLLM / Standard Proxies** | **Guardrails AI** | **Snapwire** |
|---------|-------------------------------|-------------------|-------------|
| **Primary Goal** | Model Interoperability | Data Quality / Hallucination | **Agentic Safety & Governance** |
| **Loop Protection** | None (costs run until timeout) | None | **Deterministic Fuse Breaker (3x/30s)** |
| **Enforcement Model** | Probabilistic (LLM-checks-LLM) | Probabilistic | **Deterministic Fuses + Optional Heuristic** |
| **Review Flow** | Silent failures | Retries | **Snap-Card Interactive Queue (Reject / Edit / Trust)** |
| **Credential Proxy** | Pass-through | Pass-through | **Snap-Tokens with instant revocation** |
| **Spend Monitoring** | Basic logging | None | **Live Burn Meter with projections** |
| **Intent Guard** | None | Output validation | **Semantic Goal-Drift Detection [HEURISTIC]** |
| **EU AI Act Ready** | Manual | Manual | **Built-in Article 12 & 14 conformity** |
| **Deployment** | Cloud proxy | Python library | **Self-hosted, your infrastructure** |

**The key difference:** Most proxies use another LLM to check the first one — slow, expensive, and can hallucinate. Snapwire's core uses deterministic code (regex, JSON schema, velocity counters). The LLM layer is optional and always labeled `[HEURISTIC]`.

---

## Compliance Readiness

Snapwire provides **Conformity-Ready Infrastructure** for organizations operating under the EU AI Act (2026) and similar regulatory frameworks.

| Requirement | EU AI Act Article | Snapwire Feature |
|-------------|------------------|-----------------|
| **Automatic Logging** | Article 12 (Record-keeping) | Full audit trail of every intercepted tool call, with timestamps, agent ID, rule evaluations, and human decisions. Exportable via API. |
| **Human Oversight** | Article 14 (Human Oversight) | Snap-Card Review Queue with Reject, Edit & Release, and Trust 24h actions. Blocked calls require explicit human approval before proceeding. |
| **Risk Management** | Article 9 (Risk Management) | Risk Confidence Index per tool, Blast Radius Governor per agent, real-time spend monitoring via Live Burn Meter. |
| **Technical Documentation** | Article 11 (Technical Documentation) | Config export/import, rule documentation, Audit CLI for offline analysis. |

> Snapwire does not guarantee regulatory compliance. These features provide technical infrastructure that supports compliance programs. Consult qualified legal counsel for your specific obligations.

---

## Performance

Snapwire introduces a **Governance Tax** — the latency overhead of intercepting each tool call through the safety gateway.

**Typical overhead (local testing):**
- Deterministic checks (Fuse Breaker, Schema Validation, Snap-Token resolution): **< 5ms typical**
- Full rule evaluation with LLM (when AI-powered rules are active): **200-800ms typical** (varies by LLM provider and network)
- Dashboard and SSE streaming: **No impact on agent latency**

**The tradeoff:** You are trading single-digit milliseconds of deterministic latency for the certainty that your agent won't enter a $1,000 loop or leak your production credentials. For 99% of agent workloads (which aren't doing high-frequency trading), this overhead is irrelevant compared to the safety gain.

**For high-velocity environments:** The Python/Flask gateway is designed for governance, not hot-path throughput. If you need sub-10ms overhead at scale, the deterministic rule engine can be extracted into a standalone sidecar.

---

## Roadmap

- **Egress Allowlisting** — Restrict outbound agent requests to approved domains and IPs (Coming March 2026)
- **Compliance Export** — One-click audit trail exports for SOC 2 / ISO 27001 evidence (Coming March 2026)
- **HSM Integration** — AWS KMS, HashiCorp Vault, Azure Key Vault as external key backends (Q3 2026)
- **Snapwire Core (High-Velocity Engine)** — Compiled sidecar for sub-10ms deterministic rule evaluation at scale (Q3/Q4 2026)
- **Cryptographic Agility** — Post-quantum ready key rotation and algorithm-agnostic encryption layer

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting process and Safe Harbor policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for fork and customization guidelines.

---

<p align="center">
  <em>Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature.<br/>The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator.</em>
</p>
