<p align="center">
  <img src="static/badge-snapwire.svg" alt="Protected by Snapwire" />
</p>

<h1 align="center">Snapwire: The Deterministic Agent Firewall</h1>
<p align="center"><strong>NIST IR 8596 Aligned | Colorado SB24-205 Safe Harbor Ready</strong></p>

<p align="center">
  <strong>Snapwire</strong> is a high-performance, open-source governance layer designed for the 2026 Agentic Economy.<br/>
  It acts as a <strong>Deterministic Gatekeeper</strong> between your AI Agents and your mission-critical data,<br/>
  transforming autonomous "black boxes" into governed, traceable, and legally defensible assets.
</p>

<p align="center">
  <a href="https://replit.com/@MasonJeffreys/Snapwire"><img src="https://img.shields.io/badge/Deploy-Replit-F26207?style=for-the-badge&logo=replit&logoColor=white" alt="Deploy to Replit" /></a>&nbsp;
  <a href="https://railway.app/new/template?template=https://github.com/snapwire-ai/snapwire"><img src="https://img.shields.io/badge/Deploy-Railway-0B0D0E?style=for-the-badge&logo=railway&logoColor=white" alt="Deploy to Railway" /></a>&nbsp;
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker Ready" />
</p>

<p align="center">
  <a href="#executive-summary-for-nist--regulatory-compliance">NIST Summary</a> &middot;
  <a href="#core-features-at-a-glance">Features</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#audit-cli">Audit CLI</a> &middot;
  <a href="#custom-rules">Custom Rules</a> &middot;
  <a href="#api">API</a> &middot;
  <a href="#how-snapwire-compares">Compare</a> &middot;
  <a href="#self-hosting">Self-Hosting</a> &middot;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

### One-Line Install

```bash
git clone https://github.com/snapwire-ai/snapwire.git && cd snapwire && docker compose up
```

PostgreSQL + Snapwire, running locally in under 60 seconds. Your keys, your data, your infrastructure.

---

## Executive Summary for NIST & Regulatory Compliance

This project is architected to satisfy the **NIST AI Risk Management Framework (AI RMF 1.0)** and the **NIST Cybersecurity Framework (CSF 2.0) Profile for AI (NIST IR 8596)**.

### 1. Governance & Accountability (NIST GV.OC / GV.RR)

* **A2A Identity & Traceability:** Implements **Parent Agent ID** tracing and **Human-Accountability Headers** (`X-Snapwire-Authorized-By`) to ensure every autonomous action is mapped to a verifiable human intent.
* **Three-Tier Role Model:** Strict separation of duties between **Platform Admins** (Global Governance), **Workspace Owners** (Tenant Compliance), and **Viewers** (Auditors).
* **Forensic Lineage Map:** Visual chain-of-command tree with NIST RESPOND-1.1 badges and trace detail click-through (Origin-ID, Parent-ID, Trace-ID, Authorized-By).

### 2. Risk Mapping & Measurement (NIST MAP / MEASURE)

* **The CVE Gauntlet:** Automated protection against **OpenClaw (CVE-2026-25253)** and 17+ hardcoded attack patterns (Redirects, SSRF, Hijacking).
* **Dynamic Chaos Ingestor:** Autonomous stress-testing of 1,000+ protocols using LLM-generated attack scenarios to calculate a **Risk Confidence Index** before deployment.
* **Self-Correction Loop:** When the CVE Gauntlet detects a vulnerability, the system generates an AI-powered fix and presents an "Original vs. Fixed" diff for one-click admin approval.

### 3. Continuous Monitoring & Management (NIST MANAGE / PROTECT)

* **Deterministic Hold Window:** Prevents "Machine-Speed Malice" by enforcing a configurable human-review pause for high-consequence tool calls.
* **Sentinel Proxy (Sidecar):** A zero-trust reverse proxy that intercepts all LLM traffic, providing **Observe**, **Audit**, and **Enforce** modes without modifying agent logic.
* **Vibe-Audit Weekly Summarizer:** Automated Friday 4 PM executive summary aggregating all security actions, cost savings, and compliance posture — delivered to Slack.

### 4. Content Integrity & Non-Repudiation (NIST DE.AE / RS.AN)

* **SHA-256 Content Hashing:** Every audit log entry is cryptographically hashed for tamper-evident forensic readiness.
* **HMAC-Signed Headers:** `X-Snapwire-Signature` provides non-repudiation for every intercepted tool call.
* **Immutable Audit Trail:** Exportable via API, Audit CLI, and Safety Disclosure PDF with NIST grade verification.

---

## Colorado SB24-205 "Safe Harbor" Support

Snapwire provides the **"Reasonable Care"** evidence required by the Colorado AI Act (effective June 30, 2026):

* **Automated Impact Assessments:** Generates one-click **Safety Disclosure PDFs** containing NIST grades and risk-mitigation logs.
* **Substantial Modification Tracking:** Real-time dashboard alerts when agent capabilities shift, ensuring compliance assessments stay current.
* **Consequentiality Tagging:** Mark high-stakes tools for explicit governance, with compliance portal reporting for Colorado SB24-205 affirmative defense.
* **Legal Counsel Acknowledgment Gate:** Compliance downloads require explicit acknowledgment, audit-logged with user ID and timestamp.
* **Deployer Compliance Portal:** One-click audit bundle ZIP download with auto-fill impact assessment and affirmative defense checklist.
* **AI Bill of Materials (AIBOM):** CycloneDX v1.7 JSON supply chain manifest tracking all agent tools, services, safety grades, and cryptographic formulation hashes. Compatible with OWASP Dependency-Track and enterprise SBOM tooling.

---

## Core Features at a Glance

* **60-Second Setup:** Deploy via Replit or Docker in one line of code.
* **Plain-Language Audits:** **Vibe-Summary** converts complex JSON tool-calls into 3-sentence English for non-technical stakeholders.
* **Loop Protection:** **Fuse Breaker** and **Thinking Token Sentinel** auto-block hallucination loops and costly logic spirals.
* **Cost Governance:** **Live Burn Meter** provides real-time spend projections and hard-cap enforcement.
* **Credential Proxy:** **Snap-Tokens** replace raw API keys. Agents never see real credentials. One-click revocation with **The Snap** emergency kill-switch.
* **Review Queue:** Blocked actions shown as structured **Snap-Cards** with Reject, Edit & Release, and Trust 24h actions.
* **Goal Drift Detection:** Flags behavioral shifts in agent reasoning for human review (advisory, heuristic).
* **Honeypot Tripwires:** Decoy tools detect unauthorized access attempts.
* **Schema Validation Guard:** Per-tool JSON schema enforcement with strict/flexible modes.
* **Auto-Triage Rules:** Regex-based automatic approval/denial with risk thresholds.

> All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator.

---

## Joint Federal Filing: NIST March 9th RFI

NIST is drafting federal guidelines for autonomous AI agent security under the **Consortium for the Advancement of AI Safety and Interoperability (CAISI)** initiative. The public comment period for **Docket NIST-2025-0035** (AI Agent Security RFI) closes **March 9, 2026**.

We are submitting a joint technical response based on the Sentinel Proxy architecture — an independent governance layer that provides cryptographically signed, non-repudiable audit trails for AI agent tool calls, aligned with **NISTIR 8596** (Cyber AI Profile).

**How to participate:**

1. **Fork** this repository and run `python -m pytest tests/ -v` to verify all tests pass
2. **Contribute** a new [Protocol Detector](CONTRIBUTING.md#contributing-a-sentinel-protocol-detector-3-steps) or [Deterministic Safeguard](CONTRIBUTING.md#deterministic-safeguards) to extend coverage
3. **Run** `python -m sentinel --export-nist` to generate your NIST compliance mapping and verify your grade
4. **Submit** your comment to [regulations.gov/docket/NIST-2025-0035](https://www.regulations.gov/docket/NIST-2025-0035) referencing the Sentinel Proxy architecture as a technical implementation of the Non-Repudiation and Identity Attribution requirements

**Core technical argument:** Traditional guardrails live inside the model or app — if the agent is hijacked (see [CVE-2026-25253](tests/cve_2026_25253_repro.py)), it can bypass internal checks. An independent governance proxy operating at the network layer, with HMAC-signed logs (`X-Snapwire-Signature`) and named human accountability (`X-Snapwire-Authorized-By`), provides the forensic trail that NIST IR 8596 requires for traceability.

**Embed your NIST grade:**

```markdown
![NIST Grade](https://your-instance.com/badge/nist-grade)
```

---

## Quick Start

> **Zero Config:** Snapwire works out of the box with SQLite and no API keys. Fork → Run → Working in 30 seconds. Add PostgreSQL and an LLM key later for full features.

### Option 1: Fork on Replit (fastest)

1. Click **Fork** on the [Snapwire Repl](https://replit.com/@snapwire/snapwire) to get your own copy.
2. Open the **Database** tab and create a PostgreSQL database (auto-configures `DATABASE_URL`).
3. Open the **Secrets** tab (padlock icon) and add:
   - `SESSION_SECRET` — any random string (for session encryption)
   - `ANTHROPIC_API_KEY` *(optional)* — your [Anthropic API key](https://console.anthropic.com/). Deterministic features (loop detection, spend monitoring, schema guard) work without any LLM key.
4. Click **Run**. The setup wizard guides you through creating your admin account.
5. Check `/health` to verify everything is connected:

```json
{
  "status": "ok",
  "database": "connected",
  "setup_complete": true,
  "features": {
    "loop_detection": true,
    "spend_monitoring": true,
    "schema_guard": true,
    "llm_rules": false
  }
}
```

> **Tip:** Check the "Load starter rules" box during setup to get 3 security rules and a $25/session spend limit pre-configured.

### Option 2: Docker (recommended for self-hosting)

```bash
git clone https://github.com/snapwire-ai/snapwire.git
cd snapwire
cp .env.example .env
# Edit .env with your settings
docker build -t snapwire .
docker run -p 5000:5000 --env-file .env snapwire
```

### Option 3: Run directly

**Requires Python 3.11+**

```bash
git clone https://github.com/snapwire-ai/snapwire.git
cd snapwire
pip install .
cp .env.example .env
# Edit .env with your settings
python main.py
```

Visit `http://localhost:5000` — the setup wizard will guide you through first-run configuration.

Verify with:
```bash
curl http://localhost:5000/health
```

### Option 4: Python SDK

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

### Troubleshooting

| Problem | Solution |
|---------|----------|
| **Port 5000 already in use** | Set the `PORT` environment variable to a different port: `PORT=8080 python main.py` |
| **`psycopg2` installation fails** | Snapwire falls back to SQLite automatically — no PostgreSQL driver required for local development. |
| **No LLM API key** | Deterministic features (loop detection, spend monitoring, schema guard, Snap-Tokens) work without any API key. Only AI-powered rule evaluation and goal drift analysis require a key. |

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
| `/api/compliance/aibom` | GET | CycloneDX v1.7 AI Bill of Materials |
| `/api/compliance/aibom/download` | GET | Download AIBOM as .cdx.json file |
| `/api/compliance/openapi.json` | GET | OpenAPI 3.0.3 governance spec |
| `/health` | GET | Health check (DB, secrets, features, setup status) |

Full API documentation available at `/docs` when running the server. Headless compliance API reference at `/docs/compliance`.

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
| `SLACK_WEBHOOK_URL` | No | For Watchdog alerts, Hold Window notifications, and Weekly Vibe-Audit delivery |
| `ADMIN_EMAIL` | No | Platform Admin email for Engine Room access |
| `WATCHDOG_SOURCE_URL` | No | URL for automated nightly tool registry scanning |

### Docker

```bash
docker build -t snapwire .
docker run -p 5000:5000 \
  -e DATABASE_URL=postgresql://user:pass@host:5432/snapwire \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  snapwire
```

### Sentinel Proxy (Sidecar)

Deploy as a transparent reverse proxy alongside your LLM gateway:

```bash
docker compose -f sentinel/docker-compose.yml up
```

The Sentinel Proxy intercepts all LLM API traffic and routes it through Snapwire governance in three modes:
- **Observe** — Fire-and-forget logging (zero latency impact)
- **Audit** — Log + inject NIST provenance headers
- **Enforce** — Log + headers + block (fail-closed)

### Production

For production deployments, use Gunicorn (included in the Docker image):

```bash
gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 120 --reuse-port main:app
```

---

## How Snapwire Compares

| Feature | **Agent Sandboxes** | **LiteLLM / Standard Proxies** | **Guardrails AI** | **Snapwire** |
|---------|---------------------|-------------------------------|-------------------|-------------|
| **Primary Goal** | Runtime Isolation | Model Interoperability | Data Quality / Hallucination | **Agentic Safety & Governance** |
| **Loop Protection** | None | None (costs run until timeout) | None | **Deterministic Fuse Breaker (3x/30s)** |
| **Enforcement Model** | OS-level containment | Probabilistic (LLM-checks-LLM) | Probabilistic | **Deterministic Fuses + Optional Heuristic** |
| **Review Flow** | None | Silent failures | Retries | **Snap-Card Interactive Queue (Reject / Edit / Trust)** |
| **Credential Proxy** | None | Pass-through | Pass-through | **Snap-Tokens with instant revocation** |
| **Spend Monitoring** | None | Basic logging | None | **Live Burn Meter with projections** |
| **NIST IR 8596** | None | None | None | **Full alignment with GV/MAP/PROTECT/DETECT** |
| **Colorado SB24-205** | Manual | Manual | Manual | **Built-in Safe Harbor evidence** |
| **Deployment** | Container / VM | Cloud proxy | Python library | **Self-hosted, your infrastructure** |

**The key difference:** Most proxies use another LLM to check the first one — slow, expensive, and can hallucinate. Snapwire's core uses deterministic code (regex, JSON schema, velocity counters). The LLM layer is optional and always labeled `[HEURISTIC]`.

---

## EU AI Act

Snapwire provides **Conformity-Ready Infrastructure** for organizations operating under the EU AI Act (2026) and similar regulatory frameworks.

| Requirement | EU AI Act Article | Snapwire Feature |
|-------------|------------------|-----------------|
| **Automatic Logging** | Article 12 (Record-keeping) | Full audit trail of every intercepted tool call, with timestamps, agent ID, rule evaluations, and human decisions. Exportable via API. |
| **Human Oversight** | Article 14 (Human Oversight) | Snap-Card Review Queue with Reject, Edit & Release, and Trust 24h actions. Blocked calls require explicit human approval before proceeding. |
| **Risk Management** | Article 9 (Risk Management) | Risk Confidence Index per tool, Blast Radius Governor per agent, real-time spend monitoring via Live Burn Meter. |
| **Technical Documentation** | Article 11 (Technical Documentation) | Config export/import, Safety Disclosure PDFs, Audit CLI for offline analysis. |

> Snapwire does not guarantee regulatory compliance. These features provide technical infrastructure that supports compliance programs. Consult qualified legal counsel for your specific obligations.

---

## Badge

Add this to your README to show your agents are governed:

```markdown
[![Protected by Snapwire](https://github.com/snapwire-ai/snapwire/raw/main/static/badge-snapwire.svg)](https://github.com/snapwire-ai/snapwire)
```

[![Protected by Snapwire](https://github.com/snapwire-ai/snapwire/raw/main/static/badge-snapwire.svg)](https://github.com/snapwire-ai/snapwire)

---

## Performance

Snapwire introduces a **Governance Tax** — the latency overhead of intercepting each tool call through the safety gateway.

**Typical overhead (local testing):**
- Deterministic checks (Fuse Breaker, Schema Validation, Snap-Token resolution): **< 5ms typical**
- Full rule evaluation with LLM (when AI-powered rules are active): **200-800ms typical** (varies by LLM provider and network)
- Dashboard and SSE streaming: **No impact on agent latency**

**The tradeoff:** You are trading single-digit milliseconds of deterministic latency for the certainty that your agent won't enter a $1,000 loop or leak your production credentials. For 99% of agent workloads (which aren't doing high-frequency trading), this overhead is irrelevant compared to the safety gain.

---

## Roadmap

- **HSM Integration** — AWS KMS, HashiCorp Vault, Azure Key Vault as external key backends (Q3 2026)
- **Snapwire Core (High-Velocity Engine)** — Compiled sidecar for sub-10ms deterministic rule evaluation at scale (Q3/Q4 2026)
- **Cryptographic Agility** — Post-quantum ready key rotation and algorithm-agnostic encryption layer
- **Multi-Cloud Sentinel** — Pre-built Sentinel Proxy images for AWS ECS, GCP Cloud Run, and Azure Container Instances
- **SOC 2 Evidence Pack** — One-click audit trail export mapped to SOC 2 Trust Service Criteria

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting process and Safe Harbor policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for fork and customization guidelines.

---

### How to Use this Document

1. **For GitHub:** This README signals to the community that Snapwire is the professional, compliance-ready choice for AI agent governance.
2. **For Clients:** Provide a link to this page as the "Executive Governance Overview."
3. **For NIST RFI (March 9th):** Use the Executive Summary as the basis for your official comment to Docket NIST-2025-0035.

---

<p align="center">
  <em>Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature.<br/>The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator.</em>
</p>
