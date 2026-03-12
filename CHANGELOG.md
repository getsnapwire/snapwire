# Changelog

All notable changes to Snapwire are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [0.1.0] — 2026-03-11 — GitHub Launch

### Added

**Core Runtime Security**
- Fuse Breaker — deterministic 3x/30s loop detection with automatic API key lockout
- Schema Validation Guard — per-tool JSON schema enforcement with hardcoded boundaries
- Snap-Tokens — proxy credential system; agents never see real API keys
- Live Burn Meter — real-time cost tracking with hard-cap enforcement
- Risk Confidence Index — 0-100 trust scoring per tool call
- Tool Safe Catalog — AI-powered safety grading for all registered tools
- Blast Radius Governor — dual per-agent spending and action limits
- Identity Vault — encrypted credential storage with AES-256

**JIT Context-Matching (new in 0.1.0)**
- Snap-Tokens now support `allowed_tools` — scope a token to specific tool names only
- `jit_intent` field stored on every token for audit trail
- Runtime enforcement: tool calls outside allowed list return HTTP 403 with `jit_tool_not_allowed`

**Agent-Collision Detection (new in 0.1.0)**
- `AgentLock` — database-backed mutex for multi-agent resource coordination
- `POST /api/agent-lock/acquire` — acquire a named resource lock with TTL
- `POST /api/agent-lock/release` — release a held lock
- `GET /api/agent-lock/status` — view all active locks for a tenant
- Engine Room: Agent Locks sub-tab with live lock registry and force-release

**Human-in-the-Loop (HITL)**
- Snap-Card Review Queue — runtime violations surface for human approval/denial
- Context-Aware Remediation Prompts — LLM-powered fix suggestions per violation
- Trust Rules — 24-hour TTL auto-approval for recurring approved patterns
- Auto-Triage Rules — regex-based automatic approval/denial with risk thresholds
- Deterministic Hold Window — configurable pause for high-consequence tool calls

**Monitoring & Auditing**
- Forensic Lineage Map — visual chain-of-command with NIST RESPOND badges
- Vibe-Summary — plain-English summaries of every security action
- Vibe-Audit Weekly Summarizer — Friday 4 PM executive summary to Slack
- Reasoning Enforcement — requires `inner_monologue` field on agent tool calls
- Thinking Token Sentinel — detects logic loops and latency anomalies

**Compliance**
- NIST IR 8596 alignment — 55/55 features mapped, 100% coverage
- Colorado SB24-205 Safe Harbor support — Safety Disclosure PDF generation
- EU AI Act alignment — AIBOM (CycloneDX v1.7) with NIST IR 8596 control tags
- Deployer Compliance Portal — one-click PDF generation for regulatory evidence
- NIST RFI-2025-0035 commentary — `nist_rfi_responses.txt` with 55-feature responses

**Sentinel Proxy (Sidecar)**
- Transparent reverse proxy — intercepts LLM API traffic with zero agent code changes
- 9 built-in protocol detectors: OpenAI, Anthropic, Google Gemini, Cohere, AWS Bedrock, LangChain, MCP, A2A, Generic JSON-RPC
- Three operating modes: `observe`, `audit`, `enforce`
- `X-Snapwire-Signature` HMAC header — cryptographic non-repudiation for every call
- Detector Lab — UI for generating new protocol detectors on-the-fly

**Security**
- Taint Tracking — cross-call data-flow governance; blocks exfiltration chains
- Session Pulse — TTL-based continuous token re-validation
- Honeypot Tripwires — decoy tools that auto-lock API keys on access
- OpenClaw Safeguard — BASE_URL redirect/hijack attack detector (CVE-2026-25253)
- Deception & Goal Drift Detector — flags agent behavior that deviates from declared intent
- Strict Reasoning Toggle — requires structured reasoning before tool execution

**Infrastructure**
- Multi-tenant architecture with `tenant_id` isolation
- Three-tier role model: Platform Admin, Workspace Owner, Viewer
- BYOK (Bring Your Own Key) — tenants store encrypted LLM API keys
- Snapwire CLI — `init`, `check`, `up`, `aibom` commands with Rich terminal output
- Python SDK — installable package for programmatic intercept integration
- Engine Room — super-admin dashboard with system health, chaos lab, global burn meter

**Platform**
- One-click deploy to Replit and Railway
- Docker Compose for local self-hosting
- PostgreSQL (production) and SQLite (development) support

---

## Roadmap

### [0.2.0] — Planned

- Semantic Rollback — LLM-powered undo for reversible agent actions
- Ghost Proxy — read-only shadow mode that mirrors traffic without blocking
- HSM Integration — AWS KMS, HashiCorp Vault, Azure Key Vault backends
- GitHub Actions native integration
- Webhook alerts for third-party SIEM systems

---

*Snapwire is Apache 2.0 licensed. Contributions welcome — see CONTRIBUTING.md.*
