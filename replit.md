# Snapwire

## Overview
Snapwire is "The Deterministic Agent Firewall" — an open-source (Apache 2.0) governance layer for the 2026 Agentic Economy. It intercepts, audits, and controls AI agent tool calls against user-defined automation rules, acting as a deterministic gatekeeper between AI agents and mission-critical data. NIST IR 8596 aligned and Colorado SB24-205 Safe Harbor ready. Key capabilities include real-time cost tracking, loop detection, credential proxy (Snap-Tokens), emergency global token revocation, AI-powered evaluation, and compliance-ready audit trails. Supports multi-tenancy and deploys platform-agnostically. Positioning: "Headless Governance Infrastructure." Marketing: "The 60-Second Firewall for your AI Agents." Admin: `fastfitness4u@gmail.com`. Current goals: NIST RFI March 9th filing, Vanguard onboarding readiness, and GitHub README finalization with NIST Executive Summary.

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Browser notifications for blocked actions
- Plain-language explanations everywhere
- Footer disclaimer on all pages: "Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator."

## System Architecture
Snapwire is built with a Python Flask backend and supports PostgreSQL or SQLite databases via SQLAlchemy ORM.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented at the database level with `tenant_id` columns.
-   **Authentication**: Auto-detects environment, using Replit Auth or local username/password with bcrypt.
-   **LLM Provider Layer**: Unified adapter for Anthropic Claude and OpenAI GPT.
-   **Email Layer**: Supports Replit Mail, SMTP, or console logging.
-   **Database**: PostgreSQL (preferred) or SQLite.
-   **Frontend**: Includes a landing page, pricing page, API docs, TOS, privacy policy, public audit, setup wizard, and a dashboard with Server-Sent Events (SSE) for real-time updates.
-   **First-Run Setup Wizard**: Guides initial configuration when no users exist.
-   **Config Export/Import**: Branded JSON format for rules and configurations.
-   **Telemetry**: Opt-in anonymous usage data collection.
-   **Snap-Token Acknowledgment Gate**: Requires user acknowledgment of responsibility before first Snap-Token creation.
-   **Python SDK**: An installable SDK package for programmatic interaction.
-   **NISTIR 8596 Alignment**: Includes features like Parent Agent ID for traceability and Content Hash Integrity for tamper detection, and PDF compliance reports.
-   **BYOK (Bring Your Own Key) Model**: Allows tenants to store their encrypted LLM API keys.
-   **Sentinel Proxy (Sidecar)**: A transparent reverse proxy (`sentinel/` package) that intercepts LLM API traffic and routes it through Snapwire governance. Uses `aiohttp` for async proxying. It operates in three modes: `observe` (fire-and-forget logging), `audit` (log + inject NIST headers), and `enforce` (log + headers + block, fail-closed). Protocol detection via a registry pattern. Dockerized as a sidecar service. It also injects `X-Snapwire-Origin-ID`, `X-Snapwire-Parent-ID`, and `X-Snapwire-Trace` headers for provenance.

**Key Features & Implementations:**
-   **Fuse Breaker**: Detects and automatically blocks recurring tool calls (hallucination loops).
-   **Schema Validation Guard**: Enforces JSON schemas for tool arguments.
-   **Snap-Tokens**: Manages proxy tokens that abstract real API keys, enabling secure agent interaction and instant revocation; supports ephemeral tokens.
-   **Live Burn Meter**: Provides real-time cost tracking and spend projections.
-   **Risk Confidence Index**: Calculates a trust score for each tool.
-   **Tool Safe Catalog**: AI-powered safety grading for tools.
-   **Blast Radius Governor**: Implements dual-limit systems per agent.
-   **Identity Vault**: Securely stores credentials.
-   **Deception & Goal Drift Detector**: Analyzes agent monologues for misalignments.
-   **Honeypot Tripwires**: Utilizes decoy tools to detect unauthorized access.
-   **Snap-Card Review Queue**: Presents blocked actions as structured "Snap-Cards" for review.
-   **Trust Rules (24h TTL)**: Allows creation of temporary auto-approval rules.
-   **Thinking Token Sentinel**: Monitors LLM `usage.thinking_tokens` to detect potential logic loops and pipeline latency anomalies.
-   **MCP JSON-RPC 2.0 Ingestion**: Auto-detects MCP format for tool calls.
-   **Three-Tier Role Model**: Restructures roles into Platform Admin, Workspace Owner, and Viewer.
-   **Reasoning Enforcement**: Requires agents to provide `inner_monologue` for high-risk tool calls.
-   **Forensic Lineage Map**: Provides a visual chain-of-command tree structure from audit log data.
-   **Liability-Shielding Features**: Public Safety Disclosure page and `X-Snapwire-Authorized-By` header for human accountability.
-   **Deterministic Hold Window**: Temporarily holds high-risk allowed calls for configurable seconds, with Slack integration for review and approval/denial.
-   **Auto-Triage Rules**: Automated approval/denial of actions based on regex matching and risk thresholds.
-   **OpenClaw**: A deterministic BASE_URL redirect attack detector.
-   **Vibe-Summary**: Claude-powered 3-sentence plain-English summaries on Snap-Cards (deterministic fallback without LLM key). Stored in `PendingAction.vibe_summary` and `AuditLogEntry.vibe_summary`.
-   **Stealth Mode**: `TenantSettings.is_stealth_mode` (default True) hides community features (Leaderboard, Founding Sentinel Wall of Fame, Community Rules) from non-admin users. Admin toggle in dashboard Security > Stealth Mode. Platform Admin global override in Engine Room > Stealth Control.
-   **Deployer Compliance Portal**: `/compliance-portal` with auto-fill impact assessment, audit bundle ZIP download (`/api/compliance/audit-bundle`), and Colorado SB24-205 affirmative defense checklist.
-   **Batch Ingestor**: `scripts/batch_ingestor.py` processes JSON files of MCP tool schemas through the CVE gauntlet with auto-heal, dry-run, and cost caps.
-   **Vanguard User Guide PDF**: `/safety/vanguard-guide.pdf` — branded PDF covering Hold Window, Slack Alerts, Weekly Digest, and Safety PDF features.
-   **NIST RESPOND-1.1 Tagging**: Slack Kill actions auto-tagged with RESPOND-1.1 in audit log violations for active human incident response governance.
-   **A2A Chain of Command**: Enhanced Forensic Lineage Map with NIST RESPOND-1.1 badge, trace detail click-through (Origin-ID, Parent-ID, Trace-ID, Authorized-By), compliance summary panel (human-origin verified, integrity hash coverage %), and "TRACED" badges per node.
-   **Consequentiality Tagging**: `ToolCatalog.is_consequential` (default False). `PATCH /api/catalog/<id>/consequential` endpoint. Dashboard "Tag Stakes" toggle with HIGH-STAKES visual indicator. Safety PDF Section 9 lists consequential tools for Colorado SB24-205. Compliance Portal shows consequential count.
-   **Headless Compliance API Docs**: `/docs/compliance` interactive Swagger-like API reference. `/api/compliance/openapi.json` returns OpenAPI 3.0.3 spec covering 9 governance endpoints. Links from `/docs` and compliance portal.
-   **Dynamic Chaos Ingestor**: `scripts/batch_ingestor.py` upgraded with `generate_chaos_exploits()` — Claude generates 3 per-tool attack scenarios (parameter injection, privilege escalation, data exfiltration). `--no-chaos` flag for static-only mode. Counts against 50-call LLM cost cap.
-   **Legal Counsel Acknowledgment Gate**: Compliance portal download buttons (Audit Bundle, Safety PDF) disabled until user checks "I have reviewed with qualified legal counsel" checkbox. Each download logs `compliance_counsel_acknowledgment` to audit log with user ID and timestamp.
-   **Substantial Modification Trigger**: `TenantSettings.last_assessment_at` tracks when last audit bundle was downloaded. Dashboard shows alert banner when 10+ tools added since last assessment, linking to compliance portal. Downloading audit bundle resets the counter.
-   **Homepage Rewrite**: Plain-language hero ("AI Agents act on your behalf. We make sure they don't go rogue."), Plug/Watch/Control "How It Works", NISTIR 8596 badge, Shared Responsibility Matrix table, compliance feature card, updated nav/footer links (Compliance, Governance-as-Code), 60-second messaging throughout.
-   **Engine Room (Super-Admin Tab Group)**: Platform Admin-only dashboard tab with 6 sub-panels: Batch Ingestor UI (file upload/URL input with dry-run/no-heal/no-chaos options, results table), Chaos Lab (per-tool chaos test runner with catch/miss stats), Global Burn Meter (cross-tenant spend aggregation), Stealth Control (global/per-tenant stealth mode toggle), Telemetry (relocated from Settings), and Weekly Summary. All endpoints gated by `require_platform_admin`. Orange accent styling (#FF6B00) distinguishes from tenant workspace tabs.
-   **Self-Correction Loop (Feature #47)**: When a tool fails the CVE Gauntlet and auto-heal produces a fix, the healed schema is stored in `ToolCatalog.pending_heal_schema` with status `pending_heal` instead of being silently adopted. Engine Room shows side-by-side "Original vs. Fixed" JSON diff with Approve/Reject buttons. APIs: `POST /api/admin/heal-approve/<tool_id>`, `POST /api/admin/heal-reject/<tool_id>`. Pending Fixes badge on Batch Ingestor tab.
-   **Vibe-Audit Weekly Summarizer (Feature #48)**: Automated Friday 4 PM UTC executive summary aggregating all audit logs, batch ingestor results, cost savings, and security posture. Claude generates a 1-page Markdown report (deterministic fallback without LLM key). Sent to Slack via `SLACK_WEBHOOK_URL`. Engine Room > Weekly Summary sub-tab for on-demand generation and manual Slack send. APIs: `GET /api/admin/weekly-summary`, `POST /api/admin/weekly-summary/send`.
-   **Watchdog Script**: `scripts/watchdog.py` — automated batch ingestor run with Slack failure alerts (`SLACK_WEBHOOK_URL`). Configurable source via `WATCHDOG_SOURCE_URL` env var. Silent on success, alerts on D/F grades or CVE failures. Manual trigger via Engine Room > Batch Ingestor > "Run Now" button. API: `POST /api/admin/watchdog/run`, `GET /api/admin/watchdog/status`.
-   **Admin/Tenant Dashboard Split**: Three-tier role model enforced — Platform Admin sees Engine Room tab + all Settings sub-tabs; Workspace Owner (admin role) sees Security tab + Webhooks; Viewer sees Home/Activity/Rules/Agents/Settings(account only). All tenant data endpoints scoped by `get_current_tenant_id()`.
-   **Taint Tracking (Feature #50)**: Cross-call data-flow governance. `ToolCatalog.sensitivity_level` (none/internal/pii/confidential) and `ToolCatalog.io_type` (source/sink/processor) classify tools. When an agent calls a SOURCE tool with sensitivity > none, the active `ProxyToken` gets `is_tainted = True`. Tainted tokens are blocked from calling SINK tools (HTTP clients, email, messaging). Human-in-the-loop "Clear Taint" release via `POST /api/vault/proxy-tokens/<id>/clear-taint`. Dashboard: Security > Taint & Pulse panel shows tainted tokens with clear buttons; Tool Catalog shows SOURCE/SINK/sensitivity badges with dropdown controls. `PATCH /api/catalog/<id>/sensitivity` sets sensitivity_level and io_type.
-   **Session Pulse (Feature #51)**: TTL-based continuous token re-validation. `TenantSettings.pulse_ttl_minutes` (default 0 = disabled). When > 0, new Snap-Tokens get `ProxyToken.pulse_expiry` set on creation. Tokens with expired pulse return HTTP 401 "Security Pulse Expired: Re-validation Required". `POST /api/vault/proxy-tokens/refresh` extends pulse_expiry by tenant's pulse_ttl_minutes. Refresh checks recent Goal Drift violations and logs advisory warning (doesn't block). Dashboard: Security > Taint & Pulse panel has TTL input. Satisfies NIST IR 8596 "Continuous Monitoring and Logging" requirement.
-   **Strict Reasoning Toggle (Feature #52)**: `TenantSettings.strict_reasoning` (default False). When enabled, ALL tool calls must include `inner_monologue` field — calls without reasoning are rejected with HTTP 412 "Strict Reasoning Mode: inner_monologue required on all tool calls". Extends existing Reasoning Enforcement (Feature #14) from high-risk-only to all calls. `GET/PATCH /api/settings/strict-reasoning` endpoints. Dashboard: Security > Taint & Pulse panel has toggle. Ensures AIBOM is always populated with "Why" for Colorado SB24-205 affirmative defense.
-   **AIBOM Generator (Feature #49)**: CycloneDX v1.7 JSON AI Bill of Materials. `src/aibom_generator.py` generates per-tenant supply chain manifests from ToolCatalog and AuditLogEntry data. Components = registered tools with safety grades. Services = observed tool calls with risk scores and agent counts. Properties = aggregate compliance stats (block rate, NIST framework, grade distribution). Formulation = SHA-256 hashes linking intent→action for forensic chain of custody. APIs: `GET /api/compliance/aibom`, `GET /api/compliance/aibom/download`, `GET /api/compliance/aibom/summary`. Admin APIs: `GET /api/admin/aibom`, `GET /api/admin/aibom/download`, `GET /api/admin/aibom/summary`. Compliance Portal AIBOM section with stats, grade distribution, component preview, and download button (legal counsel gate). Audit bundle ZIP now includes `snapwire-aibom.cdx.json`. Engine Room > Global Burn shows cross-tenant AIBOM supply chain stats with global download. OpenAPI spec updated with AIBOM endpoints.

## External Dependencies
-   **Database**: PostgreSQL, SQLite
-   **AI Service**: Anthropic Claude, OpenAI GPT
-   **Authentication**: Replit Auth, bcrypt
-   **Email**: Replit Mail, SMTP
-   **ORM**: SQLAlchemy
-   **Web Framework**: Flask
-   **WSGI Server**: Gunicorn
-   **PDF Generation**: fpdf2
-   **Async HTTP**: aiohttp (Sentinel Proxy)
-   **Slack Integration**: slack-bolt