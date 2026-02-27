# Snapwire

## Overview
Snapwire is an AI-powered security gateway designed to intercept, audit, and control AI agent tool calls against user-defined automation rules. It acts as "The Firewall for AI Agents," preventing unauthorized or undesirable actions by AI agents. The project's core purpose is to provide real-time monitoring and control over AI operations, focusing on spend monitoring, security, and behavioral governance. Key capabilities include real-time cost tracking, loop detection, credential security, emergency global token revocation, and AI-powered evaluation of agent tool calls. It supports multi-tenancy and deploys platform-agnostically, aiming for a comprehensive solution for AI agent governance.

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
-   **Stealth Mode**: `TenantSettings.is_stealth_mode` (default True) hides community features (Leaderboard, Founding Sentinel Wall of Fame, Community Rules) from non-admin users. Admin toggle in dashboard Security > Stealth Mode.
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