# Snapwire

## Overview
Snapwire is an AI-powered security gateway designed to intercept, audit, and control AI agent tool calls against user-defined automation rules. It functions as "The Firewall for AI Agents," preventing unauthorized or undesirable actions by AI agents. The project aims to provide real-time monitoring and control over AI operations, focusing on spend monitoring, security, and behavioral governance. Key capabilities include spend monitoring, loop detection, credential security, real-time cost tracking, emergency global revocation of tokens, and AI-powered evaluation of agent tool calls. It supports multi-tenancy and deploys platform-agnostically, with features like a Tool Safe Catalog, Blast Radius Governor, and Deception Detection.

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
-   **NISTIR 8596 Alignment**: Includes features like Parent Agent ID for traceability and Content Hash Integrity for tamper detection.
-   **BYOK (Bring Your Own Key) Model**: Allows tenants to store their encrypted LLM API keys.
-   **Sentinel Proxy (Sidecar)**: Transparent reverse proxy (`sentinel/` package) that intercepts LLM API traffic and routes it through Snapwire governance. Uses `aiohttp` for async proxying. Three modes: `observe` (fire-and-forget logging), `audit` (log + inject NIST headers), `enforce` (log + headers + block, fail-closed). Protocol detection via registry pattern in `sentinel/detector.py`. Entry point: `python -m sentinel`. NIST compliance export: `python -m sentinel --export-nist`. Dockerized as sidecar service on port 8080.

**Key Features & Implementations:**
-   **Fuse Breaker**: Detects and automatically blocks recurring tool calls (hallucination loops) with a 429 status.
-   **Schema Validation Guard**: Enforces JSON schemas for tool arguments.
-   **Snap-Tokens**: Manages proxy tokens that abstract real API keys, enabling secure agent interaction and instant revocation; supports ephemeral tokens.
-   **Live Burn Meter**: Provides real-time cost tracking, projecting daily burn rate and 30-day spend.
-   **Risk Confidence Index**: Calculates a trust score (0-100) for each tool based on GitHub reputation and URL safety scans.
-   **Tool Safe Catalog**: AI-powered safety grading for tools.
-   **Blast Radius Governor**: Implements dual-limit systems per agent.
-   **Identity Vault**: Securely stores credentials.
-   **Deception & Goal Drift Detector**: Analyzes agent monologues via LLM for potential misalignments.
-   **Honeypot Tripwires**: Utilizes decoy tools to detect unauthorized access attempts.
-   **Snap-Card Review Queue**: Presents blocked actions as structured "Snap-Cards" for review.
-   **Trust Rules (24h TTL)**: Allows creation of temporary auto-approval rules for specific agent+tool combinations.
-   **Thinking Token Sentinel**: Monitors LLM `usage.thinking_tokens` to detect potential logic loops.
-   **MCP JSON-RPC 2.0 Ingestion**: Auto-detects MCP format for tool calls and processes them through the pipeline.
-   **Three-Tier Role Model**: Restructures roles into Platform Admin, Workspace Owner, and Viewer.

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

## Change Log (Recent)
- **2026-02-26**: Reasoning Enforcement — (1) When high-risk tool calls (critical/high severity violations) are submitted without `inner_monologue`, Snapwire returns `412 Precondition Required` with `status: "reasoning_required"`, requiring the agent to re-submit with reasoning. (2) `reasoning_enforcement` column added to `TenantSettings` (default: enabled). (3) Dashboard Settings → Webhooks & Notifications tab: toggle to enable/disable reasoning enforcement. (4) API endpoints: `GET/PATCH /api/settings/reasoning-enforcement`. (5) SDK handles 412 response gracefully, returning `decision: "reasoning_required"`. (6) API docs updated with 412 status code and example response.
- **2026-02-26**: NISTIR 8596 Compliance Report (PDF) — (1) `src/compliance_report.py` generates branded PDF reports using fpdf2: compliance score, NIST category breakdown table, audit activity summary, identity attribution summary, weekly digest, disclaimer. (2) `GET /api/compliance/nist-report/pdf` endpoint returns downloadable PDF. (3) Dashboard NIST section: "Download NIST Audit Report" button next to "Generate Report".
- **2026-02-27**: Forensic Lineage Map — (1) `GET /api/audit-log/lineage` endpoint returns agent chain-of-command tree structure (nodes, edges, summary) from audit log data. (2) Dashboard Home tab: visual tree rendering showing Human → Agent → Sub-agent chains with status badges (Allowed/Blocked/Halt/Pending), risk scores, tool chips, and content hash integrity indicators. (3) Audit log entries with `parent_agent_id` show chain-link icon with NIST-Compliant lineage tooltip. (4) `seed_demo.py` script populates realistic multi-agent demo data (orchestrator → code-writer, reviewer, deploy-agent → monitor) with mixed statuses.
- **2026-02-27**: Docker Hardening — (1) `HEALTHCHECK` added to Dockerfile (curl /health). (2) App service healthcheck added to docker-compose.yml. (3) `.dockerignore` expanded to exclude attached_assets, tests, .replit, .upm, .config, .cache, uv.lock.
- **2026-02-27**: Sentinel Proxy (Sidecar) — (1) `sentinel/detector.py`: registry-pattern multi-protocol tool-call detector (OpenAI, Anthropic, MCP, A2A, generic JSON-RPC) returning `DetectedToolCall` named tuples. (2) `sentinel/proxy.py`: async reverse proxy (aiohttp) with 3 modes — observe (fire-and-forget, zero latency), audit (log + inject NIST headers), enforce (block + fail-closed Andon Cord). Injects `X-Snapwire-Origin-ID`, `X-Snapwire-Parent-ID`, `X-Snapwire-Trace` headers. (3) `sentinel/__main__.py`: CLI entry point with startup banner + `--export-nist` flag. (4) `sentinel/nist_export.py`: generates `snapwire-nist-mapping.md` with letter grade (A/B/C) mapped to NIST RFI 2025-0035. (5) `sentinel/Dockerfile` added; `docker-compose.yml` sentinel sidecar service on port 8080. (6) Landing page: "Zero-Code Agent Firewall" feature card + Reasonable Care Disclosure + Infrastructure Intermediary legal clauses. (7) Dashboard: Sentinel quickstart card with copy-paste snippets and 3-mode legend. (8) API docs: full Sentinel Proxy section (protocols, modes, headers, config, NIST export). (9) `tests/test_sentinel.py`: 22 tests covering detector, config, NIST export. Total: 74 tests passing.