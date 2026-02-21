# Snapwire

## Overview
Snapwire is "The Safety Fuse for Your AI Agents" — an AI-powered security gateway that intercepts AI agent tool calls, audits them against user-defined automation rules using an LLM (Claude or GPT), and blocks actions that violate these rules. Blocked actions are queued for manual human approval or denial via a web dashboard, accompanied by browser notifications.

The project is platform-agnostic and can be deployed on any infrastructure: Docker, Replit, Heroku, AWS, bare metal, etc.

Key capabilities include:
- **Utility-First Positioning**: "Metering, not judging" — leads with spend monitoring, loop detection, and credential security.
- **Fuse Breaker (Loop Detector)**: Detects hallucination loops (same tool + same args 3x in 30s) and auto-blocks ("snaps the circuit") with estimated savings tracking and Broken Circuit animation.
- **Schema Validation Guard**: Per-tool JSON schema enforcement with strict (strip unauthorized params) / flexible (log only) modes.
- **Snap-Tokens**: Proxy tokens (`snap_` prefixed) replace raw API keys. Agents never see real credentials. One-click revocation. Acknowledgment gate before first token creation.
- **Live Burn Meter**: Real-time cost tracking with daily burn rate, 30-day spend projections, and visual gradient meter.
- **The Snap (Kill-Switch)**: Emergency revoke all active Snap-Tokens with one click. Circuit-break animation on trigger.
- **Automation Rules**: AI-powered evaluation of agent tool calls against custom rules.
- **Multi-Tenancy**: Supports individual user workspaces and team collaboration through organizations.
- **Enhanced Security**: Tool Safe Catalog, Blast Radius Governor, Identity Vault, Deception Detection, Honeypot Tripwires.
- **Risk Confidence Index**: 0-100 trust scores per tool with GitHub reputation lookup, URL safety scanning, and automatic risk grading (A-F).
- **Platform-Agnostic**: LLM, auth, email, database, and session layers all auto-detect their environment.
- **Viral Growth**: Config export/import with branded metadata, opt-in telemetry, Share My Savings card.

## Brand Identity
- **Name**: Snapwire
- **Tagline**: "The Safety Fuse for Your AI Agents."
- **Style**: "Industrial Safety" palette — True Charcoal (#0B0D10) base, Deep Slate (#151A21) surfaces, Safety Orange (#FF6B00) for actions, Electric Cyan (#40E0FF) for monitoring/intelligence, Holographic Teal (#00F5D4) for success, Ion Gold (#FFD66B) for warnings, Cloud Dancer (#F0EEE9) text, Night Plum (#2B1538) hero gradient accents
- **Terminology**: "The Fuse" (security layer), "Snap-Tokens" (proxy identity tokens), "The Snap" (kill-switch), "Fuse Breaker" (loop detector), "Live Burn Meter" (spend monitor)
- **Legal Position**: Neutral Intermediary — monitoring utility, not liable for AI actions

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Browser notifications for blocked actions
- Plain-language explanations everywhere
- Footer disclaimer on all pages: "Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator."

## System Architecture
Snapwire is built with a Python Flask backend and supports PostgreSQL or SQLite databases via SQLAlchemy ORM.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented at the database level with `tenant_id` columns across relevant models.
-   **Authentication**: Auto-detects environment — uses Replit Auth when `REPL_ID` is present, otherwise local username/password with bcrypt.
-   **LLM Provider Layer** (`src/llm_provider.py`): Unified adapter supporting Anthropic Claude and OpenAI GPT.
-   **Email Layer** (`src/email_service.py`): Supports Replit Mail, SMTP, or console logging.
-   **Database**: PostgreSQL via `DATABASE_URL`, falls back to SQLite if not set.
-   **Session Secret**: Reads from `SESSION_SECRET` env var, auto-generates if not set.
-   **Port**: Configurable via `PORT` env var, defaults to 5000.
-   **Frontend**: Landing page (`login.html`), pricing page (`pricing.html`), API docs (`docs.html`), TOS (`tos.html`), privacy policy (`privacy.html`), public audit (`audit.html`), setup wizard (`setup_wizard.html`), and dashboard (`dashboard.html`) with SSE for real-time updates.
-   **First-Run Setup Wizard**: Presents setup wizard when no users exist.
-   **Config Export/Import**: Branded JSON format with metadata header. Import validates format and accepts both "Snapwire" and legacy "Agentic Firewall" exports.
-   **Telemetry**: Opt-in anonymous telemetry with daily ping.
-   **Snap-Token Acknowledgment Gate**: Before creating first Snap-Token, user must acknowledge: "I acknowledge that Snapwire is a monitoring utility and that I remain 100% responsible for the costs and actions of my autonomous agents."
-   **Python SDK**: Installable SDK package (`sdk/` directory) for `pip install snapwire`.

**Key Features & Implementations:**
-   **Fuse Breaker** (`src/loop_detector.py`): Detects hallucination loops (3+ repeats in 30s), auto-blocks with 429, records events with estimated savings. Dashboard shows "Broken Circuit" animation.
-   **Schema Validation Guard** (`src/schema_guard.py`): Per-tool JSON schema enforcement.
-   **Snap-Tokens** (`src/vault.py`): ProxyToken model with `snap_` tokens. Agents use proxy tokens; real keys injected at gateway. Full token shown only on creation. One-click revocation. **The Snap** button for emergency global revocation.
-   **Live Burn Meter**: Real-time cost tracking in overview API. Dashboard shows gradient burn meter with needle indicator, Total Savings counter, and **Share My Savings** downloadable branded image card.
-   **Risk Confidence Index** (`src/risk_index.py`): 0-100 trust scores per tool with GitHub reputation lookup and URL safety scanning. All outputs labeled as "Intelligence Signals" with legal disclaimer.
-   **Tool Safe Catalog** (`src/tool_catalog.py`): AI-powered safety grading (A-F).
-   **Blast Radius Governor** (`src/blast_radius.py`): Per-agent dual-limit system.
-   **Identity Vault** (`src/vault.py`): Secure credential storage with Snap-Token proxy layer.
-   **Deception & Goal Drift Detector**: Analyzes `inner_monologue` via LLM.
-   **Honeypot Tripwires**: Decoy tools to detect unauthorized access.
-   **TOS Acceptance Gate**: Users must scroll through and accept Terms of Service before dashboard access.
-   **Snap-Card Review Queue**: Redesigned review queue with "Snap-Cards" — each blocked action shows as a structured card with Snap Reason badge, dual-panel layout (Agent Intent vs Security Signal), and three actions: Reject, Edit & Release (JSON editor modal), Trust 24h (creates temporary auto-approve rule).
-   **Trust Rules (24h TTL)**: `TrustRule` model enables temporary auto-approval for specific agent+tool combinations. Created via "Trust 24h" button on Snap-Cards. Auto-expires after 24 hours. Revocable from API.

## External Dependencies
-   **Database**: PostgreSQL (production) / SQLite (development/testing)
-   **AI Service**: Anthropic Claude or OpenAI GPT (via `src/llm_provider.py` adapter)
-   **Authentication**: Replit Auth (when on Replit) or local auth (bcrypt)
-   **Email**: Replit Mail, SMTP, or console fallback
-   **ORM**: SQLAlchemy
-   **Web Framework**: Flask
-   **WSGI Server**: Gunicorn

## Key Environment Variables
-   `DATABASE_URL` - PostgreSQL connection string (optional, falls back to SQLite)
-   `SESSION_SECRET` - Session encryption key (optional, auto-generated)
-   `PORT` - Server port (default: 5000)
-   `LLM_PROVIDER` - "anthropic" or "openai" (auto-detected from keys)
-   `ANTHROPIC_API_KEY` - Anthropic Claude API key
-   `OPENAI_API_KEY` - OpenAI API key

## Key Endpoints
-   `GET /health` - Health check
-   `POST /api/intercept` - Main agent tool call interception (includes loop detection, schema validation, risk scoring, proxy token resolution)
-   `GET /api/overview` - Dashboard overview stats
-   `GET /api/loop-detector/events` - Loop/fuse breaker event history
-   `POST /api/vault/proxy-tokens` - Generate new Snap-Token
-   `POST /api/vault/proxy-tokens/revoke-all` - The Snap — emergency revoke all
-   `GET /api/tools/<id>/risk-score` - Risk confidence index
-   `GET /api/risk-signals` - Recent risk intelligence signals
-   `POST /api/rules/export` - Export rules as branded JSON
-   `POST /api/rules/import` - Import rule packs
-   `GET /privacy` - Privacy policy page
-   `POST /api/actions/<id>/edit-release` - Edit parameters and release a blocked action
-   `POST /api/actions/<id>/trust` - Approve and create 24h trust rule for agent+tool
-   `GET /api/trust-rules` - List active trust rules
-   `POST /api/trust-rules/<id>/revoke` - Revoke a trust rule

## Security
-   **Rate Limiting**: Flask-Limiter applied to auth endpoints
-   **Neutral Intermediary**: TOS defines Snapwire as monitoring utility with $100 liability cap
-   **Snap-Token Acknowledgment**: Users must accept responsibility before creating tokens

## Testing
-   Run tests: `python -m pytest tests/ -v`

## Recent Changes
- **2026-02-21**: Launch readiness — Rewrote README.md for GitHub (overview, install, audit CLI, custom rules, API, badge, roadmap, disclaimer). Updated .env.example with current branding and clear docs. Created attack scenario test suite (22 scenarios across 6 categories: credential exfil, env access, PII, crypto, domain exfil, safe calls) with test runner in `tests/scenarios/`. Added prominent "Total Saved" counter card to dashboard top-level stats grid with Holographic Teal styling.
- **2026-02-21**: Legal liability copy refinements — Hero headline changed from "proves it behaves safely" to "enforces behavioral boundaries". Replaced absolute claims ("catches a $500 loop", "pays for itself") with enforcement language ("designed to detect loops based on user-defined velocity limits"). Added HEURISTIC label to Goal Drift Alerts to distinguish AI-powered features from deterministic ones. Changed "Secure Your Agent" to "Govern Your Agent" on audit page. Updated docs API description from "deception detection" to "heuristic goal-drift analysis". All copy now uses govern/enforce/monitor vocabulary instead of secure/prove/guarantee.
- **2026-02-21**: Developer growth layer — Created `/rules` directory with 5 community-inviting stub rule files (block_pii, budget_cap, env_protection, crypto_lock, domain_allowlist) following consistent `evaluate()` interface pattern. Built `snapwire_audit.py` CLI tool that scans local JSON agent logs for 3x/30s recursive loops and reports estimated wasted spend with fork CTA. Removed pricing page from navigation (redirects to homepage). Replaced dashboard "Upgrade to Cloud" link with GitHub link.
- **2026-02-21**: Open-source preparation — Added Apache 2.0 LICENSE, SECURITY.md (vulnerability reporting process with Safe Harbor), CONTRIBUTING.md (fork/customize guidelines focused on deterministic rules). Updated SDK pyproject.toml with proper metadata, keywords, classifiers, and Apache-2.0 license. Added "Protected by Snapwire" SVG badge. Improved Dockerfile with --reuse-port flag.
- **2026-02-20**: Safe Harbor disclaimer update — replaced generic footer disclaimer across all 14 templates and dashboard with precise legal language: "All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator." Added section-level disclaimer to Snap-Card review queue and per-card disclaimer on each Snap-Card.
- **2026-02-20**: Landing page GTM copy refresh — new headline "The Real-Time Circuit Breaker for AI Agents", competitive positioning against static scanners, Burn Meter as lead feature, revised "Industrial Guardian" tone. Replaced Shadow Mode with Snap-Card Review Queue in core features. Renamed deception detector to "Goal Drift Alerts". Added Roadmap section (Egress Allowlisting, Compliance Export as "Coming March 2026"). Updated final CTA. Removed unbuilt features from main feature list.
- **2026-02-20**: Snap-Card Review Queue — redesigned pending approvals with structured Snap-Cards (reason badge, dual-panel Agent Intent / Security Signal layout, mobile-responsive stacking). Three action buttons: Reject, Edit & Release (JSON editor modal with validation), Trust 24h (creates TTL auto-approve rule for agent+tool combo). Added TrustRule model, trust-approved intercept logic, and toast notifications. Pulse animation on new cards.
- **2026-02-20**: Industrial Safety palette overhaul — True Charcoal (#0B0D10) base, Deep Slate (#151A21) surfaces, Electric Cyan (#40E0FF) for monitoring, Holographic Teal (#00F5D4) for success, Ion Gold (#FFD66B) for warnings, Cloud Dancer (#F0EEE9) text. Night Plum (#2B1538) cinematic mesh gradient on hero sections. All 14+ templates, static/style.css, and dashboard canvas colors updated.
- **2026-02-19**: Second design pass — lightened dark theme further to #111827/#1f2937 for more open, airy feel. Added card shadows for depth. Removed "Ready for Enterprise?" section from landing page. All 14+ templates consistent.
- **2026-02-19**: Design refresh — shifted from heavy industrial black to softer dark slate/navy with refined orange accents. Updated all 14 templates to new palette. Added welcome banner onboarding, better empty states, mobile responsiveness, platform-agnostic vault messaging. Simplified pricing to Free + Pro (removed Enterprise tier). Updated TOS liability cap from $100 to "fees paid in prior 30 days". 
- **2026-02-19**: Full rebrand from "Agentic Firewall" to "Snapwire". Added Live Burn Meter, Broken Circuit animation, Snap-Token acknowledgment gate, The Snap kill-switch, privacy policy page. Updated all templates, backend, SDK, tests, and documentation.
