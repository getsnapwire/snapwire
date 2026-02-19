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
- **Style**: Industrial, high-contrast Dark Mode with Safety Orange (#FF6600) accents
- **Terminology**: "The Fuse" (security layer), "Snap-Tokens" (proxy identity tokens), "The Snap" (kill-switch), "Fuse Breaker" (loop detector), "Live Burn Meter" (spend monitor)
- **Legal Position**: Neutral Intermediary — monitoring utility, not liable for AI actions

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Industrial dark theme with Safety Orange (#FF6600) primary accent
- Browser notifications for blocked actions
- Plain-language explanations everywhere
- Footer disclaimer on all pages: "Snapwire is a technical monitoring utility. Use at your own risk. User assumes all liability for agent behavior."

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

## Security
-   **Rate Limiting**: Flask-Limiter applied to auth endpoints
-   **Neutral Intermediary**: TOS defines Snapwire as monitoring utility with $100 liability cap
-   **Snap-Token Acknowledgment**: Users must accept responsibility before creating tokens

## Testing
-   Run tests: `python -m pytest tests/ -v`

## Recent Changes
- **2026-02-19**: Full rebrand from "Agentic Firewall" to "Snapwire". New industrial dark mode with Safety Orange (#FF6600) theme. Added Live Burn Meter, Broken Circuit animation, Snap-Token acknowledgment gate, The Snap kill-switch, privacy policy page. Updated all templates, backend, SDK, tests, and documentation.
