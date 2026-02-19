# Agentic Firewall

## Overview
The Agentic Firewall is an AI-powered system designed to secure AI agent operations by intercepting tool calls, auditing them against user-defined constitutional rules using an LLM (Claude or GPT), and blocking actions that violate these rules. Blocked actions are queued for manual human approval or denial via a web dashboard, accompanied by browser notifications.

The project is platform-agnostic and can be deployed on any infrastructure: Docker, Replit, Heroku, AWS, bare metal, etc.

Key capabilities include:
- **Utility-First Positioning**: "Metering, not judging" — leads with spend monitoring, loop detection, and credential security.
- **Agentic Loop Detector**: Detects hallucination loops (same tool + same args 3x in 30s) and auto-blocks with estimated savings tracking.
- **Schema Validation Guard**: Per-tool JSON schema enforcement with strict (strip unauthorized params) / flexible (log only) modes.
- **Credential Proxy**: Proxy tokens (`agfw_` prefixed) replace raw API keys. Agents never see real credentials. One-click revocation.
- **Spend Monitor**: Real-time cost tracking with daily burn rate and 30-day spend projections.
- **Automation Rules** (formerly Constitutional Auditor): AI-powered evaluation of agent tool calls against custom rules.
- **Multi-Tenancy**: Supports individual user workspaces and team collaboration through organizations.
- **Enhanced Security**: Tool Safe Catalog, Blast Radius Governor, Identity Vault, Deception Detection, Honeypot Tripwires.
- **Platform-Agnostic**: LLM, auth, email, database, and session layers all auto-detect their environment.
- **Viral Growth**: Config export/import with branded metadata, opt-in telemetry, embeddable badges.

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Browser notifications for blocked actions
- Constitutional theme: "amendments" not "guardrails"
- Plain-language explanations everywhere
- Modern SaaS-style landing page with light theme for marketing

## System Architecture
The Agentic Firewall is built with a Python Flask backend and supports PostgreSQL or SQLite databases via SQLAlchemy ORM.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented at the database level with `tenant_id` columns across relevant models. Each user receives a personal tenant upon first login, and organizations provide shared tenant spaces.
-   **Authentication**: Auto-detects environment — uses Replit Auth (OpenID Connect) when `REPL_ID` is present, otherwise uses local username/password authentication with bcrypt. Both share the same User model and Flask-Login session management.
-   **LLM Provider Layer** (`src/llm_provider.py`): Unified adapter supporting Anthropic Claude and OpenAI GPT. Auto-detects provider from available API keys, configurable via `LLM_PROVIDER` env var. Gracefully handles missing keys with clear error messages.
-   **Email Layer** (`src/email_service.py`): Supports Replit Mail (on Replit), SMTP (self-hosted), or console logging (development). Auto-detects transport based on environment.
-   **Database**: PostgreSQL via `DATABASE_URL`, falls back to SQLite if not set. Zero-config for local development.
-   **Session Secret**: Reads from `SESSION_SECRET` env var, auto-generates a random secret if not set.
-   **Port**: Configurable via `PORT` env var, defaults to 5000.
-   **Frontend**: Landing page (`login.html`), pricing page (`pricing.html`), API docs page (`docs.html`), TOS page (`tos.html`), public audit page (`audit.html`), setup wizard (`setup_wizard.html`), and dashboard (`dashboard.html`) with SSE for real-time updates.
-   **First-Run Setup Wizard**: When no users exist in the database, presents a friendly setup wizard to create the first admin account. No manual database seeding required.
-   **Config Export/Import**: Branded JSON format with metadata header (generator, version, source URL, install_id, share_id). Import validates format and creates rules for the current tenant.
-   **Telemetry**: Opt-in anonymous telemetry with daily ping to cloud, transparency endpoint, and admin telemetry dashboard. Unique install_id generated on first boot.
-   **Email Verification**: Local auth accounts require email verification before dashboard access. First admin account is auto-verified.
-   **Password Reset**: Forgot password flow with time-limited reset tokens sent via email.
-   **Python SDK**: Installable SDK package (`sdk/` directory) for `pip install agentic-firewall`.

**Key Features & Implementations:**
-   **Agentic Loop Detector** (`src/loop_detector.py`): Detects hallucination loops (same tool + same args 3+ times in 30s), auto-blocks with 429, records events with estimated savings.
-   **Schema Validation Guard** (`src/schema_guard.py`): Per-tool JSON schema enforcement. Strict mode strips unauthorized params, flexible mode logs only. SchemaViolationEvent model tracks all violations.
-   **Credential Proxy** (`src/vault.py`): ProxyToken model with `agfw_` tokens. Agents use proxy tokens; real keys injected at gateway. Full token shown only on creation (one-time view); listings always mask tokens. One-click revocation. **Global Revoke** button for emergency breach response.
-   **Spend Monitor**: Real-time cost tracking in overview API (today_spend, daily_rate, projected_30d, total_savings). Dashboard shows Total Savings counter and burn rate. **Share My Savings** button generates downloadable branded image card.
-   **Risk Confidence Index** (`src/risk_index.py`): 0-100 trust scores per tool with GitHub reputation lookup (stars, age, activity), URL safety scanning (pattern-based), and automatic risk grading (A-F). All outputs labeled as "Intelligence Signals" with legal disclaimer. RiskSignal model tracks assessment history.
-   **Tool Safe Catalog** (`src/tool_catalog.py`): AI-powered safety grading (A-F) with schema enforcement toggle per tool.
-   **Blast Radius Governor** (`src/blast_radius.py`): Per-agent dual-limit system (rate-based + budget-based) with manual hard-lock reset.
-   **Identity Vault** (`src/vault.py`): Secure credential storage with proxy token layer on top.
-   **Deception & Goal Drift Detector**: Analyzes `inner_monologue` via LLM to identify and block deceptive agent behavior.
-   **Honeypot Tripwires**: Decoy tools designed to detect and alert on unauthorized access attempts, locking API keys upon trigger.
-   **Framework Integrations**: Pre-built SDK snippets for LangChain, CrewAI, and OpenAI Assistants.
-   **Org Management**: Create organizations, invite members, manage roles (owner, admin, member).
-   **API Key Management**: Generation, revocation, and toggling of API keys, scoped to specific tenants.
-   **Webhook System**: Supports persistent webhook configs and ad-hoc webhooks for agents.
-   **3-Step Onboarding**: Utility-first wizard (Generate API Key → Set Spend Limit → Shadow Mode).
-   **TOS Acceptance Gate**: Users must scroll through and accept updated Terms of Service (AS-IS, no-liability, proxy token responsibility, human-in-the-loop) before accessing dashboard. Timestamp tracked per user.

## External Dependencies
-   **Database**: PostgreSQL (production) / SQLite (development/testing)
-   **AI Service**: Anthropic Claude or OpenAI GPT (via `src/llm_provider.py` adapter)
-   **Authentication**: Replit Auth (when on Replit) or local auth (bcrypt)
-   **Email**: Replit Mail, SMTP, or console fallback (via `src/email_service.py`)
-   **ORM**: SQLAlchemy
-   **Web Framework**: Flask
-   **WSGI Server**: Gunicorn

## Deployment Paths
-   **Docker**: `docker-compose up -d` with included Dockerfile and docker-compose.yml
-   **Cloud (Managed SaaS)**: Users sign up via Replit Auth on Replit deployment
-   **Self-Hosted**: Local Python or any PaaS (Heroku, Railway, Render, etc.)
-   **Public Audit Tool**: Free lead-generation tool at `/audit`

## Key Environment Variables
-   `DATABASE_URL` - PostgreSQL connection string (optional, falls back to SQLite)
-   `SESSION_SECRET` - Session encryption key (optional, auto-generated)
-   `PORT` - Server port (default: 5000)
-   `LLM_PROVIDER` - "anthropic" or "openai" (auto-detected from keys)
-   `ANTHROPIC_API_KEY` - Anthropic Claude API key
-   `OPENAI_API_KEY` - OpenAI API key
-   `LLM_MODEL` - Override default model (default: claude-sonnet-4-5 / gpt-4o)
-   `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` - SMTP email settings
-   `APP_DOMAIN` - Public domain for webhook callbacks (auto-detected)
-   `TEMPLATE_URL` - Fork/deploy link for self-hosted users

## Key Endpoints
-   `GET /health` - Health check endpoint (DB status, uptime, version)
-   `POST /api/intercept` - Main agent tool call interception (includes loop detection, schema validation, proxy token resolution)
-   `GET /api/overview` - Dashboard overview stats (includes total_savings, loops_detected, spend projections)
-   `GET /api/loop-detector/events` - Loop detector event history
-   `GET /api/loop-detector/stats` - Loop detection statistics and savings
-   `PUT /api/tools/<id>/schema` - Set JSON schema and enforcement mode for a tool
-   `GET /api/schema-guard/stats` - Schema violation statistics
-   `GET /api/vault/proxy-tokens` - List proxy tokens (masked)
-   `POST /api/vault/proxy-tokens` - Generate new proxy token (one-time view of full token)
-   `POST /api/vault/proxy-tokens/<id>/revoke` - Revoke a proxy token
-   `POST /api/vault/proxy-tokens/revoke-all` - Emergency revoke all active proxy tokens
-   `GET /api/tools/<id>/risk-score` - Calculate risk confidence index for a tool
-   `GET /api/risk-signals` - List recent risk intelligence signals
-   `GET /api/risk-signals/summary` - Per-tool latest risk scores
-   `POST /api/risk-score/check` - Manually check risk score for a tool name
-   `POST /api/rules/export` - Export rules as branded JSON
-   `POST /api/rules/import` - Import rule packs
-   `GET /api/telemetry/transparency` - View telemetry transparency info
-   `POST /api/telemetry/ingest` - Receive telemetry pings from other instances
-   `GET /api/admin/telemetry-dashboard` - Admin dashboard with network-wide stats

## Security
-   **Rate Limiting**: Flask-Limiter applied to auth endpoints (login: 5/min, register: 3/hr, forgot-password: 3/hr, reset-password: 5/min, telemetry ingest: 10/min)

## Testing & CI/CD
-   **Test Suite**: pytest-based tests in `tests/` covering health, auth, rules CRUD, config export/import, telemetry, and overview endpoints
-   **CI Pipeline**: GitHub Actions (`.github/workflows/ci.yml`) runs tests and linting on push/PR to main
-   Run tests: `python -m pytest tests/ -v`

## Pending Integrations
-   **Stripe**: Payment processing for pricing tiers (Free/Pro/Enterprise) is not yet connected.
