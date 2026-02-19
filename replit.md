# Agentic Firewall

## Overview
The Agentic Firewall is an AI-powered system designed to secure AI agent operations by intercepting tool calls, auditing them against user-defined constitutional rules using an LLM (Claude or GPT), and blocking actions that violate these rules. Blocked actions are queued for manual human approval or denial via a web dashboard, accompanied by browser notifications.

The project is platform-agnostic and can be deployed on any infrastructure: Docker, Replit, Heroku, AWS, bare metal, etc.

Key capabilities include:
- **Constitutional AI Auditing**: Real-time evaluation of agent tool calls against a set of constitutional rules.
- **Multi-Tenancy**: Supports individual user workspaces and team collaboration through organizations, each with customizable rules and data.
- **Enhanced Security Features**: Includes a Tool Safe Catalog for grading tool safety, a Blast Radius Governor with dual limits (rate-based + budget-based) and manual reset, an Identity Vault for secure credential handling, Deception & Goal Drift Detection, and Honeypot Tripwires.
- **Platform-Agnostic**: LLM, auth, email, database, and session layers all auto-detect their environment and fall back gracefully.
- **Viral Growth**: Config export/import with branded metadata and share chains, opt-in telemetry, embeddable badges.

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
-   **Tool Safe Catalog**: AI-powered safety grading (A-F) for tools, with auto-blocking of unsafe tools.
-   **Blast Radius Governor**: Per-agent dual-limit system (rate-based + budget-based) with manual hard-lock reset from dashboard.
-   **Identity Vault**: Secure credential proxy, ensuring agents never directly access raw API keys.
-   **Deception & Goal Drift Detector**: Analyzes `inner_monologue` via LLM to identify and block deceptive agent behavior.
-   **Honeypot Tripwires**: Decoy tools designed to detect and alert on unauthorized access attempts, locking API keys upon trigger.
-   **Framework Integrations**: Pre-built SDK snippets for LangChain, CrewAI, and OpenAI Assistants.
-   **Org Management**: Create organizations, invite members, manage roles (owner, admin, member).
-   **API Key Management**: Generation, revocation, and toggling of API keys, scoped to specific tenants.
-   **Webhook System**: Supports persistent webhook configs and ad-hoc webhooks for agents.

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
-   `POST /api/intercept` - Main agent tool call interception endpoint
-   `GET /api/overview` - Dashboard overview stats
-   `POST /api/rules/export` - Export rules as branded JSON
-   `POST /api/rules/import` - Import rule packs
-   `GET /api/telemetry/transparency` - View telemetry transparency info
-   `GET /api/settings/telemetry` - Check/toggle telemetry status

## Pending Integrations
-   **Stripe**: Payment processing for pricing tiers (Free/Pro/Enterprise) is not yet connected.
