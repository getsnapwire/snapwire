# Agentic Firewall

## Overview
The Agentic Firewall is an AI-powered system designed to secure AI agent operations by intercepting tool calls, auditing them against user-defined constitutional rules using Claude, and blocking actions that violate these rules. Blocked actions are queued for manual human approval or denial via a web dashboard, accompanied by browser notifications.

Key capabilities include:
- **Constitutional AI Auditing**: Real-time evaluation of agent tool calls against a set of constitutional rules.
- **Multi-Tenancy**: Supports individual user workspaces and team collaboration through organizations, each with customizable rules and data.
- **Enhanced Security Features**: Includes a Tool Safe Catalog for grading tool safety, a Blast Radius Governor with dual limits (rate-based + budget-based) and manual reset, an Identity Vault for secure credential handling, Deception & Goal Drift Detection, and Honeypot Tripwires.
- **Comprehensive Management**: Provides an admin panel, user management, API key management, real-time monitoring, and a web dashboard for rule creation (AI-powered NLP or visual builder), action resolution, and analytics.
- **Commercialization Focus**: Built for market potential with features supporting enterprise deployment and user engagement.

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Browser notifications for blocked actions
- Constitutional theme: "amendments" not "guardrails"
- Plain-language explanations everywhere
- Modern SaaS-style landing page with light theme for marketing

## System Architecture
The Agentic Firewall is built with a Python Flask backend and a PostgreSQL database utilizing SQLAlchemy for ORM.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented at the database level with `tenant_id` columns across relevant models. Each user receives a personal tenant upon first login, and organizations provide shared tenant spaces. A dashboard workspace switcher allows seamless switching between tenants.
-   **Authentication**: Utilizes Replit Auth (OpenID Connect) via Flask-Dance and Flask-Login for dashboard access, and API key authentication for agent-facing endpoints (`/api/intercept`).
-   **AI Auditor**: Leverages Claude via Replit AI Integrations (Anthropic) for constitutional rule auditing, deception detection, and tool safety grading.
-   **Frontend**: Consists of a modern landing page (`login.html`), pricing page (`pricing.html`), API docs page (`docs.html`), TOS acceptance page (`tos.html`), public audit page (`audit.html`), and a dashboard (`dashboard.html`) featuring polling and Server-Sent Events (SSE) for real-time updates. Dashboard includes dark/light mode toggle.
-   **TOS Gate**: First-run experience requires authenticated users to scroll through and accept Terms of Service before accessing the dashboard. Acceptance tracked via `tos_accepted_at` timestamp on User model. Button disabled until user scrolls to bottom.
-   **Security**: Incorporates input sanitization (SQL/prompt injection, path traversal), rate limiting per API key, and secure credential handling via the Identity Vault.
-   **Rule Management**: Constitution rules are database-backed and tenant-scoped, supporting versioning, import/export, and rollback. An AI Rule Builder (NLP) and Visual Rule Builder enhance rule creation.
-   **Action Resolution**: Blocked actions are managed in a queue, with support for manual approval/denial, bulk operations, auto-approval for recurring actions, and auto-denial after a timeout. Webhook callbacks notify agents of resolution outcomes.
-   **Monitoring & Notifications**: Features a comprehensive audit log, usage analytics with charts (timeline, risk trends, top tools), real-time activity streams via SSE, Slack/webhook integrations, and email notification settings for critical alerts.
-   **Public Pages**: Pricing page with three tiers (Free/Pro/Enterprise) and full API documentation page with Python/Node.js SDK examples.

**UI/UX Decisions:**
-   User-friendly dashboard with rule cards, toggle switches, number steppers, and "why it matters" hints.
-   3-step onboarding wizard for first-time users (install rules, generate API key, test sandbox). Tracked via `onboarding_completed_at` on User model.
-   Dashboard Overview/Home tab with key metrics at a glance (total intercepts, blocks, agents, recent activity).
-   Quick-copy SDK snippets (Python/Node.js/cURL) shown inline after API key generation.
-   Hover tooltips for detailed explanations.
-   Cloud vs Self-Hosted feature comparison matrix on pricing page.

**Key Features & Implementations:**
-   **Tool Safe Catalog**: AI-powered safety grading (A-F) for tools, with auto-blocking of unsafe tools.
-   **Blast Radius Governor**: Per-agent dual-limit system (rate-based + budget-based) with manual hard-lock reset from dashboard.
-   **Identity Vault**: Secure credential proxy, ensuring agents never directly access raw API keys.
-   **Deception & Goal Drift Detector**: Analyzes `inner_monologue` via Claude to identify and block deceptive agent behavior.
-   **Honeypot Tripwires**: Decoy tools designed to detect and alert on unauthorized access attempts, locking API keys upon trigger.
-   **Org Management**: Functionality to create organizations, invite members with shareable links, manage roles (owner, admin, member), and track usage per tenant.
-   **API Key Management**: Generation, revocation, and toggling of API keys, scoped to specific tenants.
-   **Webhook System**: Supports both persistent webhook configurations and ad-hoc webhooks for agents to receive action resolution results.

## External Dependencies
-   **Database**: PostgreSQL
-   **AI Service**: Claude (via Replit AI Integrations / Anthropic)
-   **Authentication**: Replit Auth (OpenID Connect)
-   **Email**: Replit Mail (via OpenInt mailer API, no external service needed)
-   **Notifications**: Slack (via webhooks), Email (via Replit Mail)
-   **ORM**: SQLAlchemy
-   **Web Framework**: Flask
-   **WSGI Server**: Gunicorn

## Deployment Paths
-   **Cloud (Managed SaaS)**: Users sign up via Replit Auth and get a fully managed experience with dashboard, analytics, and auto-scaling.
-   **Self-Hosted (Replit Template)**: Users register (name, email, company, use case) before accessing the template. Registrations tracked in `self_hosted_installs` table. Same database schema enables future migration to Cloud.
-   **Public Audit Tool**: Free lead-generation tool at `/audit`. Anyone can paste a system prompt to get an AI-powered security analysis with Safety Score (0-100), vulnerability cards, and a downloadable shareable PNG image (1200x630). Rate limited to 10/hour per IP. Tracked in `public_audits` table.

## Key Endpoints
-   `GET /health` - Health check endpoint for self-hosted monitoring (DB status, uptime, version)
-   `GET /api/overview` - Dashboard overview stats (total intercepts, blocks, agents, recent activity)
-   `GET /api/onboarding/status` - Check onboarding progress (rules, keys, tested)
-   `POST /api/onboarding/complete` - Mark onboarding as completed
-   `GET /api/admin/self-hosted` - View self-hosted registrations (requires login)
-   `GET /api/admin/public-audits` - View public audit stats and recent audits (requires login)

## Pending Integrations
-   **Stripe**: Payment processing for pricing tiers (Free/Pro/Enterprise) is not yet connected. User dismissed the Stripe connector setup. To enable billing, the user needs to connect Stripe via the integrations panel or provide a Stripe API key as a secret.