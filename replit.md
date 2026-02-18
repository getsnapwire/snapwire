# Agentic Firewall

## Overview
An AI-powered firewall that intercepts agent tool calls, audits them against a set of constitutional rules using Claude, and blocks actions that violate the rules. Blocked actions are queued for manual human approval or denial via a web dashboard with browser notifications. Authentication required via Replit Auth. Designed for commercialization with admin panel, user management, API key management, and real-time monitoring.

## Recent Changes
- 2026-02-18: Added dashboard UI for AI Rule Builder (NLP), Visual Rule Builder (dropdowns), shadow mode toggles, rule history with rollback, and policy sandbox
- 2026-02-18: Added API key management (generate, revoke, toggle keys per agent)
- 2026-02-18: Added webhook callback system (agents receive approve/deny results via POST)
- 2026-02-18: Added rule template presets (Safe Browsing, Financial Compliance, Code Safety, Data Protection)
- 2026-02-18: Added auto-approve logic for repeatedly approved rules and auto-deny timeout (30 min)
- 2026-02-18: Added real-time live action stream via Server-Sent Events (SSE)
- 2026-02-18: Added agent session tracking (view action chains per agent)
- 2026-02-18: Added weekly safety digest / summary report
- 2026-02-18: Added API key authentication for /api/intercept endpoint
- 2026-02-16: Added modern landing page / homepage with hero, features, how-it-works sections
- 2026-02-16: Added admin panel with user management (roles, access control)
- 2026-02-16: Added dashboard analytics: stats, violations-by-rule chart, recent activity timeline
- 2026-02-16: Added bulk approve/deny, CSV audit log export, activity summary banner
- 2026-02-16: Added Replit Auth login -- dashboard requires sign-in, API endpoints protected
- 2026-02-16: Added onboarding walkthrough overlay for first-time visitors (4-step guided tour)
- 2026-02-16: Updated auditor to generate plain-language explanations for non-technical users
- 2026-02-16: Renamed "guardrail" to "amendment" to match constitutional theme
- 2026-02-16: Added hover tooltips explaining every section of the dashboard
- 2026-02-16: Revamped Constitution tab with user-friendly rule cards, toggle switches, number steppers, display names, and "why it matters" hints
- 2026-02-16: Added rule management UI - add, edit, delete rules from dashboard
- 2026-02-16: Initial build - Flask API, Claude auditor, dashboard UI, browser notifications

## Architecture
- **Backend**: Python Flask (app.py + main.py) on port 5000
- **Database**: PostgreSQL via SQLAlchemy (users, OAuth sessions, roles, API keys)
- **Auth**: Replit Auth (OpenID Connect) via Flask-Dance + Flask-Login; API key auth for agent endpoints
- **Roles**: Admin (full access) and Viewer (read-only dashboard access)
- **AI Auditor**: Claude Sonnet 4.5 via Replit AI Integrations (Anthropic)
- **Frontend**: Landing page (login.html) + Dashboard (dashboard.html) with polling + SSE
- **Config**: constitution.json for rules
- **Webhooks**: POST callbacks to agents when actions are resolved
- **Auto-rules**: Auto-approve after 5 consecutive approvals; auto-deny after 30-minute timeout

## Project Structure
```
app.py                   # Flask app factory, SQLAlchemy setup
main.py                  # Routes, API endpoints, admin endpoints, SSE, API keys
replit_auth.py           # Replit Auth (OpenID Connect) integration
models.py                # User, OAuth, ApiKey database models
constitution.json        # Constitutional rules configuration
src/
  __init__.py
  constitution.py        # Rules loading and management
  auditor.py             # Claude-powered tool call auditor
  action_queue.py        # Action queue, webhooks, SSE, sessions, auto-approve/deny, digest
  rule_templates.py      # Pre-built rule template packs
templates/
  dashboard.html         # Main dashboard UI with all tabs
  login.html             # Modern landing page / homepage
  403.html               # Access denied page
static/
  style.css              # Dashboard styling
```

## Key API Endpoints
- `POST /api/intercept` - Submit a tool call for audit (API key or no auth -- for agent use)
- `GET /api/actions/pending` - List blocked actions awaiting approval (auth required)
- `GET /api/actions/<id>` - Get action status (API key or auth -- for agents to poll)
- `POST /api/actions/<id>/resolve` - Approve or deny a blocked action (admin only)
- `POST /api/actions/bulk-resolve` - Bulk approve/deny multiple actions (admin only)
- `GET /api/audit-log` - View audit history (auth required)
- `GET /api/audit-log/export` - Download audit log as CSV (auth required)
- `GET /api/stats` - Dashboard analytics and metrics (auth required)
- `GET /api/constitution` - View current rules (auth required)
- `PUT /api/constitution/rules/<name>` - Update a rule value (admin only)
- `POST /api/constitution/rules` - Create a new rule (admin only)
- `DELETE /api/constitution/rules/<name>` - Delete a rule (admin only)
- `PATCH /api/constitution/rules/<name>` - Update rule value, description, and severity (admin only)

## API Key Endpoints
- `GET /api/api-keys` - List user's API keys (auth required)
- `POST /api/api-keys` - Generate a new API key (admin only)
- `DELETE /api/api-keys/<id>` - Revoke an API key (admin only)
- `PATCH /api/api-keys/<id>/toggle` - Enable/disable an API key (admin only)

## Real-Time & Agent Endpoints
- `GET /api/stream` - Server-Sent Events live action stream (auth required)
- `GET /api/agents/sessions` - View agent session history (auth required)
- `GET /api/digest` - Weekly safety digest summary (auth required)

## Template Endpoints
- `GET /api/templates` - List available rule template packs (auth required)
- `GET /api/templates/<id>` - View template details (auth required)
- `POST /api/templates/<id>/install` - Install a rule template pack (admin only)

## Admin API Endpoints
- `GET /api/admin/users` - List all users with roles and status (admin only)
- `PATCH /api/admin/users/<id>/role` - Change user role (admin only)
- `PATCH /api/admin/users/<id>/access` - Revoke or restore user access (admin only)

## Auth Routes
- `/auth/replit_auth/login` - Start login flow
- `/auth/logout` - Log out and end session

## User Roles
- **Admin** - Full access: manage rules, approve/deny actions, manage users, API keys
- **Viewer** - Read-only: view dashboard, stats, audit log (cannot modify rules or manage users)
- First user to sign in gets admin role by default

## Webhook Integration
When submitting a tool call to `/api/intercept`, include a `webhook_url` field. When the action is resolved (approved/denied/auto-denied), the firewall will POST the result to that URL with the action details.

## API Key Authentication
Include `Authorization: Bearer af_YOUR_KEY` header when calling `/api/intercept` or `/api/actions/<id>`. API keys are managed from the dashboard's API Keys tab.

## User Preferences
- Dark-themed dashboard UI
- Browser notifications for blocked actions
- In-memory action queue (no database for actions)
- Constitutional theme: "amendments" not "guardrails"
- Plain-language explanations everywhere
- Modern SaaS-style landing page for marketing
