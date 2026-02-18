# Agentic Firewall

## Overview
An AI-powered firewall that intercepts agent tool calls, audits them against a set of constitutional rules using Claude, and blocks actions that violate the rules. Blocked actions are queued for manual human approval or denial via a web dashboard with browser notifications. Full multi-tenant support: individual users get personal workspaces with their own rules and data, and can create/join organizations for team collaboration. Authentication via Replit Auth. Designed for commercialization with admin panel, user management, API key management, and real-time monitoring.

## Recent Changes
- 2026-02-18: Added multi-tenant architecture: Organization and OrgMembership models, ConstitutionRule model (DB-backed per-tenant rules)
- 2026-02-18: Added workspace switcher UI, org management panel, account settings, quick start guide
- 2026-02-18: Migrated constitution rules from JSON file to database with per-tenant scoping
- 2026-02-18: Added tenant_id column to all data models (AuditLogEntry, PendingAction, ApiKey, WebhookConfig, RuleVersion, AutoApproveCount)
- 2026-02-18: Added org management: create orgs, invite members via shareable links, manage roles, leave/remove members
- 2026-02-18: Added personal tenant auto-initialization with default rules on first login
- 2026-02-18: Added usage tracking per tenant (UsageRecord model, API call counting)
- 2026-02-18: Configured production deployment with Gunicorn
- 2026-02-18: Added Slack/webhook notification system for critical blocked actions with configurable thresholds
- 2026-02-18: Added webhook management panel (persistent webhook URLs per agent, test webhooks)
- 2026-02-18: Added rate limiting configuration UI (per-agent limits, usage visualization)
- 2026-02-18: Added rule import/export (JSON export/import for constitution portability)
- 2026-02-18: Built multi-agent comparison dashboard with per-agent trust scores and violation stats
- 2026-02-18: Added audit log search & filters (date range, agent, status, rule name, keyword search)
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
- **Database**: PostgreSQL via SQLAlchemy
  - User, OAuth, Organization, OrgMembership (multi-tenant)
  - ConstitutionRule (per-tenant rules, replaces constitution.json)
  - ApiKey, AuditLogEntry, PendingAction (all tenant-scoped)
  - WebhookConfig, RuleVersion, AutoApproveCount (all tenant-scoped)
  - NotificationSetting, UsageRecord (per-tenant config & tracking)
- **Multi-Tenancy**: Each user has a personal tenant; users can also create/join organizations
  - Personal tenant: user_id-based, auto-created on first login with default rules
  - Org tenant: org_id-based, shared rules and data among org members
  - Workspace switcher in dashboard header for switching between tenants
  - API keys are scoped to a tenant, so agent API calls use the correct tenant context
- **Auth**: Replit Auth (OpenID Connect) via Flask-Dance + Flask-Login; API key auth for agent endpoints
- **Roles**: Admin (full access) and Viewer (read-only dashboard access); Org roles: owner/admin/member
- **AI Auditor**: Claude via Replit AI Integrations (Anthropic)
- **Frontend**: Landing page (login.html) + Dashboard (dashboard.html) with polling + SSE
- **Webhooks**: POST callbacks to agents when actions are resolved + persistent webhook configs
- **Notifications**: Slack webhook integration for critical blocked actions
- **Auto-rules**: Auto-approve after 5 consecutive approvals; auto-deny after 30-minute timeout
- **Security**: Input sanitization (SQL/prompt injection, path traversal), rate limiting per API key
- **Deployment**: Gunicorn with autoscale on Replit

## Project Structure
```
app.py                   # Flask app factory, SQLAlchemy setup
main.py                  # Routes, API endpoints, admin endpoints, SSE, API keys, tenant/org endpoints
replit_auth.py           # Replit Auth (OpenID Connect) integration
models.py                # User, OAuth, Organization, OrgMembership, ConstitutionRule, ApiKey, AuditLogEntry, PendingAction, WebhookConfig, RuleVersion, AutoApproveCount, NotificationSetting, UsageRecord
src/
  __init__.py
  tenant.py              # Tenant helpers: get_current_tenant_id, ensure_personal_tenant, switch_tenant, install_default_rules
  constitution.py        # DB-backed rules loading, management, versioning, import/export (per-tenant)
  auditor.py             # Claude-powered tool call auditor (tenant-aware)
  action_queue.py        # Action queue, webhooks, SSE, sessions, auto-approve/deny, digest (tenant-scoped)
  rule_templates.py      # Pre-built rule template packs
  nlp_rule_builder.py    # AI-powered natural language rule parsing and conflict detection
  rate_limiter.py        # Per-API-key rate limiting with sliding window
  input_sanitizer.py     # Input sanitization for SQL injection, prompt injection, path traversal
  notifications.py       # Slack and webhook notification system
templates/
  dashboard.html         # Main dashboard UI with workspace switcher, org panel, account settings, quick start guide
  login.html             # Modern landing page / homepage
  403.html               # Access denied page
static/
  style.css              # Dashboard styling
```

## Multi-Tenant API Endpoints
- `GET /api/tenant/current` - Get current tenant info and list of available tenants
- `POST /api/tenant/switch` - Switch active workspace (personal or org)
- `POST /api/orgs` - Create a new organization
- `GET /api/orgs/<id>` - Get org details including members
- `PATCH /api/orgs/<id>` - Update org name/slug
- `POST /api/orgs/<id>/invite` - Generate an invite link
- `POST /api/orgs/join/<token>` - Join org via invite token
- `DELETE /api/orgs/<id>/members/<user_id>` - Remove member or leave org
- `PATCH /api/orgs/<id>/members/<user_id>/role` - Change member role
- `GET /api/account` - Get current user account info
- `PATCH /api/account` - Update display name
- `GET /api/usage` - Get usage history for current tenant

## Key API Endpoints
- `POST /api/intercept` - Submit a tool call for audit (API key required)
- `GET /api/actions/pending` - List blocked actions awaiting approval (auth required)
- `GET /api/actions/<id>` - Get action status (API key or auth -- for agents to poll)
- `POST /api/actions/<id>/resolve` - Approve or deny a blocked action (admin only)
- `POST /api/actions/bulk-resolve` - Bulk approve/deny multiple actions (admin only)
- `GET /api/audit-log` - View audit history with filters (auth required)
- `GET /api/audit-log/export` - Download audit log as CSV (auth required)
- `GET /api/stats` - Dashboard analytics and metrics (auth required)
- `GET /api/constitution` - View current rules (auth required)
- `GET /api/constitution/export` - Download constitution as JSON file (auth required)
- `POST /api/constitution/import` - Import rules from JSON (admin only)
- `PUT /api/constitution/rules/<name>` - Update a rule value (admin only)
- `POST /api/constitution/rules` - Create a new rule (admin only)
- `DELETE /api/constitution/rules/<name>` - Delete a rule (admin only)
- `PATCH /api/constitution/rules/<name>` - Update rule value, description, and severity (admin only)
- `PATCH /api/constitution/rules/<name>/mode` - Update rule mode: enforce/shadow/disabled (admin only)
- `GET /api/constitution/history` - View rule change history (auth required)
- `POST /api/constitution/rollback/<id>` - Rollback a rule change (admin only)
- `POST /api/sandbox/test` - Sandbox test a tool call without recording it (auth required)

## Rule Builder Endpoints
- `POST /api/rules/parse` - AI-powered natural language rule parsing (admin only)
- `POST /api/rules/conflicts` - Check for rule conflicts (auth required)

## API Key Endpoints
- `GET /api/api-keys` - List user's API keys (auth required)
- `POST /api/api-keys` - Generate a new API key (admin only)
- `DELETE /api/api-keys/<id>` - Revoke an API key (admin only)
- `PATCH /api/api-keys/<id>/toggle` - Enable/disable an API key (admin only)

## Agent & Trust Score Endpoints
- `GET /api/agents/trust-scores` - Get per-agent trust scores and violation stats (auth required)
- `GET /api/agents/<agent_id>/actions` - Get recent actions for a specific agent (auth required)
- `GET /api/agents/sessions` - View agent session history (auth required)

## Real-Time Endpoints
- `GET /api/stream` - Server-Sent Events live action stream (auth required)
- `GET /api/digest` - Weekly safety digest summary (auth required)

## Webhook Management Endpoints
- `GET /api/webhooks` - List webhook configurations (auth required)
- `POST /api/webhooks` - Create a webhook config (admin only)
- `DELETE /api/webhooks/<id>` - Delete a webhook (admin only)
- `PATCH /api/webhooks/<id>/toggle` - Enable/disable a webhook (admin only)
- `POST /api/webhooks/<id>/test` - Send a test webhook (admin only)

## Rate Limiting Endpoints
- `GET /api/rate-limits` - Get rate limit config and per-key usage (admin only)
- `PATCH /api/rate-limits/global` - Update global rate limit (admin only)

## Notification Endpoints
- `GET /api/notifications/settings` - View notification settings (auth required)
- `PUT /api/notifications/settings` - Update notification settings (admin only)
- `POST /api/notifications/test-slack` - Send a test Slack notification (admin only)

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
- **Admin** - Full access: manage rules, approve/deny actions, manage users, API keys, webhooks, rate limits, notifications
- **Viewer** - Read-only: view dashboard, stats, audit log (cannot modify rules or manage users)
- First user to sign in gets admin role by default
- **Org Owner** - Full control over organization settings, members, and rules
- **Org Admin** - Can manage org rules and members
- **Org Member** - Read-only access to org workspace

## Webhook Integration
When submitting a tool call to `/api/intercept`, include a `webhook_url` field. When the action is resolved (approved/denied/auto-denied), the firewall will POST the result to that URL with the action details. Persistent webhooks can also be configured via the Settings panel.

## API Key Authentication
Include `Authorization: Bearer af_YOUR_KEY` header when calling `/api/intercept` or `/api/actions/<id>`. API keys are managed from the dashboard's API Keys tab. Each API key is scoped to a specific tenant (personal or org workspace).

## User Preferences
- Dark-themed dashboard UI
- Browser notifications for blocked actions
- Constitutional theme: "amendments" not "guardrails"
- Plain-language explanations everywhere
- Modern SaaS-style landing page for marketing
