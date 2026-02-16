# Agentic Firewall

## Overview
An AI-powered firewall that intercepts agent tool calls, audits them against a set of constitutional rules using Claude, and blocks actions that violate the rules. Blocked actions are queued for manual human approval or denial via a web dashboard with browser notifications. Authentication required via Replit Auth. Designed for commercialization with admin panel and user management.

## Recent Changes
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
- **Database**: PostgreSQL via SQLAlchemy (users, OAuth sessions, roles)
- **Auth**: Replit Auth (OpenID Connect) via Flask-Dance + Flask-Login
- **Roles**: Admin (full access) and Viewer (read-only dashboard access)
- **AI Auditor**: Claude Sonnet 4.5 via Replit AI Integrations (Anthropic)
- **Frontend**: Landing page (login.html) + Dashboard (dashboard.html) with polling-based notifications
- **Config**: constitution.json for rules

## Project Structure
```
app.py                   # Flask app factory, SQLAlchemy setup
main.py                  # Routes, API endpoints, admin endpoints
replit_auth.py           # Replit Auth (OpenID Connect) integration
models.py                # User (with role, is_active) and OAuth database models
constitution.json        # Constitutional rules configuration
src/
  __init__.py
  constitution.py        # Rules loading and management
  auditor.py             # Claude-powered tool call auditor
  action_queue.py        # Pending action queue, audit log, stats, bulk resolve
templates/
  dashboard.html         # Main dashboard UI (authenticated) with admin panel
  login.html             # Modern landing page / homepage (unauthenticated)
  403.html               # Access denied page
static/
  style.css              # Dashboard styling
```

## Key API Endpoints
- `POST /api/intercept` - Submit a tool call for audit (no auth required -- for agent use)
- `GET /api/actions/pending` - List blocked actions awaiting approval (auth required)
- `POST /api/actions/<id>/resolve` - Approve or deny a blocked action (auth required)
- `POST /api/actions/bulk-resolve` - Bulk approve/deny multiple actions (auth required)
- `GET /api/audit-log` - View audit history (auth required)
- `GET /api/audit-log/export` - Download audit log as CSV (auth required)
- `GET /api/stats` - Dashboard analytics and metrics (auth required)
- `GET /api/constitution` - View current rules (auth required)
- `PUT /api/constitution/rules/<name>` - Update a rule value (auth required)
- `POST /api/constitution/rules` - Create a new rule (auth required)
- `DELETE /api/constitution/rules/<name>` - Delete a rule (auth required)
- `PATCH /api/constitution/rules/<name>` - Update rule value, description, and severity (auth required)

## Admin API Endpoints
- `GET /api/admin/users` - List all users with roles and status (admin only)
- `PATCH /api/admin/users/<id>/role` - Change user role (admin only)
- `PATCH /api/admin/users/<id>/access` - Revoke or restore user access (admin only)

## Auth Routes
- `/auth/replit_auth/login` - Start login flow
- `/auth/logout` - Log out and end session

## User Roles
- **Admin** - Full access: manage rules, approve/deny actions, manage users
- **Viewer** - Read-only: view dashboard, stats, audit log (cannot modify rules or manage users)
- First user to sign in gets admin role by default

## User Preferences
- Dark-themed dashboard UI
- Browser notifications for blocked actions
- In-memory action queue (no database for actions)
- Constitutional theme: "amendments" not "guardrails"
- Plain-language explanations everywhere
- Modern SaaS-style landing page for marketing
