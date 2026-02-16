# Agentic Firewall

## Overview
An AI-powered firewall that intercepts agent tool calls, audits them against a set of constitutional rules using Claude, and blocks actions that violate the rules. Blocked actions are queued for manual human approval or denial via a web dashboard with browser notifications.

## Recent Changes
- 2026-02-16: Added rule management UI - add, edit, delete rules from dashboard
- 2026-02-16: Initial build - Flask API, Claude auditor, dashboard UI, browser notifications

## Architecture
- **Backend**: Python Flask (main.py) on port 5000
- **AI Auditor**: Claude Sonnet 4.5 via Replit AI Integrations (Anthropic)
- **Frontend**: Single-page dashboard (templates/dashboard.html) with polling-based notifications
- **Config**: constitution.json for rules

## Project Structure
```
main.py                  # Flask app entry point with API routes
constitution.json        # Constitutional rules configuration
src/
  __init__.py
  constitution.py        # Rules loading and management
  auditor.py             # Claude-powered tool call auditor
  action_queue.py        # Pending action queue and audit log
templates/
  dashboard.html         # Dashboard UI
static/
  style.css              # Dashboard styling
```

## Key API Endpoints
- `POST /api/intercept` - Submit a tool call for audit
- `GET /api/actions/pending` - List blocked actions awaiting approval
- `POST /api/actions/<id>/resolve` - Approve or deny a blocked action
- `GET /api/audit-log` - View audit history
- `GET /api/constitution` - View current rules
- `PUT /api/constitution/rules/<name>` - Update a rule value
- `POST /api/constitution/rules` - Create a new rule
- `DELETE /api/constitution/rules/<name>` - Delete a rule
- `PATCH /api/constitution/rules/<name>` - Update rule value, description, and severity

## User Preferences
- Dark-themed dashboard UI
- Browser notifications for blocked actions
- In-memory action queue (no database)
