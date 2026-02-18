# Agentic Firewall

## Overview
The Agentic Firewall is an AI-powered system designed to secure AI agent operations by intercepting tool calls, auditing them against user-defined constitutional rules using Claude, and blocking actions that violate these rules. Blocked actions are queued for manual human approval or denial via a web dashboard, accompanied by browser notifications.

Key capabilities include:
- **Constitutional AI Auditing**: Real-time evaluation of agent tool calls against a set of constitutional rules.
- **Multi-Tenancy**: Supports individual user workspaces and team collaboration through organizations, each with customizable rules and data.
- **Enhanced Security Features**: Includes a Tool Safe Catalog for grading tool safety, a Blast Radius Governor for rate limiting, an Identity Vault for secure credential handling, Deception & Goal Drift Detection, and Honeypot Tripwires.
- **Comprehensive Management**: Provides an admin panel, user management, API key management, real-time monitoring, and a web dashboard for rule creation (AI-powered NLP or visual builder), action resolution, and analytics.
- **Commercialization Focus**: Built for market potential with features supporting enterprise deployment and user engagement.

## User Preferences
- Dark-themed dashboard UI
- Browser notifications for blocked actions
- Constitutional theme: "amendments" not "guardrails"
- Plain-language explanations everywhere
- Modern SaaS-style landing page for marketing

## System Architecture
The Agentic Firewall is built with a Python Flask backend and a PostgreSQL database utilizing SQLAlchemy for ORM.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented at the database level with `tenant_id` columns across relevant models. Each user receives a personal tenant upon first login, and organizations provide shared tenant spaces. A dashboard workspace switcher allows seamless switching between tenants.
-   **Authentication**: Utilizes Replit Auth (OpenID Connect) via Flask-Dance and Flask-Login for dashboard access, and API key authentication for agent-facing endpoints (`/api/intercept`).
-   **AI Auditor**: Leverages Claude via Replit AI Integrations (Anthropic) for constitutional rule auditing, deception detection, and tool safety grading.
-   **Frontend**: Consists of a modern landing page (`login.html`) and a dashboard (`dashboard.html`) featuring polling and Server-Sent Events (SSE) for real-time updates.
-   **Security**: Incorporates input sanitization (SQL/prompt injection, path traversal), rate limiting per API key, and secure credential handling via the Identity Vault.
-   **Rule Management**: Constitution rules are database-backed and tenant-scoped, supporting versioning, import/export, and rollback. An AI Rule Builder (NLP) and Visual Rule Builder enhance rule creation.
-   **Action Resolution**: Blocked actions are managed in a queue, with support for manual approval/denial, bulk operations, auto-approval for recurring actions, and auto-denial after a timeout. Webhook callbacks notify agents of resolution outcomes.
-   **Monitoring & Notifications**: Features a comprehensive audit log, dashboard analytics, real-time activity streams via SSE, and Slack/webhook integrations for critical alerts.

**UI/UX Decisions:**
-   User-friendly dashboard with rule cards, toggle switches, number steppers, and "why it matters" hints.
-   Onboarding walkthrough for first-time users.
-   Hover tooltips for detailed explanations.

**Key Features & Implementations:**
-   **Tool Safe Catalog**: AI-powered safety grading (A-F) for tools, with auto-blocking of unsafe tools.
-   **Blast Radius Governor**: Per-agent sliding window rate limiter with auto-lockout capabilities.
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
-   **Notifications**: Slack (via webhooks)
-   **ORM**: SQLAlchemy
-   **Web Framework**: Flask
-   **WSGI Server**: Gunicorn