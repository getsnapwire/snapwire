# Snapwire

## Overview
Snapwire is an AI-powered security gateway designed to intercept, audit, and control AI agent tool calls against user-defined automation rules. Its primary purpose is to act as "The Safety Fuse for Your AI Agents," preventing unauthorized or undesirable actions by AI agents. The project aims to provide real-time monitoring and control over AI operations, focusing on spend monitoring, security, and behavioral governance.

Key capabilities include:
- **Utility-First Positioning**: Focuses on spend monitoring, loop detection, and credential security.
- **Fuse Breaker (Loop Detector)**: Detects and blocks hallucination loops.
- **Schema Validation Guard**: Enforces per-tool JSON schema validation.
- **Snap-Tokens**: Proxy tokens replace raw API keys for enhanced security and one-click revocation.
- **Live Burn Meter**: Provides real-time cost tracking and spend projections.
- **The Snap (Kill-Switch)**: Emergency global revocation of all active Snap-Tokens.
- **Automation Rules**: AI-powered evaluation of agent tool calls against custom rules.
- **Multi-Tenancy**: Supports individual user workspaces and team collaboration.
- **Enhanced Security Features**: Tool Safe Catalog, Blast Radius Governor, Identity Vault, Deception Detection, Honeypot Tripwires.
- **Risk Confidence Index**: Provides trust scores per tool based on reputation and safety scanning.
- **Platform-Agnostic**: Deploys on various infrastructures and auto-detects environment for LLM, auth, email, database, and session layers.
- **Viral Growth Features**: Config export/import, opt-in telemetry, Share My Savings card.

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Browser notifications for blocked actions
- Plain-language explanations everywhere
- Footer disclaimer on all pages: "Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator."

## System Architecture
Snapwire is built with a Python Flask backend and supports PostgreSQL or SQLite databases via SQLAlchemy ORM.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented at the database level with `tenant_id` columns.
-   **Authentication**: Auto-detects environment, using Replit Auth or local username/password with bcrypt.
-   **LLM Provider Layer**: Unified adapter for Anthropic Claude and OpenAI GPT.
-   **Email Layer**: Supports Replit Mail, SMTP, or console logging.
-   **Database**: PostgreSQL (preferred) or SQLite.
-   **Frontend**: Includes a landing page, pricing page, API docs, TOS, privacy policy, public audit, setup wizard, and a dashboard with Server-Sent Events (SSE) for real-time updates.
-   **First-Run Setup Wizard**: Guides initial configuration when no users exist.
-   **Config Export/Import**: Branded JSON format for rules and configurations.
-   **Telemetry**: Opt-in anonymous usage data collection.
-   **Snap-Token Acknowledgment Gate**: Requires user acknowledgment of responsibility before first Snap-Token creation.
-   **Python SDK**: An installable SDK package for programmatic interaction.

**Key Features & Implementations:**
-   **Fuse Breaker**: Detects and automatically blocks recurring tool calls (hallucination loops) with a 429 status, records events, and estimates savings.
-   **Schema Validation Guard**: Enforces JSON schemas for tool arguments.
-   **Snap-Tokens**: Manages proxy tokens that abstract real API keys, enabling secure agent interaction and instant revocation.
-   **Live Burn Meter**: Provides real-time cost tracking, projecting daily burn rate and 30-day spend, with visual indicators and savings tracking.
-   **Risk Confidence Index**: Calculates a trust score (0-100) for each tool based on GitHub reputation and URL safety scans.
-   **Tool Safe Catalog**: AI-powered safety grading for tools.
-   **Blast Radius Governor**: Implements dual-limit systems per agent.
-   **Identity Vault**: Securely stores credentials.
-   **Deception & Goal Drift Detector**: Analyzes agent monologues via LLM for potential misalignments.
-   **Honeypot Tripwires**: Utilizes decoy tools to detect unauthorized access attempts.
-   **TOS Acceptance Gate**: Requires users to accept terms before dashboard access.
-   **Snap-Card Review Queue**: Presents blocked actions as structured "Snap-Cards" for review, with options to reject, edit & release, or temporarily trust the action.
-   **Trust Rules (24h TTL)**: Allows creation of temporary auto-approval rules for specific agent+tool combinations.

## External Dependencies
-   **Database**: PostgreSQL, SQLite
-   **AI Service**: Anthropic Claude, OpenAI GPT
-   **Authentication**: Replit Auth, bcrypt
-   **Email**: Replit Mail, SMTP
-   **ORM**: SQLAlchemy
-   **Web Framework**: Flask
-   **WSGI Server**: Gunicorn