# Snapwire

## Overview
Snapwire is an open-source Agentic Runtime Security (ARS) platform designed to govern AI agent tool calls. It provides a deterministic gatekeeper for mission-critical data by intercepting, auditing, and controlling agent actions against user-defined automation rules. Key capabilities include real-time cost tracking, loop detection, secure credential proxy (Snap-Tokens), global token revocation, AI-powered evaluation, and compliance-ready audit trails. Snapwire aims to provide "Headless Governance Infrastructure" and a "60-Second Agentic Runtime Security Layer for your AI Agents," supporting multi-tenancy and platform-agnostic deployment. It incorporates features aligned with NISTIR 8596 and EU AI Act compliance.

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Browser notifications for runtime violations
- Plain-language explanations everywhere
- Footer disclaimer on all pages: "Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator."

## System Architecture
Snapwire is built with a Python Flask backend, utilizing SQLAlchemy ORM for database interactions.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented via `tenant_id` columns in the database.
-   **Authentication**: Auto-detects environment for Replit Auth or uses local username/password with bcrypt. Supports multiple super administrators.
-   **LLM Provider Layer**: Unified adapter for Anthropic Claude and OpenAI GPT.
-   **Email Layer**: Configurable for Replit Mail, SMTP, or console logging.
-   **Database**: Supports PostgreSQL (preferred) or SQLite.
-   **Frontend**: Features a landing page, pricing page, API docs, legal pages, public audit, setup wizard, and a dashboard with Server-Sent Events (SSE) for real-time updates.
-   **First-Run Setup Wizard**: Guides initial configuration and includes a "What to Expect After Forking" visual timeline.
-   **Config Export/Import**: Branded JSON format for rules and configurations.
-   **Telemetry**: Opt-in anonymous usage data collection.
-   **Snap-Token Acknowledgment Gate**: Requires user acknowledgment of responsibility before first Snap-Token creation.
-   **Python SDK**: An installable SDK package for programmatic interaction.
-   **Compliance Integration**: Features align with NISTIR 8596 and EU AI Act, including PDF compliance reports, automated tagging, and an AIBOM Generator (CycloneDX v1.7 with `nist:ir-8596-control` tags on every component and global `nist:ir-8596-features-mapped: 55` / `nist:ir-8596-coverage: 100%` properties).
-   **BYOK (Bring Your Own Key) Model**: Allows tenants to store encrypted LLM API keys.
-   **Sentinel Proxy (Sidecar)**: A Dockerized, transparent reverse proxy that intercepts LLM API traffic, routes it through Snapwire governance, and operates in `observe`, `audit`, or `enforce` modes. It supports 9 auto-detected protocols (OpenAI, Anthropic, Google Gemini, Cohere, AWS Bedrock, LangChain, MCP, A2A, Generic JSON-RPC) and allows custom protocol detectors via a registry-based architecture and a "Detector Lab" UI for on-the-fly generation. It injects headers for provenance and tracks latency. The `X-Snapwire-Signature` header includes `agent_id` in the HMAC payload (`agent_id.trace_id.timestamp.path`) for operator-traceable digital watermarking.
-   **Engine Room**: A super-admin dashboard with system health monitoring, batch ingestor UI, chaos lab, global burn meter, stealth control, telemetry, HITL evidence, detector lab, latency monitor, and shadow agents.
-   **Three-Tier Role Model**: Platform Admin, Workspace Owner, and Viewer roles.

**Key Features & Implementations:**
-   **Runtime Security**: Fuse Breaker (loop detection), Schema Validation Guard, Snap-Tokens (secure proxy/revocation), Live Burn Meter (cost tracking), Risk Confidence Index, Tool Safe Catalog (AI-powered safety grading), Blast Radius Governor (dual-limit systems), Identity Vault (credential storage), Deception & Goal Drift Detector, Honeypot Tripwires, OpenClaw (redirect attack detector), Taint Tracking (cross-call data-flow governance), Session Pulse (continuous token re-validation), Deterministic Hold Window (for high-risk calls), Strict Reasoning Toggle.
-   **Human-in-the-Loop (HITL) & Remediation**: Snap-Card Review Queue for runtime violations, Context-Aware Remediation Prompts (LLM-powered fix suggestions), Trust Rules (24h TTL auto-approval), Auto-Triage Rules.
-   **Monitoring & Auditing**: Forensic Lineage Map (visual chain-of-command), Reasoning Enforcement (requires `inner_monologue`), Thinking Token Sentinel (detects logic loops/latency anomalies), Vibe-Summary (plain-English summaries), Vibe-Audit Weekly Summarizer (executive summaries).
-   **Compliance & Governance**: Deployer Compliance Portal, Consequentiality Tagging, Headless Compliance API Docs, Legal Counsel Acknowledgment Gate, Substantial Modification Trigger, NIST-2025-0035 RFI Commentary Generator (`generate_nist_commentary.py` produces `nist_rfi_responses.txt` with regulatory-grade responses for all 55 features mapped to RFI sections).
-   **System Operations**: Batch Ingestor (processes MCP tool schemas), Self-Correction Loop (manages auto-healed schemas), Watchdog Script (automated ingestor runs), Environment Validator, System Health Tab, Live NIST Enforcement Heatmap, Unmanaged Agent Discovery (Shadow Agents).
-   **User Experience**: Enhanced Onboarding Overlay, API Docs Try It Playground, Snapwire CLI for setup and management.
-   **Snapwire CLI**: Typer-based CLI (`snapwire_cli.py`) with four commands: `snapwire init` (generates `.snapwire.yaml` config and `.env.example`), `snapwire check` (preflight validation with Regulatory Readiness summary: 55/55 features, NIST 100%, EU AI Act 100%), `snapwire up` (starts Flask + Sentinel Proxy by default with `SNAPWIRE SECURED` banner; `--no-proxy` to disable), `snapwire aibom` (generates CycloneDX v1.7 AIBOM JSON with NIST IR 8596 control tags). Rich-formatted terminal output.

## External Dependencies
-   **Database**: PostgreSQL, SQLite
-   **AI Service**: Anthropic Claude, OpenAI GPT
-   **Authentication**: Replit Auth, bcrypt
-   **Email**: Replit Mail, SMTP
-   **ORM**: SQLAlchemy
-   **Web Framework**: Flask
-   **WSGI Server**: Gunicorn
-   **PDF Generation**: fpdf2
-   **Async HTTP**: aiohttp
-   **Slack Integration**: slack-bolt
-   **CLI Framework**: Typer, Rich