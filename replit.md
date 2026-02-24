# Snapwire

## Overview
Snapwire is "The Safety Fuse for Your AI Agents" – an AI-powered security gateway that intercepts AI agent tool calls, audits them against user-defined automation rules using an LLM, and blocks actions that violate these rules. Blocked actions are queued for manual human approval or denial via a web dashboard. The project aims to provide real-time monitoring and control over AI agent operations, focusing on spend monitoring, security, and behavioral governance.

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

## Testing
-   Run tests: `python -m pytest tests/ -v`
-   89 tests total: 52 core + 37 attack scenarios
-   Attack scenarios in `tests/scenarios/` cover 6 categories with memorable names (e.g., `sleeper_agent_aws_credential_harvest`, `recursive_token_drain_via_swap`, `dns_tunnel_exfiltration`)

## Dashboard Structure (6 Tabs)
- **Home** — Overview cards, burn meter, savings counter, tip banner
- **Activity** — Sub-tabs: Pending (with count badge), Audit Log, Live Stream, Digest
- **Rules** — Sub-tabs: My Rules, Rule History, Sandbox (test)
- **Agents** — Sub-tabs: Agents, Analytics
- **Security** (admin only) — Sub-tabs: Snap-Tokens, Honeypots, Blast Radius, Tool Catalog, Risk Intelligence
- **Settings** — Sub-tabs: API Keys, Organization, Account, Webhooks (admin), Users (admin), Telemetry (admin)
- External nav links: Leaderboard, Community Rules
- Help overlay: "?" button opens slide-in quickstart guide

## Rule Template Packs (8 total)
safe_browsing, financial_compliance, code_safety, data_protection, universal_starter, sql_redline, egress_allowlist, shell_safety

## Fork Experience (60-Second TTV)
- **Auto-Login**: Local/self-hosted first run auto-creates admin user + API key on localhost (no signup form). Falls back to setup wizard on public networks.
- **Pre-Loaded Rules**: New tenants get 22 rules active immediately: universal_starter (6) + sql_redline (6) + shell_safety (8) + 2 limit rules. All in enforce mode.
- **Try It Now Card**: Dashboard shows a ready-to-paste curl command (with real API key) that triggers a SQL Redline block. Dismissible after first block.
- **First-Block Celebration**: Toast notification + badge pulse when first action is blocked.
- **Simplified Tabs**: Local mode shows 3 primary tabs (Status / Kill Feed / Rules) with "More" dropdown for Agents, Security, Settings.
- **Local Mode Banner**: Reminds user to secure instance with a link to Settings > Account.

## Recent Changes
- **2026-02-24**: 60-Second TTV Implementation — Auto-login for local mode (localhost/private network only, with race condition protection). Pre-loaded 22 rules (universal_starter + sql_redline + shell_safety) on first tenant creation. Simplified 3-tab layout for self-hosted (Status/Kill Feed/Rules + More dropdown). Try It Now curl card with real API key. First-block celebration toast. Local mode security banner.
- **2026-02-24**: Dashboard Consolidation & Polish — Consolidated 22 tabs to 6 grouped tabs (Home, Activity, Rules, Agents, Security, Settings) with sub-tab navigation. Removed welcome banner and getting started checklist (wizard modal is the single onboarding flow). Added tip banner, empty states for all panels, and help overlay. Security fixes: tenant verification on user role/access endpoints, @require_admin on platform endpoints. Shell Safety rule template pack (8 rules: rm -rf, eval/exec, curl|bash, chmod 777, env export, alias override, nohup, redirect to sensitive paths). Telemetry enabled by default with DO_NOT_TRACK env var support. API docs expanded to ~30 endpoints (loop detection, shadow mode, trust rules, snap-tokens, config export/import, blast radius, error reference, rate limits). Dead code cleanup.
- **2026-02-24**: Competitive Positioning & UX Clarity — "Why Not Just a Sandbox?" section on landing page (two-layer diagram: Isolation vs Governance, with "5 Things Sandboxes Can't Stop" sub-section). Egress Allowlisting MVP accelerated from roadmap to shipped feature (rule template pack with configurable domain allowlist, moved from Roadmap to Core Features with NEW badge). FAQ entry: "How is Snapwire different from a cloud sandbox?" README comparison table expanded with "Agent Sandboxes" column + complementary framing paragraph. "Sandbox-Compatible" trust signal in hero area. "What is an AI Agent?" one-liner below hero for non-technical visitors. Plain-English subtitles on enterprise features (Shadow Merge → "Risk-Free Rule Testing", Goal Drift → "Behavior Change Warnings", Honeypot Tripwires → "Decoy Tool Detection"). Free Safety Audit preview section elevated on landing page with mockup score/vulnerabilities. README Quick Start cleanup: Zero Config callout, API key marked optional, Python 3.11+ requirement, `/health` verification step with example response, troubleshooting section (port conflicts, psycopg2 fallback, no-LLM-key).
- **2026-02-24**: V1 Launch Package — Landing page copy rewrite (hero: "Stop Your AI Agents Before They Break Something", outcome-focused feature descriptions, shorter FAQ). Live Kill Feed on landing page (anonymized public feed of blocked actions via `/api/public/feed`). Sentinel counter showing X/150 Founding Slots via `/api/public/stats`. Vibe-to-Rule input: type a rule in plain English, get Python enforcement code via LLM (`/api/public/vibe-to-rule`, rate-limited 5/hr/IP, graceful fallback without LLM key). SQL Redline rule template pack (6 rules: DROP TABLE, DELETE/UPDATE without WHERE, GRANT/REVOKE, TRUNCATE, ALTER DROP COLUMN). Community rule grader latency benchmarking (per-scenario timing, 5ms max threshold, auto-reject slow rules). Shadow Merge positioned as enterprise feature on landing page + dashboard tooltip. Public endpoints fully anonymized (no tenant/agent/tool data leakage).
- **2026-02-23**: Fork experience improvements — Enhanced `/health` endpoint (checks DB, secrets, LLM connectivity, feature status, first-run detection). Setup wizard now has 3 steps: welcome, environment check (hits `/health` to show DB/secrets/LLM status with actionable guidance), account creation with optional "Load starter rules" checkbox. Seed data endpoint (`POST /api/seed-data`) loads 3 security rules + $25/session spend limit. Getting Started checklist banner on dashboard (dismissible, tracks rules/key/token/test progress with progress bar). Updated `.env.example` with Replit-specific notes. README now has "Option 1: Fork on Replit" as fastest Quick Start path.
- **2026-02-23**: Community Leaderboard & Rules Catalog — 4-tier badge system (Fuse Apprentice → Circuit Breaker → Grid Operator → Sentinel Prime), auto-verified rule submissions via test suite, Wall of Fame (150 Founding Sentinel slots), community rules catalog with ratings/imports, achievement engine with savings milestones. New models: CommunityProfile, UserBadge, CommunityRule, RuleRating. New modules: `community/grader.py` (auto-grader), `community/achievements.py` (badge engine), `community/routes.py` (blueprint). New pages: `/leaderboard`, `/community-rules`.
- **2026-02-22**: Enterprise positioning — SECURITY.md threat model for Identity Vault (AES-256, HSM roadmap, Cryptographic Agility). README: "How Snapwire Compares" table (vs LiteLLM, Guardrails AI), "Compliance Readiness" section (EU AI Act Articles 9, 11, 12, 14), "Performance" section (Governance Tax framing). Roadmap: HSM Integration Q3, High-Velocity Engine Q3/Q4, Cryptographic Agility. Attack scenarios renamed with real-world agent-failure names.
- **2026-02-21**: Enhanced Snapwire Audit CLI — Multi-format log support (JSON array, JSONL, nested LangChain/CrewAI/AutoGPT structures with auto-detection). New detections: credential access (22 patterns), data exfiltration signals, velocity spikes. Severity levels, `--json` for CI/CD, exit codes. Sample logs in `examples/`.
- **2026-02-21**: Launch readiness — Rewrote README.md for GitHub. Attack scenario test suite (22 scenarios, 6 categories). "Total Saved" counter card on dashboard.
- **2026-02-21**: Legal liability copy refinements — enforce/govern vocabulary. Developer growth layer — `/rules/` directory, `snapwire_audit.py` CLI. Open-source preparation — Apache 2.0 LICENSE, SECURITY.md, CONTRIBUTING.md.