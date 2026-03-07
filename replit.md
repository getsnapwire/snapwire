# Snapwire

## Overview
Snapwire is an Agentic Runtime Security (ARS) platform — an open-source governance layer for the AI Agentic Economy. It intercepts, audits, and controls AI agent tool calls against user-defined automation rules, acting as a deterministic gatekeeper for mission-critical data. Key capabilities include real-time cost tracking, loop detection, credential proxy (Snap-Tokens), emergency global token revocation, AI-powered evaluation, and compliance-ready audit trails. It supports multi-tenancy and deploys platform-agnostically, providing "Headless Governance Infrastructure" and a "60-Second Agentic Runtime Security Layer for your AI Agents."

## User Preferences
- Dashboard supports dark/light mode toggle (default: dark, saved in localStorage)
- Browser notifications for runtime violations
- Plain-language explanations everywhere
- Footer disclaimer on all pages: "Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator."

## System Architecture
Snapwire is built with a Python Flask backend and supports PostgreSQL or SQLite databases via SQLAlchemy ORM.

**Core Architectural Patterns & Decisions:**
-   **Multi-Tenancy**: Implemented at the database level with `tenant_id` columns.
-   **Authentication**: Auto-detects environment, using Replit Auth or local username/password with bcrypt. Super admin access via `/admin-agent` route.
-   **Multi-Admin Support**: `ADMIN_EMAIL` supports comma-separated emails for multiple super admins (e.g., `hello@getsnapwire.com,fastfitness4u@gmail.com`).
-   **LLM Provider Layer**: Unified adapter for Anthropic Claude and OpenAI GPT.
-   **Email Layer**: Supports Replit Mail, SMTP, or console logging.
-   **Database**: PostgreSQL (preferred) or SQLite.
-   **Frontend**: Includes a landing page, pricing page, API docs, TOS, privacy policy, public audit, setup wizard, and a dashboard with Server-Sent Events (SSE) for real-time updates.
-   **First-Run Setup Wizard**: Guides initial configuration.
-   **Config Export/Import**: Branded JSON format for rules and configurations.
-   **Telemetry**: Opt-in anonymous usage data collection.
-   **Snap-Token Acknowledgment Gate**: Requires user acknowledgment of responsibility before first Snap-Token creation.
-   **Python SDK**: An installable SDK package for programmatic interaction.
-   **NISTIR 8596 Alignment**: Includes features for traceability, content hash integrity, and PDF compliance reports.
-   **BYOK (Bring Your Own Key) Model**: Allows tenants to store encrypted LLM API keys.
-   **Sentinel Proxy (Sidecar)**: A transparent reverse proxy that intercepts LLM API traffic, routes it through Snapwire governance, and operates in `observe`, `audit`, or `enforce` modes. Dockerized as a sidecar service, it injects headers for provenance. Auto-detects 9 protocols: OpenAI (+ Mistral, Azure OpenAI), Anthropic, Google Gemini, Cohere, AWS Bedrock, LangChain, MCP, A2A, and Generic JSON-RPC. Registry-based architecture (`@register_protocol` decorator) — adding a new protocol is one function, zero proxy changes. Custom detectors auto-loaded from `sentinel/custom_detectors.py` (survives upstream updates).
-   **Protocol Detector Generator (Detector Lab)**: Engine Room sub-tab where admins paste a sample JSON payload from any LLM provider and Snapwire generates a working `@register_protocol` detector function. One-click Save & Activate writes to `sentinel/custom_detectors.py` and hot-reloads. Shows all active detectors (built-in vs custom). Makes Snapwire instantly compatible with any LLM provider.

**Key Features & Implementations:**
-   **Fuse Breaker**: Detects and blocks recurring tool calls (hallucination loops).
-   **Schema Validation Guard**: Enforces JSON schemas for tool arguments.
-   **Snap-Tokens**: Manages proxy tokens for secure agent interaction and instant revocation.
-   **Live Burn Meter**: Provides real-time cost tracking.
-   **Risk Confidence Index**: Calculates a trust score for each tool.
-   **Tool Safe Catalog**: AI-powered safety grading for tools.
-   **Blast Radius Governor**: Implements dual-limit systems per agent.
-   **Identity Vault**: Securely stores credentials.
-   **Deception & Goal Drift Detector**: Analyzes agent monologues for misalignments.
-   **Honeypot Tripwires**: Utilizes decoy tools to detect unauthorized access.
-   **Snap-Card Review Queue**: Presents runtime violations as structured "Snap-Cards" for review, with Reject, Edit & Release, Trust 24h, and Generate Fix Prompt buttons.
-   **Context-Aware Remediation Prompts**: Generates Universal Markdown Block fix prompts on Snap-Cards combining agent intent, violation details, and NIST category. LLM-powered with deterministic fallback per violation type. Compatible with Claude, ChatGPT, and Cursor.
-   **Trust Rules (24h TTL)**: Allows creation of temporary auto-approval rules.
-   **Thinking Token Sentinel**: Monitors LLM `usage.thinking_tokens` to detect logic loops and pipeline latency anomalies.
-   **MCP JSON-RPC 2.0 Ingestion**: Auto-detects MCP format for tool calls.
-   **Three-Tier Role Model**: Platform Admin, Workspace Owner, and Viewer roles.
-   **Reasoning Enforcement**: Requires agents to provide `inner_monologue` for high-risk tool calls.
-   **Forensic Lineage Map**: Provides a visual chain-of-command tree structure from audit log data.
-   **Liability-Shielding Features**: Public Safety Disclosure and `X-Snapwire-Authorized-By` header for human accountability.
-   **Deterministic Hold Window**: Temporarily holds high-risk allowed calls for configurable seconds, with Slack integration.
-   **Auto-Triage Rules**: Automated approval/denial based on regex matching and risk thresholds.
-   **OpenClaw**: A deterministic BASE_URL redirect attack detector.
-   **Vibe-Summary**: Claude-powered 3-sentence plain-English summaries on Snap-Cards.
-   **Stealth Mode**: Hides community features from non-admin users.
-   **Deployer Compliance Portal**: `/compliance-portal` with impact assessment, audit bundle ZIP download, and Colorado SB24-205 checklist.
-   **Batch Ingestor**: Processes JSON files of MCP tool schemas through a CVE gauntlet with auto-heal.
-   **NIST RESPOND-1.1 Tagging**: Slack Kill actions auto-tagged in audit logs.
-   **A2A Chain of Command**: Enhanced Forensic Lineage Map with NIST RESPOND-1.1 badge and compliance summary.
-   **Consequentiality Tagging**: `ToolCatalog.is_consequential` for identifying high-stakes tools.
-   **Headless Compliance API Docs**: Interactive Swagger-like API reference for compliance endpoints.
-   **Dynamic Chaos Ingestor**: Generates per-tool attack scenarios using Claude.
-   **Legal Counsel Acknowledgment Gate**: Requires user acknowledgment before downloading compliance documents.
-   **Substantial Modification Trigger**: Alerts users when 10+ tools added since last audit.
-   **Homepage Rewrite**: Focuses on plain-language explanations of Snapwire's purpose and features. UI uses universal terms: "Runtime Violations," "Security Signals," "Detected Vulnerabilities."
-   **Engine Room (Super-Admin Tab Group)**: Platform Admin-only dashboard with System Health, Batch Ingestor UI, Chaos Lab, Global Burn Meter, Stealth Control, Telemetry, Weekly Summary, and HITL Evidence.
-   **Self-Correction Loop**: Manages auto-healed tool schemas for admin review and approval/rejection.
-   **Vibe-Audit Weekly Summarizer**: Automated executive summary of audit logs, ingestor results, cost savings, and security posture sent to Slack.
-   **Watchdog Script**: Automated batch ingestor run with Slack failure alerts.
-   **Admin/Tenant Dashboard Split**: Enforces role-based access to dashboard features.
-   **Taint Tracking**: Cross-call data-flow governance, classifying tools by sensitivity and I/O type to prevent data leakage.
-   **Session Pulse**: TTL-based continuous token re-validation for security.
-   **Strict Reasoning Toggle**: Requires `inner_monologue` for all tool calls when enabled.
-   **AIBOM Generator**: Generates CycloneDX v1.7 JSON AI Bill of Materials from tool catalog and audit log data. Embeds ServiceNow ITSM properties (`sn:risk_level`, `sn:impact_category`, `sn:configuration_item`) in components and services. HMAC-SHA256 signed for tamper detection with `verify_aibom_hmac()` verification.
-   **NIST IR 8596 Auto-Tagger**: Automatically tags every blocked/held audit log entry with its corresponding NIST IR 8596 category ID (e.g., `PR.DS-1`, `DE.CM-1`) in `violations_json`. Mapping in `src/nist_mapping.py`.
-   **NIST IR 8596 Attestation PDF**: Generates a branded PDF mapping Snapwire features to NIST IR 8596 / CSF 2.0 categories.
-   **ServiceNow Manifest**: Generates a JSON mapping Snapwire data to ServiceNow ITSM fields.
-   **Vibe-Audit Weekly Summarizer**: Includes NIST IR 8596 category breakdown showing enforcement activity by NIST function/category in both LLM-generated and deterministic fallback reports.
-   **Environment Validator**: `check_setup.py` standalone script validates environment (required/recommended/optional vars, database connectivity) with color-coded report. Startup warnings in `main.py` for critical missing vars.
-   **System Health Tab**: Engine Room sub-tab showing real-time subsystem status (database, LLM, email, Slack, Sentinel, session) with green/yellow/red indicators, refresh, and copy-diagnostics.
-   **Observe & Audit Mode**: Renamed from "Shadow Mode" in all user-facing text. Internal identifiers unchanged (`shadow_mode`, `is_shadow_mode()`, `shadow-blocked`). Professional security posture terminology.
-   **Enhanced Onboarding Overlay**: 5-step guided tour: Welcome + API key, Set Budget, Send Test Tool Call (copy-paste curl), Review Snap-Card (button explanations), Go Live (Observe & Audit vs Enforcement). Skip Tour on every step.
-   **HITL Evidence Drill-Down**: Engine Room sub-tab with intervention rate %, 30-day stacked bar chart (manual vs auto resolutions), top-agents table, downloadable compliance evidence summary. Proves human governance for acquirer due diligence.
-   **Live NIST Enforcement Heatmap**: Dashboard 6-tile grid (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER) with color-intensity activity levels, CSS pulse animation for recent activity, hover tooltips. RESPOND tile specifically highlights Snap-Token revocations and Kill-Switch events. Auto-refreshes every 30 seconds.
-   **Expanded FAQ**: 9 questions covering product, fork/self-hosting, environment variables, LLM-free usage, and update strategy.
-   **"What to Expect After Forking" Section**: Homepage 4-step visual timeline (Fork → Setup Wizard → First Tool Call → Protected) with fork CTA.
-   **Detailed "How It Works"**: Homepage 3-step section with specific feature names (Fuse Breaker, Burn Meter, Taint Tracking, Snap-Cards, Fix Prompts, NIST compliance) and framework compatibility badges (LangChain, CrewAI, OpenAI Assistants, MCP).
-   **Cloud Coming Soon**: Pricing page and homepage Cloud column dimmed with "Coming Soon" badges. Self-Hosted remains primary CTA. "Join Waitlist" replaces "Sign Up Free."
-   **API Docs Try It Playground**: Interactive playground in API docs with pre-filled intercept request, Run button (live fetch), Copy as curl, color-coded response display. Honeypot-aware: abuse attempts produce "Blocked by Snapwire" demo.

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