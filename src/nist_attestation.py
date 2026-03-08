import hashlib
import json
from datetime import datetime

from app import db

SNAPWIRE_VERSION = "1.0.0"

NIST_FUNCTIONS = {
    "GOVERN": "Establish and monitor AI risk management policies and processes",
    "IDENTIFY": "Identify and document AI system risks and context",
    "PROTECT": "Implement safeguards to manage AI system risks",
    "DETECT": "Monitor and detect AI system anomalies and incidents",
    "RESPOND": "Take action regarding detected AI system incidents",
    "MAP": "Contextualize AI system risks within broader operational environment",
    "MEASURE": "Analyze and assess AI system risks quantitatively",
    "MANAGE": "Allocate resources and implement controls for AI risk priorities",
}

FEATURE_NIST_MAP = [
    {
        "number": 1,
        "name": "Constitutional Rule Engine",
        "description": "Deterministic policy enforcement engine that evaluates every AI agent tool call against user-defined automation rules with severity-based blocking and monitoring.",
        "nist_categories": ["GOVERN-1.1", "GOVERN-1.2", "PROTECT-1.1"],
        "evidence": "ConstitutionRule model with tenant-scoped rules, severity levels, and enforce/shadow modes",
        "component": "src/constitution.py",
    },
    {
        "number": 2,
        "name": "OpenClaw CVE-2026-25253 Safeguard",
        "description": "Detects and blocks BASE_URL redirect, credential exfiltration, domain spoofing, WebSocket hijacking, and environment variable injection attacks.",
        "nist_categories": ["PROTECT-1.1", "DETECT-1.1", "RESPOND-1.1"],
        "evidence": "CVE pattern matching in safeguard_openclaw module with real-time blocking",
        "component": "src/safeguard_openclaw.py",
    },
    {
        "number": 3,
        "name": "Loop Detector (Fuse Breaker)",
        "description": "Identifies and kills repetitive tool-call patterns (hallucination loops) before they drain budgets, with configurable thresholds.",
        "nist_categories": ["DETECT-1.1", "MANAGE-2.2", "MEASURE-2.6"],
        "evidence": "LoopDetectorEvent model tracking repeat counts, params hashes, and estimated savings",
        "component": "src/loop_detector.py",
    },
    {
        "number": 4,
        "name": "Input Sanitizer",
        "description": "Strips injection attempts from agent-supplied parameters to prevent prompt injection via tool parameters.",
        "nist_categories": ["PROTECT-1.1", "GOVERN-1.2"],
        "evidence": "Parameter sanitization pipeline with pattern detection and neutralization",
        "component": "src/input_sanitizer.py",
    },
    {
        "number": 5,
        "name": "Blast Radius Controls",
        "description": "Dual-limit system (rate + spend) per agent with configurable lockout periods and manual reset requirements.",
        "nist_categories": ["MANAGE-2.2", "MANAGE-2.4", "PROTECT-1.1"],
        "evidence": "BlastRadiusConfig and BlastRadiusEvent models with per-tenant rate and spend limits",
        "component": "src/blast_radius.py",
    },
    {
        "number": 6,
        "name": "Honeypot Tripwires",
        "description": "Decoy tools that detect rogue agent behavior; triggering a honeypot locks the associated API key and generates alerts.",
        "nist_categories": ["DETECT-1.1", "RESPOND-1.1", "IDENTIFY-1.1"],
        "evidence": "HoneypotTool and HoneypotAlert models with automatic API key lockout",
        "component": "src/honeypot.py",
    },
    {
        "number": 7,
        "name": "Identity Vault (Snap-Tokens)",
        "description": "Proxy token system ensuring agents never see raw secrets; Snap-Tokens abstract real API keys for secure agent interaction.",
        "nist_categories": ["PROTECT-1.1", "GOVERN-6.1", "MANAGE-2.2"],
        "evidence": "VaultEntry and ProxyToken models with token generation, rotation, and revocation",
        "component": "src/vault.py",
    },
    {
        "number": 8,
        "name": "Tool Safety Catalog",
        "description": "AI-powered safety grading system for tools with status tracking, auto-approve controls, and consequentiality tagging.",
        "nist_categories": ["IDENTIFY-1.1", "MAP-3.4", "MEASURE-2.6"],
        "evidence": "ToolCatalog model with safety_grade, status, auto_approve, and is_consequential fields",
        "component": "src/tool_catalog.py",
    },
    {
        "number": 9,
        "name": "Deception Detector",
        "description": "Heuristic analysis that identifies agent circumvention of safety rules through obfuscation and deceptive patterns.",
        "nist_categories": ["DETECT-1.1", "MEASURE-2.6", "PROTECT-1.1"],
        "evidence": "Deception scoring with pattern analysis for encoding tricks, instruction injection, and evasion",
        "component": "src/deception.py",
    },
    {
        "number": 10,
        "name": "Schema Guard",
        "description": "Enforces JSON schemas for tool arguments with flexible and strict enforcement modes and violation tracking.",
        "nist_categories": ["PROTECT-1.1", "MEASURE-2.6", "MAP-3.5"],
        "evidence": "SchemaViolationEvent model with enforcement_mode and per-tool schema validation",
        "component": "src/schema_guard.py",
    },
    {
        "number": 11,
        "name": "Risk Index Scoring",
        "description": "Calculates a trust/risk score for each tool call based on multiple signals including violations, history, and context.",
        "nist_categories": ["MEASURE-2.6", "MANAGE-2.2", "IDENTIFY-1.1"],
        "evidence": "RiskSignal model with multi-signal scoring and per-tool risk summaries",
        "component": "src/risk_index.py",
    },
    {
        "number": 12,
        "name": "Thinking Token Sentinel",
        "description": "Monitors AI model thinking tokens and detects latency anomalies that may indicate adversarial manipulation.",
        "nist_categories": ["DETECT-1.1", "MEASURE-2.6"],
        "evidence": "Thinking token inspection with latency anomaly detection and sentinel statistics",
        "component": "src/thinking_sentinel.py",
    },
    {
        "number": 13,
        "name": "Rate Limiter",
        "description": "Per-tenant rate limiting for API calls with configurable thresholds and automatic throttling.",
        "nist_categories": ["PROTECT-1.1", "MANAGE-2.2"],
        "evidence": "Rate limit enforcement with per-minute thresholds and tenant-scoped tracking",
        "component": "src/rate_limiter.py",
    },
    {
        "number": 14,
        "name": "Reasoning Enforcement",
        "description": "Requires high-risk tool calls to include inner_monologue field explaining agent reasoning for audit trail completeness.",
        "nist_categories": ["GOVERN-1.2", "MAP-5.1", "MANAGE-2.3"],
        "evidence": "inner_monologue requirement on high-risk calls with HTTP 412 enforcement",
        "component": "main.py",
    },
    {
        "number": 15,
        "name": "Immutable Audit Trail",
        "description": "Every tool call decision is logged with timestamps, agent IDs, operator context, and content hashes for forensic traceability.",
        "nist_categories": ["GOVERN-1.1", "MANAGE-4.1", "RESPOND-1.1"],
        "evidence": "AuditLogEntry model with SHA-256 content hashes, agent_id, and parent_agent_id tracking",
        "component": "src/action_queue.py",
    },
    {
        "number": 16,
        "name": "Human-in-the-Loop Review Queue",
        "description": "Configurable hold window that pauses agent actions for human review with approve/deny/kill controls.",
        "nist_categories": ["GOVERN-1.1", "RESPOND-1.1", "MANAGE-2.3"],
        "evidence": "PendingAction model with hold_expires_at, resolved_by, and configurable hold timeout",
        "component": "src/action_queue.py",
    },
    {
        "number": 17,
        "name": "Multi-Tenancy",
        "description": "Database-level tenant isolation with tenant_id columns on all data models for secure multi-organization deployment.",
        "nist_categories": ["GOVERN-6.1", "PROTECT-1.1"],
        "evidence": "tenant_id columns on all models with tenant-scoped queries via get_current_tenant_id()",
        "component": "src/tenant.py",
    },
    {
        "number": 18,
        "name": "API Key Management",
        "description": "Secure API key generation, hashing, rotation, and deactivation with per-key agent name binding.",
        "nist_categories": ["PROTECT-1.1", "GOVERN-6.1", "MANAGE-2.2"],
        "evidence": "ApiKey model with SHA-256 key hashing, agent_name binding, and is_active controls",
        "component": "main.py",
    },
    {
        "number": 19,
        "name": "Webhook Notifications",
        "description": "Configurable webhook endpoints for real-time event notifications with agent filtering and event type selection.",
        "nist_categories": ["RESPOND-1.1", "MANAGE-4.1"],
        "evidence": "WebhookConfig model with event_types, agent_filter, and trigger tracking",
        "component": "src/notifications.py",
    },
    {
        "number": 20,
        "name": "Slack Integration",
        "description": "Real-time Slack alerts via Socket Mode with interactive Approve/Kill buttons for held actions.",
        "nist_categories": ["RESPOND-1.1", "MANAGE-2.3"],
        "evidence": "Slack Socket Mode integration with Block Kit messages and interactive action handlers",
        "component": "src/slack_notifier.py",
    },
    {
        "number": 21,
        "name": "Email Notifications",
        "description": "Email alerts for blocked actions, critical risks, and weekly compliance digests with multi-provider support.",
        "nist_categories": ["RESPOND-1.1", "MANAGE-4.1"],
        "evidence": "Email service with blocked action alerts, critical risk notifications, and digest emails",
        "component": "src/email_service.py",
    },
    {
        "number": 22,
        "name": "Rule Templates (Packs)",
        "description": "Pre-built rule packs for common security scenarios including SQL redline, shell safety, data protection, and financial compliance.",
        "nist_categories": ["GOVERN-1.1", "GOVERN-1.2", "PROTECT-1.1"],
        "evidence": "RULE_TEMPLATES with universal_starter, sql_redline, shell_safety, financial_compliance packs",
        "component": "src/rule_templates.py",
    },
    {
        "number": 23,
        "name": "NLP Rule Builder",
        "description": "Natural language interface for creating constitutional rules with conflict detection and rule testing capabilities.",
        "nist_categories": ["GOVERN-1.1", "MAP-5.1"],
        "evidence": "parse_natural_language_rule(), detect_rule_conflicts(), test_rule_against_action()",
        "component": "src/nlp_rule_builder.py",
    },
    {
        "number": 24,
        "name": "Observe & Audit Mode",
        "description": "Rules can be tested in observation mode before enforcement, logging what would be blocked without actually blocking.",
        "nist_categories": ["MEASURE-2.6", "MANAGE-2.3", "MAP-3.5"],
        "evidence": "ConstitutionRule.mode field with enforce/shadow options and shadow-blocked audit status",
        "component": "src/constitution.py",
    },
    {
        "number": 25,
        "name": "Rule Version History",
        "description": "Complete change tracking for constitutional rules with diff visibility and version restoration.",
        "nist_categories": ["GOVERN-1.1", "MANAGE-4.1"],
        "evidence": "RuleVersion model tracking old_value, new_value, old_config, new_config, and changed_by",
        "component": "src/constitution.py",
    },
    {
        "number": 26,
        "name": "NIST IR 8596 Coverage Mapping",
        "description": "Maps installed rule packs to NIST CSF 2.0 categories with coverage scoring and gap analysis.",
        "nist_categories": ["GOVERN-1.1", "IDENTIFY-1.1", "MAP-3.4"],
        "evidence": "NIST_CATEGORIES dict with 12 categories, RULE_PACK_NIST_MAP, and generate_compliance_report()",
        "component": "src/nist_mapping.py",
    },
    {
        "number": 27,
        "name": "Safety Disclosure PDF",
        "description": "Auto-generated PDF documenting compliance posture, active safeguards, NIST grade, and audit log fingerprint.",
        "nist_categories": ["GOVERN-1.1", "GOVERN-1.2", "MAP-5.1"],
        "evidence": "generate_safety_pdf() producing branded PDF with NIST coverage, safeguards, and SHA-256 fingerprint",
        "component": "src/safety_pdf.py",
    },
    {
        "number": 28,
        "name": "Compliance Portal",
        "description": "Centralized compliance dashboard with impact assessment, AIBOM, audit bundle, and affirmative defense evidence.",
        "nist_categories": ["GOVERN-1.1", "IDENTIFY-1.1", "MAP-5.1"],
        "evidence": "Compliance portal template with multiple sections for regulatory readiness",
        "component": "templates/compliance_portal.html",
    },
    {
        "number": 29,
        "name": "Colorado SB24-205 Safe Harbor",
        "description": "Affirmative defense evidence generation including human oversight records, discrimination testing, and safety disclosures.",
        "nist_categories": ["GOVERN-1.1", "GOVERN-1.2", "MAP-5.1"],
        "evidence": "Compliance portal affirmative defense section with evidence documentation",
        "component": "templates/compliance_portal.html",
    },
    {
        "number": 30,
        "name": "X-Snapwire Headers",
        "description": "Immutable operator attribution headers (X-Snapwire-Authorized-By, X-Snapwire-Origin-ID) injected into every proxied request.",
        "nist_categories": ["GOVERN-1.1", "MANAGE-4.1", "RESPOND-1.1"],
        "evidence": "Header injection on all proxied requests for forensic traceability",
        "component": "sentinel/proxy.py",
    },
    {
        "number": 31,
        "name": "Sentinel Proxy (Sidecar)",
        "description": "Transparent reverse proxy intercepting LLM API traffic with observe/audit/enforce modes and fail-closed enforcement.",
        "nist_categories": ["PROTECT-1.1", "DETECT-1.1", "MANAGE-2.2"],
        "evidence": "aiohttp-based async proxy with protocol detection, NIST header injection, and three operating modes",
        "component": "sentinel/proxy.py",
    },
    {
        "number": 32,
        "name": "Community Rules",
        "description": "Open, peer-reviewed rule contributions with achievement system, leaderboard, and community grading.",
        "nist_categories": ["GOVERN-1.2", "MAP-3.5"],
        "evidence": "Community blueprint with rule submission, grading, achievements, and leaderboard",
        "component": "community/routes.py",
    },
    {
        "number": 33,
        "name": "Organization Management",
        "description": "Multi-organization support with membership roles, tenant switching, and organization-scoped data isolation.",
        "nist_categories": ["GOVERN-6.1", "PROTECT-1.1"],
        "evidence": "Organization and OrgMembership models with role-based access control",
        "component": "models.py",
    },
    {
        "number": 34,
        "name": "LLM Provider Layer",
        "description": "Unified adapter supporting Anthropic Claude and OpenAI GPT with BYOK (Bring Your Own Key) model.",
        "nist_categories": ["GOVERN-6.1", "PROTECT-1.1"],
        "evidence": "LLM provider abstraction with encrypted tenant API key storage",
        "component": "src/llm_provider.py",
    },
    {
        "number": 35,
        "name": "LLM Encryption",
        "description": "Tenant-specific LLM API keys stored with encryption for BYOK deployments.",
        "nist_categories": ["PROTECT-1.1", "GOVERN-6.1"],
        "evidence": "Encrypted key storage with per-tenant isolation",
        "component": "src/llm_encryption.py",
    },
    {
        "number": 36,
        "name": "Consequentiality Tagging",
        "description": "Tools tagged as high-stakes per Colorado SB24-205 receive enhanced governance controls and disclosure requirements.",
        "nist_categories": ["IDENTIFY-1.1", "MAP-5.1", "GOVERN-1.2"],
        "evidence": "ToolCatalog.is_consequential flag with safety PDF disclosure and enhanced monitoring",
        "component": "src/tool_catalog.py",
    },
    {
        "number": 37,
        "name": "Auto-Approve Trust Escalation",
        "description": "Tools with consistent approval history can be auto-approved based on configurable consecutive approval thresholds.",
        "nist_categories": ["MANAGE-2.3", "MEASURE-2.6"],
        "evidence": "AutoApproveCount model tracking consecutive approvals per rule per agent",
        "component": "src/action_queue.py",
    },
    {
        "number": 38,
        "name": "Auto-Triage Rules",
        "description": "Configurable rules for automatic triage of tool calls based on risk score, tool name, and agent patterns.",
        "nist_categories": ["MANAGE-2.3", "RESPOND-1.1"],
        "evidence": "AutoTriageRule model with condition matching and automatic resolution",
        "component": "src/action_queue.py",
    },
    {
        "number": 39,
        "name": "Server-Sent Events (SSE)",
        "description": "Real-time dashboard updates via SSE for live monitoring of agent activity and enforcement decisions.",
        "nist_categories": ["DETECT-1.1", "MANAGE-4.1"],
        "evidence": "SSE subscription system with real-time event streaming to connected clients",
        "component": "src/action_queue.py",
    },
    {
        "number": 40,
        "name": "Config Export/Import",
        "description": "Branded JSON format for exporting and importing rules and configurations across Snapwire instances.",
        "nist_categories": ["GOVERN-1.1", "MANAGE-2.2"],
        "evidence": "JSON export/import with version tracking and tenant-scoped configuration",
        "component": "main.py",
    },
    {
        "number": 41,
        "name": "Setup Wizard",
        "description": "First-run guided configuration wizard for initial Snapwire instance setup with rule pack selection.",
        "nist_categories": ["GOVERN-1.1"],
        "evidence": "Setup wizard template with step-by-step configuration flow",
        "component": "templates/setup_wizard.html",
    },
    {
        "number": 42,
        "name": "Usage Metering",
        "description": "Per-tenant monthly API call tracking for billing and capacity planning.",
        "nist_categories": ["MANAGE-4.1", "GOVERN-6.1"],
        "evidence": "UsageRecord model with tenant_id and monthly aggregation",
        "component": "main.py",
    },
    {
        "number": 43,
        "name": "Parent Agent ID Tracing",
        "description": "Tracks delegation chains across multi-agent systems with parent_agent_id for complete provenance.",
        "nist_categories": ["GOVERN-1.1", "IDENTIFY-1.1", "MANAGE-4.1"],
        "evidence": "parent_agent_id field on AuditLogEntry and PendingAction for delegation chain tracing",
        "component": "src/action_queue.py",
    },
    {
        "number": 44,
        "name": "Content Hash Integrity",
        "description": "SHA-256 content hashes on audit log entries for tamper detection and independent verification.",
        "nist_categories": ["PROTECT-1.1", "MANAGE-4.1"],
        "evidence": "AuditLogEntry.content_hash with SHA-256 hashing of tool call content",
        "component": "src/action_queue.py",
    },
    {
        "number": 45,
        "name": "Batch Ingestor",
        "description": "Bulk import of agent logs from JSON/JSONL files with automated safety grading and CVE scanning.",
        "nist_categories": ["IDENTIFY-1.1", "MEASURE-2.6"],
        "evidence": "Batch processing pipeline with file upload, parsing, and automated tool grading",
        "component": "scripts/batch_ingestor.py",
    },
    {
        "number": 46,
        "name": "Watchdog Script",
        "description": "Automated batch ingestor with Slack failure alerts, configurable source URL, and silent-on-success operation.",
        "nist_categories": ["DETECT-1.1", "MANAGE-4.1"],
        "evidence": "Watchdog with SLACK_WEBHOOK_URL alerts, WATCHDOG_SOURCE_URL config, and D/F grade alerts",
        "component": "scripts/watchdog.py",
    },
    {
        "number": 47,
        "name": "Self-Correction Loop",
        "description": "Auto-heal pipeline with human approval gate: healed schemas stored as pending with side-by-side diff review.",
        "nist_categories": ["MANAGE-2.4", "RESPOND-1.1", "MEASURE-2.6"],
        "evidence": "ToolCatalog.pending_heal_schema with approve/reject workflow and original_schema preservation",
        "component": "src/tool_catalog.py",
    },
    {
        "number": 48,
        "name": "Vibe-Audit Weekly Summarizer",
        "description": "Automated Friday executive summary aggregating audit logs, cost savings, and security posture with LLM or deterministic fallback.",
        "nist_categories": ["MANAGE-4.1", "MEASURE-2.6", "GOVERN-1.1"],
        "evidence": "Weekly summary generation with Slack distribution and on-demand Engine Room access",
        "component": "main.py",
    },
    {
        "number": 49,
        "name": "AIBOM Generator",
        "description": "CycloneDX v1.7 AI Bill of Materials with components, services, properties, and SHA-256 formulation hashes.",
        "nist_categories": ["IDENTIFY-1.1", "MAP-3.4", "GOVERN-1.2"],
        "evidence": "CycloneDX JSON output with tool components, service mappings, and forensic chain of custody",
        "component": "src/aibom_generator.py",
    },
    {
        "number": 50,
        "name": "Taint Tracking",
        "description": "Cross-call data-flow governance classifying tools as source/sink/processor with sensitivity levels and taint propagation.",
        "nist_categories": ["PROTECT-1.1", "DETECT-1.1", "MANAGE-2.4"],
        "evidence": "ToolCatalog.sensitivity_level and io_type with ProxyToken.is_tainted blocking sink calls",
        "component": "src/taint_tracker.py",
    },
    {
        "number": 51,
        "name": "Session Pulse",
        "description": "TTL-based continuous token re-validation with configurable pulse intervals and automatic expiry.",
        "nist_categories": ["PROTECT-1.1", "MANAGE-4.1", "MEASURE-2.6"],
        "evidence": "TenantSettings.pulse_ttl_minutes with ProxyToken.pulse_expiry and refresh endpoint",
        "component": "src/vault.py",
    },
    {
        "number": 52,
        "name": "Strict Reasoning Toggle",
        "description": "Requires ALL tool calls to include inner_monologue reasoning field when enabled, ensuring complete audit trail documentation.",
        "nist_categories": ["GOVERN-1.2", "MAP-5.1", "MANAGE-2.3"],
        "evidence": "TenantSettings.strict_reasoning with HTTP 412 enforcement on missing inner_monologue",
        "component": "main.py",
    },
    {
        "number": 53,
        "name": "Ultra-Low Latency Intercept",
        "description": "Sub-10ms governance overhead tracking with p50/p95/p99 percentile metrics, per-request latency stored in audit log, X-Snapwire-Latency-Ms response header, and Engine Room Latency Monitor dashboard.",
        "nist_categories": ["DETECT-1.1", "MEASURE-2.6", "MANAGE-4.1"],
        "evidence": "AuditLogEntry.intercept_latency_ms column, /api/admin/latency-stats endpoint, Sentinel LatencyTracker with /sentinel/metrics",
        "component": "main.py, sentinel/proxy.py",
    },
    {
        "number": 54,
        "name": "Unmanaged Agent Discovery",
        "description": "Detects unregistered agent IDs hitting the intercept endpoint, tracking sighting count, source IP, and last tool used. Admins can acknowledge or enroll shadow agents via Engine Room.",
        "nist_categories": ["DETECT-2.1", "IDENTIFY-1.1", "RESPOND-1.1", "GOVERN-2.1"],
        "evidence": "UnmanagedAgentSighting model with /api/admin/unmanaged-agents endpoints and Shadow Agents Engine Room tab",
        "component": "main.py, models.py",
    },
    {
        "number": 55,
        "name": "Snapwire CLI",
        "description": "Typer-based CLI with four commands: `snapwire init` (generates .snapwire.yaml config and .env.example), `snapwire check` (preflight: env vars, database, 1-token LLM test, plus Regulatory Readiness summary), `snapwire up` (Flask + Sentinel Proxy by default, --no-proxy to disable), and `snapwire aibom` (generates CycloneDX v1.7 AI Bill of Materials JSON). Professional Rich-formatted terminal interface for deployment, compliance evidence, and demos.",
        "nist_categories": ["GOVERN-1.1", "IDENTIFY-1.1", "MANAGE-4.1", "MAP-3.4"],
        "evidence": "Validated via `snapwire check` pre-flight routine; operationalized via `snapwire up` for deterministic runtime governance; machine-audited via `snapwire aibom` for CycloneDX v1.7 traceability",
        "component": "snapwire_cli.py",
    },
]


def _compute_feature_hash(feature, tenant_id, config_state=""):
    hash_input = json.dumps({
        "feature_number": feature["number"],
        "feature_name": feature["name"],
        "nist_categories": feature["nist_categories"],
        "component": feature["component"],
        "evidence": feature["evidence"],
        "tenant_id": tenant_id or "global",
        "config_state": config_state,
    }, sort_keys=True)
    return hashlib.sha256(hash_input.encode()).hexdigest()


def _get_coverage_by_function(features):
    function_features = {}
    for feature in features:
        for cat_id in feature["nist_categories"]:
            func_name = cat_id.split("-")[0]
            if func_name not in function_features:
                function_features[func_name] = set()
            function_features[func_name].add(feature["number"])

    coverage = {}
    for func_name in NIST_FUNCTIONS:
        feature_nums = function_features.get(func_name, set())
        coverage[func_name] = {
            "function": func_name,
            "description": NIST_FUNCTIONS[func_name],
            "feature_count": len(feature_nums),
            "feature_numbers": sorted(feature_nums),
            "coverage_percentage": round((len(feature_nums) / len(FEATURE_NIST_MAP)) * 100, 1),
        }
    return coverage


def generate_attestation_data(tenant_id):
    from models import ConstitutionRule, AuditLogEntry, ToolCatalog

    now = datetime.utcnow()

    active_rules_count = 0
    rule_hashes = ""
    try:
        rules_query = ConstitutionRule.query
        if tenant_id:
            rules_query = rules_query.filter_by(tenant_id=tenant_id)
        rules = rules_query.all()
        active_rules_count = len(rules)
        rule_data = "|".join(f"{r.rule_name}:{r.value}:{r.severity}:{r.mode}" for r in rules)
        rule_hashes = hashlib.sha256(rule_data.encode()).hexdigest() if rule_data else ""
    except Exception:
        pass

    audit_stats = {"total": 0, "blocked": 0, "allowed": 0, "held": 0}
    try:
        base_query = AuditLogEntry.query
        if tenant_id:
            base_query = base_query.filter(AuditLogEntry.tenant_id == tenant_id)
        audit_stats["total"] = base_query.count()
        audit_stats["blocked"] = base_query.filter(
            AuditLogEntry.status.in_(["blocked", "blocked-blast-radius", "blocked-sanitizer", "blocked-catalog", "blocked-deception"])
        ).count()
        audit_stats["allowed"] = base_query.filter(
            AuditLogEntry.status.in_(["allowed", "approved", "auto-approved", "auto-triage-approved", "trust-approved"])
        ).count()
        audit_stats["held"] = base_query.filter(AuditLogEntry.status == "held").count()
    except Exception:
        pass

    tool_catalog_count = 0
    try:
        tc_query = ToolCatalog.query
        if tenant_id:
            tc_query = tc_query.filter_by(tenant_id=tenant_id)
        tool_catalog_count = tc_query.count()
    except Exception:
        pass

    taint_config = {"sources": 0, "sinks": 0, "processors": 0}
    try:
        tc_query = ToolCatalog.query
        if tenant_id:
            tc_query = tc_query.filter_by(tenant_id=tenant_id)
        all_tools = tc_query.all()
        for t in all_tools:
            io = getattr(t, "io_type", "processor") or "processor"
            if io == "source":
                taint_config["sources"] += 1
            elif io == "sink":
                taint_config["sinks"] += 1
            else:
                taint_config["processors"] += 1
    except Exception:
        pass

    aibom_component_count = 0
    try:
        from src.aibom_generator import generate_aibom
        aibom = generate_aibom(tenant_id, days=30, include_formulation=False)
        aibom_component_count = len(aibom.get("components", []))
    except Exception:
        pass

    config_state = json.dumps({
        "active_rules": active_rules_count,
        "rule_hashes": rule_hashes,
        "tool_catalog_count": tool_catalog_count,
        "taint_config": taint_config,
        "aibom_components": aibom_component_count,
    }, sort_keys=True)

    features_with_hashes = []
    all_categories = set()
    for feature in FEATURE_NIST_MAP:
        feature_hash = _compute_feature_hash(feature, tenant_id, config_state)
        features_with_hashes.append({
            **feature,
            "sha256_hash": feature_hash,
        })
        all_categories.update(feature["nist_categories"])

    coverage_by_function = _get_coverage_by_function(FEATURE_NIST_MAP)

    functions_covered = sum(1 for v in coverage_by_function.values() if v["feature_count"] > 0)
    total_functions = len(NIST_FUNCTIONS)
    overall_score = round((functions_covered / total_functions) * 100, 1) if total_functions > 0 else 0

    bundle_input = json.dumps({
        "features": [f["sha256_hash"] for f in features_with_hashes],
        "tenant_id": tenant_id or "global",
        "generated_at": now.isoformat(),
    }, sort_keys=True)
    bundle_hash = hashlib.sha256(bundle_input.encode()).hexdigest()

    return {
        "metadata": {
            "report_type": "NIST IR 8596 Feature Attestation",
            "snapwire_version": SNAPWIRE_VERSION,
            "generated_at": now.isoformat() + "Z",
            "tenant_id": tenant_id or "global",
            "framework": "NIST AI RMF / CSF 2.0",
            "standard": "NIST IR 8596",
        },
        "summary": {
            "total_features": len(FEATURE_NIST_MAP),
            "nist_categories_covered": len(all_categories),
            "nist_functions_covered": functions_covered,
            "total_nist_functions": total_functions,
            "overall_attestation_score": overall_score,
        },
        "live_data": {
            "active_rules_count": active_rules_count,
            "audit_log_stats": audit_stats,
            "tool_catalog_entries": tool_catalog_count,
            "taint_tracking_config": taint_config,
            "aibom_component_count": aibom_component_count,
        },
        "coverage_by_function": coverage_by_function,
        "features": features_with_hashes,
        "integrity": {
            "bundle_sha256": bundle_hash,
            "generated_at": now.isoformat() + "Z",
        },
        "disclaimer": (
            "This attestation report is generated by Snapwire and is informational only. "
            "It does not constitute a formal NIST IR 8596 audit, certification, or legal compliance determination. "
            "It reflects feature-to-NIST-category mapping based on implemented Snapwire capabilities. "
            "All blocks, alerts, and signals are heuristic and advisory in nature. "
            "The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator."
        ),
    }
