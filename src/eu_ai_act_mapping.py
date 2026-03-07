EU_AI_ACT_ARTICLES = {
    "ART-9": {
        "id": "ART-9",
        "article": "Article 9",
        "name": "Risk Management System",
        "description": "A risk management system shall be established, implemented, documented and maintained in relation to high-risk AI systems.",
        "scenario_categories": ["env_access", "crypto_transaction", "credential_exfil"],
        "rule_packs": ["universal_starter", "financial_compliance", "shell_safety"],
    },
    "ART-10": {
        "id": "ART-10",
        "article": "Article 10",
        "name": "Data and Data Governance",
        "description": "High-risk AI systems which make use of data shall be developed on the basis of training, validation and testing data sets that meet quality criteria.",
        "scenario_categories": ["pii_leakage", "domain_exfil"],
        "rule_packs": ["data_protection", "egress_allowlist"],
    },
    "ART-11": {
        "id": "ART-11",
        "article": "Article 11",
        "name": "Technical Documentation",
        "description": "Technical documentation shall be drawn up before a high-risk AI system is placed on the market or put into service.",
        "scenario_categories": ["safe_calls"],
        "rule_packs": ["universal_starter"],
    },
    "ART-12": {
        "id": "ART-12",
        "article": "Article 12",
        "name": "Record-Keeping",
        "description": "High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system.",
        "scenario_categories": ["env_access", "credential_exfil"],
        "rule_packs": ["universal_starter", "sql_redline", "shell_safety"],
    },
    "ART-13": {
        "id": "ART-13",
        "article": "Article 13",
        "name": "Transparency and Provision of Information",
        "description": "High-risk AI systems shall be designed and developed to ensure their operation is sufficiently transparent to enable deployers to interpret a system's output.",
        "scenario_categories": ["safe_calls", "pii_leakage"],
        "rule_packs": ["universal_starter", "data_protection"],
    },
    "ART-14": {
        "id": "ART-14",
        "article": "Article 14",
        "name": "Human Oversight",
        "description": "High-risk AI systems shall be designed and developed so as to be effectively overseen by natural persons during the period of use.",
        "scenario_categories": ["incident_response"],
        "rule_packs": ["incident_response", "universal_starter"],
    },
    "ART-15": {
        "id": "ART-15",
        "article": "Article 15",
        "name": "Accuracy, Robustness and Cybersecurity",
        "description": "High-risk AI systems shall be designed and developed to achieve an appropriate level of accuracy, robustness and cybersecurity.",
        "scenario_categories": ["credential_exfil", "domain_exfil", "crypto_transaction"],
        "rule_packs": ["shell_safety", "code_safety", "safe_browsing", "egress_allowlist"],
    },
    "ART-17": {
        "id": "ART-17",
        "article": "Article 17",
        "name": "Quality Management System",
        "description": "Providers of high-risk AI systems shall put a quality management system in place to ensure compliance with this Regulation.",
        "scenario_categories": ["env_access"],
        "rule_packs": ["universal_starter", "data_protection"],
    },
    "ART-26": {
        "id": "ART-26",
        "article": "Article 26",
        "name": "Obligations of Deployers",
        "description": "Deployers of high-risk AI systems shall take appropriate technical and organisational measures to ensure they use such systems in accordance with the instructions of use.",
        "scenario_categories": ["env_access", "pii_leakage", "credential_exfil"],
        "rule_packs": ["universal_starter", "data_protection", "financial_compliance"],
    },
    "ART-72": {
        "id": "ART-72",
        "article": "Article 72",
        "name": "Conformity Assessment",
        "description": "The provider shall perform a conformity assessment for each high-risk AI system prior to placing it on the market or putting it into service.",
        "scenario_categories": ["safe_calls"],
        "rule_packs": ["universal_starter"],
    },
}


RULE_PACK_EU_MAP = {
    "universal_starter": ["ART-9", "ART-11", "ART-12", "ART-13", "ART-14", "ART-17", "ART-26", "ART-72"],
    "sql_redline": ["ART-12", "ART-15"],
    "shell_safety": ["ART-9", "ART-12", "ART-15"],
    "safe_browsing": ["ART-15", "ART-10"],
    "financial_compliance": ["ART-9", "ART-26"],
    "code_safety": ["ART-15"],
    "data_protection": ["ART-10", "ART-13", "ART-17", "ART-26"],
    "egress_allowlist": ["ART-10", "ART-15"],
    "incident_response": ["ART-14"],
}


BLOCK_STATUS_EU_MAP = {
    "blocked-sanitizer": {"article": "ART-10", "name": "Data Governance - Input Sanitization"},
    "blocked-openclaw": {"article": "ART-15", "name": "Cybersecurity - Redirect Attack Prevention"},
    "blocked-honeypot": {"article": "ART-15", "name": "Robustness - Rogue Agent Detection"},
    "blocked-blast-radius": {"article": "ART-9", "name": "Risk Management - Rate/Spend Limits"},
    "blocked-strict-reasoning": {"article": "ART-13", "name": "Transparency - Reasoning Requirements"},
    "blocked-catalog": {"article": "ART-17", "name": "Quality Management - Unapproved Tool"},
    "blocked-taint": {"article": "ART-10", "name": "Data Governance - Exfiltration Prevention"},
    "blocked-deception": {"article": "ART-15", "name": "Robustness - Intent Mismatch"},
    "blocked-loop": {"article": "ART-15", "name": "Accuracy - Hallucination Loop"},
    "blocked-schema": {"article": "ART-10", "name": "Data Governance - Schema Violation"},
    "blocked": {"article": "ART-9", "name": "Risk Management - Policy Violation"},
    "held": {"article": "ART-14", "name": "Human Oversight - Review Required"},
    "shadow-blocked": {"article": "ART-12", "name": "Record-Keeping - Observation Mode"},
}


FEATURE_EU_MAP = [
    {
        "number": 1,
        "name": "Constitutional Rule Engine",
        "eu_articles": ["ART-9", "ART-26"],
        "evidence": "Deterministic policy enforcement with severity-based blocking maps to risk management and deployer obligations",
    },
    {
        "number": 2,
        "name": "OpenClaw CVE-2026-25253 Safeguard",
        "eu_articles": ["ART-15"],
        "evidence": "Attack detection and blocking provides cybersecurity safeguards for high-risk AI systems",
    },
    {
        "number": 3,
        "name": "Loop Detector (Fuse Breaker)",
        "eu_articles": ["ART-15", "ART-9"],
        "evidence": "Hallucination loop detection ensures accuracy and robustness of AI operations",
    },
    {
        "number": 4,
        "name": "Input Sanitizer",
        "eu_articles": ["ART-10", "ART-15"],
        "evidence": "Parameter sanitization enforces data governance and cybersecurity requirements",
    },
    {
        "number": 5,
        "name": "Blast Radius Controls",
        "eu_articles": ["ART-9", "ART-26"],
        "evidence": "Dual-limit system implements risk management controls for deployer obligations",
    },
    {
        "number": 6,
        "name": "Honeypot Tripwires",
        "eu_articles": ["ART-15", "ART-12"],
        "evidence": "Decoy tools detect unauthorized access, supporting cybersecurity and record-keeping",
    },
    {
        "number": 7,
        "name": "Identity Vault (Snap-Tokens)",
        "eu_articles": ["ART-15", "ART-9"],
        "evidence": "Proxy token system ensures credential security and risk management",
    },
    {
        "number": 8,
        "name": "Tool Safety Catalog",
        "eu_articles": ["ART-17", "ART-9"],
        "evidence": "AI-powered safety grading supports quality management and risk assessment",
    },
    {
        "number": 9,
        "name": "Deception Detector",
        "eu_articles": ["ART-15", "ART-12"],
        "evidence": "Heuristic analysis for agent circumvention supports robustness and record-keeping",
    },
    {
        "number": 10,
        "name": "Schema Guard",
        "eu_articles": ["ART-10", "ART-15"],
        "evidence": "JSON schema enforcement ensures data governance and system robustness",
    },
    {
        "number": 11,
        "name": "Risk Index Scoring",
        "eu_articles": ["ART-9", "ART-11"],
        "evidence": "Multi-signal risk scoring implements risk management with technical documentation",
    },
    {
        "number": 12,
        "name": "Thinking Token Sentinel",
        "eu_articles": ["ART-15", "ART-12"],
        "evidence": "Thinking token monitoring detects adversarial manipulation for accuracy and logging",
    },
    {
        "number": 13,
        "name": "Rate Limiter",
        "eu_articles": ["ART-9", "ART-15"],
        "evidence": "Per-tenant rate limiting implements risk controls and system robustness",
    },
    {
        "number": 14,
        "name": "Reasoning Enforcement",
        "eu_articles": ["ART-13", "ART-14"],
        "evidence": "Required inner_monologue ensures transparency and supports human oversight",
    },
    {
        "number": 15,
        "name": "Immutable Audit Trail",
        "eu_articles": ["ART-12", "ART-11"],
        "evidence": "SHA-256 hashed audit logs provide automatic event recording and technical documentation",
    },
    {
        "number": 16,
        "name": "Human-in-the-Loop Review Queue",
        "eu_articles": ["ART-14", "ART-26"],
        "evidence": "Configurable hold window with approve/deny/kill controls enables human oversight",
    },
    {
        "number": 17,
        "name": "Multi-Tenancy",
        "eu_articles": ["ART-17", "ART-26"],
        "evidence": "Database-level tenant isolation supports quality management for multi-organization deployment",
    },
    {
        "number": 18,
        "name": "API Key Management",
        "eu_articles": ["ART-15", "ART-17"],
        "evidence": "Secure key hashing, rotation, and deactivation provides cybersecurity controls",
    },
    {
        "number": 19,
        "name": "Webhook Notifications",
        "eu_articles": ["ART-14", "ART-12"],
        "evidence": "Real-time event notifications enable human oversight and event recording",
    },
    {
        "number": 20,
        "name": "Slack Integration",
        "eu_articles": ["ART-14", "ART-26"],
        "evidence": "Interactive Approve/Kill buttons in Slack enable real-time human oversight",
    },
    {
        "number": 21,
        "name": "Email Notifications",
        "eu_articles": ["ART-14", "ART-12"],
        "evidence": "Email alerts for blocked actions enable human oversight and record-keeping",
    },
    {
        "number": 22,
        "name": "Rule Templates (Packs)",
        "eu_articles": ["ART-9", "ART-17"],
        "evidence": "Pre-built rule packs accelerate risk management and quality management setup",
    },
    {
        "number": 23,
        "name": "NLP Rule Builder",
        "eu_articles": ["ART-9", "ART-13"],
        "evidence": "Natural language rule creation supports accessible risk management with transparency",
    },
    {
        "number": 24,
        "name": "Observe & Audit Mode",
        "eu_articles": ["ART-72", "ART-9"],
        "evidence": "Shadow mode testing supports conformity assessment and risk evaluation",
    },
    {
        "number": 25,
        "name": "Rule Version History",
        "eu_articles": ["ART-12", "ART-17"],
        "evidence": "Complete change tracking for rules supports record-keeping and quality management",
    },
    {
        "number": 26,
        "name": "NIST IR 8596 Coverage Mapping",
        "eu_articles": ["ART-11", "ART-72"],
        "evidence": "Framework mapping provides technical documentation for conformity assessment",
    },
    {
        "number": 27,
        "name": "Safety Disclosure PDF",
        "eu_articles": ["ART-13", "ART-11"],
        "evidence": "Auto-generated compliance PDFs provide transparency and technical documentation",
    },
    {
        "number": 28,
        "name": "Compliance Portal",
        "eu_articles": ["ART-11", "ART-72", "ART-26"],
        "evidence": "Centralized compliance dashboard supports documentation, assessment, and deployer obligations",
    },
    {
        "number": 29,
        "name": "Colorado SB24-205 Safe Harbor",
        "eu_articles": ["ART-26", "ART-72"],
        "evidence": "Affirmative defense evidence supports deployer obligations and conformity assessment",
    },
    {
        "number": 30,
        "name": "X-Snapwire Headers",
        "eu_articles": ["ART-12", "ART-13"],
        "evidence": "Immutable attribution headers provide record-keeping and transparency traceability",
    },
    {
        "number": 31,
        "name": "Sentinel Proxy (Sidecar)",
        "eu_articles": ["ART-15", "ART-9", "ART-12"],
        "evidence": "Transparent reverse proxy with fail-closed enforcement ensures cybersecurity and risk management",
    },
    {
        "number": 32,
        "name": "Community Rules",
        "eu_articles": ["ART-17"],
        "evidence": "Peer-reviewed rule contributions support quality management systems",
    },
    {
        "number": 33,
        "name": "Organization Management",
        "eu_articles": ["ART-17", "ART-26"],
        "evidence": "Multi-organization support with role-based access supports quality management",
    },
    {
        "number": 34,
        "name": "LLM Provider Layer",
        "eu_articles": ["ART-15", "ART-17"],
        "evidence": "Unified provider abstraction with BYOK ensures cybersecurity and quality management",
    },
    {
        "number": 35,
        "name": "LLM Encryption",
        "eu_articles": ["ART-15", "ART-10"],
        "evidence": "Encrypted tenant API keys provide cybersecurity and data governance",
    },
    {
        "number": 36,
        "name": "Consequentiality Tagging",
        "eu_articles": ["ART-9", "ART-26"],
        "evidence": "High-stakes tool tagging supports risk management and deployer obligation awareness",
    },
    {
        "number": 37,
        "name": "Auto-Approve Trust Escalation",
        "eu_articles": ["ART-9", "ART-14"],
        "evidence": "Configurable auto-approval thresholds balance risk management with oversight efficiency",
    },
    {
        "number": 38,
        "name": "Auto-Triage Rules",
        "eu_articles": ["ART-9", "ART-14"],
        "evidence": "Automated triage based on risk thresholds supports risk management and oversight scaling",
    },
    {
        "number": 39,
        "name": "Server-Sent Events (SSE)",
        "eu_articles": ["ART-14", "ART-12"],
        "evidence": "Real-time dashboard updates enable continuous human oversight and event monitoring",
    },
    {
        "number": 40,
        "name": "Config Export/Import",
        "eu_articles": ["ART-17", "ART-11"],
        "evidence": "Configuration portability supports quality management and technical documentation",
    },
    {
        "number": 41,
        "name": "Setup Wizard",
        "eu_articles": ["ART-26", "ART-17"],
        "evidence": "Guided configuration ensures deployers set up governance correctly",
    },
    {
        "number": 42,
        "name": "Usage Metering",
        "eu_articles": ["ART-12", "ART-9"],
        "evidence": "Per-tenant API call tracking supports record-keeping and resource risk management",
    },
    {
        "number": 43,
        "name": "Parent Agent ID Tracing",
        "eu_articles": ["ART-12", "ART-13"],
        "evidence": "Delegation chain tracing provides record-keeping and transparency for multi-agent systems",
    },
    {
        "number": 44,
        "name": "Content Hash Integrity",
        "eu_articles": ["ART-12", "ART-15"],
        "evidence": "SHA-256 content hashes provide tamper-proof record-keeping and data integrity",
    },
    {
        "number": 45,
        "name": "Batch Ingestor",
        "eu_articles": ["ART-17", "ART-9"],
        "evidence": "Bulk import with automated grading supports quality management and risk assessment",
    },
    {
        "number": 46,
        "name": "Watchdog Script",
        "eu_articles": ["ART-15", "ART-12"],
        "evidence": "Automated monitoring with failure alerts supports robustness and record-keeping",
    },
    {
        "number": 47,
        "name": "Self-Correction Loop",
        "eu_articles": ["ART-15", "ART-14"],
        "evidence": "Auto-heal with human approval gate ensures accuracy with oversight",
    },
    {
        "number": 48,
        "name": "Vibe-Audit Weekly Summarizer",
        "eu_articles": ["ART-12", "ART-14", "ART-11"],
        "evidence": "Automated executive summaries support record-keeping, oversight, and documentation",
    },
    {
        "number": 49,
        "name": "AIBOM Generator",
        "eu_articles": ["ART-11", "ART-17"],
        "evidence": "CycloneDX AI Bill of Materials provides technical documentation and supply chain quality management",
    },
    {
        "number": 50,
        "name": "Taint Tracking",
        "eu_articles": ["ART-10", "ART-15"],
        "evidence": "Cross-call data-flow governance enforces data governance and prevents exfiltration",
    },
    {
        "number": 51,
        "name": "Session Pulse",
        "eu_articles": ["ART-15", "ART-9"],
        "evidence": "TTL-based token re-validation ensures continuous cybersecurity and risk management",
    },
    {
        "number": 52,
        "name": "Strict Reasoning Toggle",
        "eu_articles": ["ART-13", "ART-14"],
        "evidence": "Mandatory reasoning documentation ensures transparency and oversight completeness",
    },
    {
        "number": 53,
        "name": "Ultra-Low Latency Intercept",
        "eu_articles": ["ART-15", "ART-9", "ART-12"],
        "evidence": "Real-time governance overhead monitoring with percentile metrics ensures system accuracy, cybersecurity, and record-keeping of performance characteristics",
    },
    {
        "number": 54,
        "name": "Unmanaged Agent Discovery",
        "eu_articles": ["ART-9", "ART-14", "ART-26", "ART-72"],
        "evidence": "Detection of unregistered AI agents supports risk management, human oversight of unknown actors, deployer obligations, and post-market monitoring",
    },
]


PACK_RECOMMENDATIONS = {
    "ART-9": "universal_starter",
    "ART-10": "data_protection",
    "ART-11": "universal_starter",
    "ART-12": "universal_starter",
    "ART-13": "data_protection",
    "ART-14": "incident_response",
    "ART-15": "shell_safety",
    "ART-17": "universal_starter",
    "ART-26": "universal_starter",
    "ART-72": "universal_starter",
}


def get_eu_tag_for_status(status):
    if not status:
        return None
    entry = BLOCK_STATUS_EU_MAP.get(status)
    if entry:
        return entry
    for key, val in BLOCK_STATUS_EU_MAP.items():
        if status.startswith(key):
            return val
    return None


def score_to_grade(score: int) -> str:
    if score >= 80:
        return "A"
    elif score >= 60:
        return "B"
    elif score >= 40:
        return "C"
    else:
        return "D"


def generate_eu_compliance_report(installed_rule_names):
    installed_packs = set()
    from src.rule_templates import RULE_TEMPLATES
    for pack_id, pack_data in RULE_TEMPLATES.items():
        pack_rules = set(pack_data.get("rules", {}).keys())
        if pack_rules and pack_rules.issubset(installed_rule_names):
            installed_packs.add(pack_id)
        elif pack_rules & installed_rule_names:
            installed_packs.add(f"partial:{pack_id}")

    covered_articles = set()
    partial_articles = set()

    for pack in installed_packs:
        if pack.startswith("partial:"):
            real_pack = pack.replace("partial:", "")
            for art_id in RULE_PACK_EU_MAP.get(real_pack, []):
                partial_articles.add(art_id)
        else:
            for art_id in RULE_PACK_EU_MAP.get(pack, []):
                covered_articles.add(art_id)

    partial_articles -= covered_articles

    articles = []
    for art_id, art_info in EU_AI_ACT_ARTICLES.items():
        if art_id in covered_articles:
            status = "covered"
        elif art_id in partial_articles:
            status = "partial"
        else:
            status = "gap"

        covering_packs = []
        for pack in installed_packs:
            real_pack = pack.replace("partial:", "") if pack.startswith("partial:") else pack
            if art_id in RULE_PACK_EU_MAP.get(real_pack, []):
                covering_packs.append(real_pack)

        recommendation = None
        if status == "gap":
            rec_pack = PACK_RECOMMENDATIONS.get(art_id)
            if rec_pack:
                from src.rule_templates import RULE_TEMPLATES
                pack_info = RULE_TEMPLATES.get(rec_pack, {})
                recommendation = {
                    "pack_id": rec_pack,
                    "pack_name": pack_info.get("display_name", rec_pack),
                }

        articles.append({
            "id": art_id,
            "article": art_info["article"],
            "name": art_info["name"],
            "description": art_info["description"],
            "status": status,
            "covering_packs": covering_packs,
            "recommendation": recommendation,
        })

    total = len(EU_AI_ACT_ARTICLES)
    covered_count = len(covered_articles)
    partial_count = len(partial_articles)
    gap_count = total - covered_count - partial_count
    score = round(((covered_count + partial_count * 0.5) / total) * 100) if total > 0 else 0

    return {
        "overall_score": score,
        "grade": score_to_grade(score),
        "total_articles": total,
        "covered": covered_count,
        "partial": partial_count,
        "gaps": gap_count,
        "articles": articles,
        "disclaimer": "This report is informational and does not constitute a formal EU AI Act conformity assessment or certification. It reflects alignment based on installed Snapwire rule packs only.",
    }


def get_eu_coverage_by_article(features=None):
    if features is None:
        features = FEATURE_EU_MAP

    article_features = {}
    for feature in features:
        for art_id in feature.get("eu_articles", []):
            if art_id not in article_features:
                article_features[art_id] = set()
            article_features[art_id].add(feature["number"])

    coverage = {}
    for art_id, art_info in EU_AI_ACT_ARTICLES.items():
        feature_nums = article_features.get(art_id, set())
        coverage[art_id] = {
            "article": art_info["article"],
            "name": art_info["name"],
            "description": art_info["description"],
            "feature_count": len(feature_nums),
            "feature_numbers": sorted(feature_nums),
            "coverage_percentage": round((len(feature_nums) / len(FEATURE_EU_MAP)) * 100, 1) if FEATURE_EU_MAP else 0,
        }
    return coverage
