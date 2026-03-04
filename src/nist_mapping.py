NIST_CATEGORIES = {
    "GOVERN-1.1": {
        "id": "GOVERN-1.1",
        "function": "GOVERN",
        "name": "Legal and Regulatory Requirements",
        "description": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
        "scenario_categories": ["env_access"],
        "rule_packs": ["universal_starter", "shell_safety"],
    },
    "GOVERN-1.2": {
        "id": "GOVERN-1.2",
        "function": "GOVERN",
        "name": "Trustworthy AI Characteristics",
        "description": "Trustworthy AI characteristics are integrated into organizational policies, procedures, and processes.",
        "scenario_categories": ["credential_exfil"],
        "rule_packs": ["universal_starter", "data_protection"],
    },
    "GOVERN-6.1": {
        "id": "GOVERN-6.1",
        "function": "GOVERN",
        "name": "Deployment Policies",
        "description": "Policies and procedures are in place that address AI risks associated with third-party entities.",
        "scenario_categories": ["crypto_transaction"],
        "rule_packs": ["financial_compliance"],
    },
    "MAP-3.4": {
        "id": "MAP-3.4",
        "function": "MAP",
        "name": "Data Constraints",
        "description": "Risks associated with transparency, data constraints, and impacts on affected communities are assessed.",
        "scenario_categories": ["domain_exfil"],
        "rule_packs": ["egress_allowlist", "safe_browsing"],
    },
    "MAP-3.5": {
        "id": "MAP-3.5",
        "function": "MAP",
        "name": "Scientific Integrity",
        "description": "Scientific integrity and TEVV considerations are identified and documented.",
        "scenario_categories": ["credential_exfil"],
        "rule_packs": ["data_protection"],
    },
    "MAP-5.1": {
        "id": "MAP-5.1",
        "function": "MAP",
        "name": "Impacts to People",
        "description": "Likelihood and magnitude of each identified impact are determined based on context.",
        "scenario_categories": ["pii_leakage"],
        "rule_packs": ["data_protection"],
    },
    "MEASURE-2.6": {
        "id": "MEASURE-2.6",
        "function": "MEASURE",
        "name": "Validity and Reliability",
        "description": "AI system validity, reliability, and robustness are assessed through testing and evaluation.",
        "scenario_categories": ["safe_calls"],
        "rule_packs": ["universal_starter"],
    },
    "MANAGE-2.2": {
        "id": "MANAGE-2.2",
        "function": "MANAGE",
        "name": "Risk Tracking Mechanisms",
        "description": "Mechanisms are in place and applied to sustain the value of deployed AI systems and track identified risks.",
        "scenario_categories": ["env_access"],
        "rule_packs": ["sql_redline", "shell_safety"],
    },
    "MANAGE-2.3": {
        "id": "MANAGE-2.3",
        "function": "MANAGE",
        "name": "Risk Assessment Procedures",
        "description": "Procedures are followed to respond to and recover from a previously unknown risk.",
        "scenario_categories": ["domain_exfil"],
        "rule_packs": ["egress_allowlist", "safe_browsing"],
    },
    "MANAGE-2.4": {
        "id": "MANAGE-2.4",
        "function": "MANAGE",
        "name": "Risk Response and Recovery",
        "description": "Mechanisms are in place and applied for AI risk response and recovery.",
        "scenario_categories": ["pii_leakage"],
        "rule_packs": ["shell_safety", "code_safety"],
    },
    "MANAGE-4.1": {
        "id": "MANAGE-4.1",
        "function": "MANAGE",
        "name": "Post-Deployment Monitoring",
        "description": "Post-deployment AI system monitoring plans are implemented and risks are regularly assessed.",
        "scenario_categories": ["crypto_transaction"],
        "rule_packs": ["financial_compliance"],
    },
    "RESPOND-1.1": {
        "id": "RESPOND-1.1",
        "function": "RESPOND",
        "name": "Incident Response",
        "description": "Active human incident response and intervention for AI agent actions, including real-time kill decisions via operator channels.",
        "scenario_categories": ["incident_response"],
        "rule_packs": ["incident_response"],
    },
}


RULE_PACK_NIST_MAP = {
    "universal_starter": ["GOVERN-1.1", "GOVERN-1.2", "MEASURE-2.6"],
    "sql_redline": ["MANAGE-2.2"],
    "shell_safety": ["GOVERN-1.1", "MANAGE-2.2", "MANAGE-2.4"],
    "safe_browsing": ["MAP-3.4", "MANAGE-2.3"],
    "financial_compliance": ["GOVERN-6.1", "MANAGE-4.1"],
    "code_safety": ["MANAGE-2.4"],
    "data_protection": ["GOVERN-1.2", "MAP-3.5", "MAP-5.1"],
    "egress_allowlist": ["MAP-3.4", "MANAGE-2.3"],
    "incident_response": ["RESPOND-1.1"],
}


BLOCK_STATUS_NIST_MAP = {
    "blocked-sanitizer": {"category": "PR.DS-1", "function": "PROTECT", "name": "Data Security — Input Sanitization"},
    "blocked-openclaw": {"category": "PR.DS-2", "function": "PROTECT", "name": "Data Security — Redirect Attack Prevention"},
    "blocked-honeypot": {"category": "DE.AE-1", "function": "DETECT", "name": "Adverse Events — Rogue Agent Detection"},
    "blocked-blast-radius": {"category": "PR.AC-1", "function": "PROTECT", "name": "Access Control — Rate/Spend Limits"},
    "blocked-strict-reasoning": {"category": "GV.PO-1", "function": "GOVERN", "name": "Policy — Reasoning Requirements"},
    "blocked-catalog": {"category": "ID.AM-2", "function": "IDENTIFY", "name": "Asset Management — Unapproved Tool"},
    "blocked-taint": {"category": "PR.DS-1", "function": "PROTECT", "name": "Data Security — Exfiltration Prevention"},
    "blocked-deception": {"category": "DE.AE-2", "function": "DETECT", "name": "Adverse Events — Intent Mismatch"},
    "blocked-loop": {"category": "DE.CM-1", "function": "DETECT", "name": "Continuous Monitoring — Hallucination Loop"},
    "blocked-schema": {"category": "PR.DS-1", "function": "PROTECT", "name": "Data Security — Schema Violation"},
    "blocked": {"category": "PR.AC-1", "function": "PROTECT", "name": "Access Control — Policy Violation"},
    "held": {"category": "RS.AN-1", "function": "RESPOND", "name": "Analysis — Human Review Required"},
    "shadow-blocked": {"category": "DE.CM-1", "function": "DETECT", "name": "Continuous Monitoring — Shadow Observation"},
}


def get_nist_tag_for_status(status):
    if not status:
        return None
    entry = BLOCK_STATUS_NIST_MAP.get(status)
    if entry:
        return entry
    for key, val in BLOCK_STATUS_NIST_MAP.items():
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


PACK_RECOMMENDATIONS = {
    "GOVERN-1.1": "universal_starter",
    "GOVERN-1.2": "data_protection",
    "GOVERN-6.1": "financial_compliance",
    "MAP-3.4": "egress_allowlist",
    "MAP-3.5": "data_protection",
    "MAP-5.1": "data_protection",
    "MEASURE-2.6": "universal_starter",
    "MANAGE-2.2": "sql_redline",
    "MANAGE-2.3": "egress_allowlist",
    "MANAGE-2.4": "shell_safety",
    "MANAGE-4.1": "financial_compliance",
    "RESPOND-1.1": "incident_response",
}


def generate_compliance_report(installed_rule_names):
    installed_packs = set()
    from src.rule_templates import RULE_TEMPLATES
    for pack_id, pack_data in RULE_TEMPLATES.items():
        pack_rules = set(pack_data.get("rules", {}).keys())
        if pack_rules and pack_rules.issubset(installed_rule_names):
            installed_packs.add(pack_id)
        elif pack_rules & installed_rule_names:
            installed_packs.add(f"partial:{pack_id}")

    covered_categories = set()
    partial_categories = set()

    for pack in installed_packs:
        if pack.startswith("partial:"):
            real_pack = pack.replace("partial:", "")
            for cat_id in RULE_PACK_NIST_MAP.get(real_pack, []):
                partial_categories.add(cat_id)
        else:
            for cat_id in RULE_PACK_NIST_MAP.get(pack, []):
                covered_categories.add(cat_id)

    partial_categories -= covered_categories

    categories = []
    for cat_id, cat_info in NIST_CATEGORIES.items():
        if cat_id in covered_categories:
            status = "covered"
        elif cat_id in partial_categories:
            status = "partial"
        else:
            status = "gap"

        covering_packs = []
        for pack in installed_packs:
            real_pack = pack.replace("partial:", "") if pack.startswith("partial:") else pack
            if cat_id in RULE_PACK_NIST_MAP.get(real_pack, []):
                covering_packs.append(real_pack)

        recommendation = None
        if status == "gap":
            rec_pack = PACK_RECOMMENDATIONS.get(cat_id)
            if rec_pack:
                from src.rule_templates import RULE_TEMPLATES
                pack_info = RULE_TEMPLATES.get(rec_pack, {})
                recommendation = {
                    "pack_id": rec_pack,
                    "pack_name": pack_info.get("display_name", rec_pack),
                }

        categories.append({
            "id": cat_id,
            "function": cat_info["function"],
            "name": cat_info["name"],
            "description": cat_info["description"],
            "status": status,
            "covering_packs": covering_packs,
            "recommendation": recommendation,
        })

    total = len(NIST_CATEGORIES)
    covered_count = len(covered_categories)
    partial_count = len(partial_categories)
    gap_count = total - covered_count - partial_count
    score = round(((covered_count + partial_count * 0.5) / total) * 100) if total > 0 else 0

    return {
        "overall_score": score,
        "grade": score_to_grade(score),
        "total_categories": total,
        "covered": covered_count,
        "partial": partial_count,
        "gaps": gap_count,
        "categories": categories,
        "disclaimer": "This report is informational and does not constitute a formal NISTIR 8596 audit or certification. It reflects CSF 2.0 alignment based on installed Snapwire rule packs only.",
    }
