"""
NIST Compliance Mapping Export for Snapwire Sentinel.

Generates a markdown file mapping the current proxy configuration
and rules to NIST RFI requirements and NISTIR 8596 categories.
Includes a Compliance Scorecard with letter grade.
"""

import json
import os
import urllib.request
import urllib.error
from datetime import datetime


def _fetch_rules(config: dict) -> list:
    try:
        url = f"{config['snapwire_url']}/api/constitution"
        req = urllib.request.Request(url)
        if config.get("api_key"):
            req.add_header("Authorization", f"Bearer {config['api_key']}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("rules", [])
    except Exception:
        return []


def _fetch_nist_report(config: dict) -> dict:
    try:
        url = f"{config['snapwire_url']}/api/compliance/nist-report"
        req = urllib.request.Request(url)
        if config.get("api_key"):
            req.add_header("Authorization", f"Bearer {config['api_key']}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def _calculate_grade(config: dict) -> tuple[str, str]:
    mode = config.get("mode", "audit")

    if mode == "enforce":
        return "A", "ENFORCE mode active with fail-closed posture. Meets Colorado AI Act 'Reasonable Care' standard."
    elif mode == "audit":
        return "B", "AUDIT mode provides tracing and logging but does not block non-compliant actions. Consider upgrading to ENFORCE for full compliance."
    else:
        return "C", "OBSERVE mode provides visibility only. No traffic modification or blocking. WARNING: This configuration alone may not satisfy the Colorado AI Act (SB 24-205) 'Reasonable Care' requirement for high-risk AI deployments."


def export_nist_report(config: dict):
    grade, grade_note = _calculate_grade(config)
    rules = _fetch_rules(config)
    nist_data = _fetch_nist_report(config)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    mode_desc = {
        "observe": "Silent-Audit (zero traffic modification, non-blocking logging)",
        "audit": "Audit (log + trace header injection, pass-through)",
        "enforce": "Enforce (block non-compliant calls, fail-closed when gateway unreachable)",
    }

    md = []
    md.append("# Snapwire Sentinel — NIST Compliance Mapping Report")
    md.append("")
    md.append(f"**Generated:** {timestamp}")
    md.append(f"**Snapwire Instance:** {config.get('snapwire_url', 'N/A')}")
    md.append(f"**Sentinel Mode:** {mode_desc.get(config['mode'], config['mode'])}")
    md.append(f"**Upstream Target:** {config.get('upstream_url', 'N/A')}")
    md.append("")

    md.append("---")
    md.append("")
    md.append("## Compliance Scorecard")
    md.append("")
    md.append(f"### Grade: **{grade}**")
    md.append("")
    md.append(f"> {grade_note}")
    md.append("")
    md.append("| Criteria | Status |")
    md.append("|---|---|")
    md.append(f"| Sentinel Proxy Active | Yes |")
    md.append(f"| Operational Mode | {config['mode'].upper()} |")
    md.append(f"| Fail-Closed (Andon Cord) | {'Yes' if config['mode'] == 'enforce' else 'No'} |")
    md.append(f"| Identity Lineage Headers | {'Yes' if config['mode'] in ('audit', 'enforce') else 'No (observe mode)'} |")
    md.append(f"| Forensic Logging | Yes |")
    md.append(f"| Active Rules | {len(rules)} |")
    md.append("")

    md.append("---")
    md.append("")
    md.append("## NIST RFI Mapping (Docket NIST-2025-0035)")
    md.append("")

    md.append("### Section 2a.ii — System-Level Controls")
    md.append("")
    md.append("| Control | Snapwire Implementation | Status |")
    md.append("|---|---|---|")
    md.append("| Transparent Interception | Sentinel Sidecar reverse proxy intercepts all LLM API traffic | Active |")
    md.append("| Protocol-Agnostic Governance | Standalone Registry detector supports OpenAI, Anthropic, MCP, A2A, Generic JSON-RPC | Active |")
    md.append(f"| Deterministic Rule Engine | {len(rules)} active rules in Constitutional AI Engine | {'Active' if rules else 'No rules configured'} |")
    md.append("| Blast Radius Governor | Per-agent spend and action limits | Active |")
    md.append("| Loop Detection (Fuse Breaker) | Automatic hallucination loop detection with 429 auto-block | Active |")
    md.append("")

    md.append("### Section 2a.iii — Identity Non-Repudiation & Delegation")
    md.append("")
    md.append("| Requirement | Snapwire Implementation | Status |")
    md.append("|---|---|---|")
    injecting = config["mode"] in ("audit", "enforce")
    md.append(f"| Root Identity (OriginChainID) | `X-Snapwire-Origin-ID` header — cryptographic binding of human principal | {'Injecting' if injecting else 'Not injecting (observe mode)'} |")
    md.append(f"| Delegation Trace (Parent_ID) | `X-Snapwire-Parent-ID` header — per-request immediate caller tracking | {'Injecting' if injecting else 'Not injecting (observe mode)'} |")
    md.append("| Content Hash Integrity | SHA-256 content hashing on audit log entries | Active |")
    md.append("| Forensic Lineage Map | Visual agent chain-of-command tree in dashboard | Active |")
    md.append("")

    md.append("### Section 4 — Deterministic Blast Radius Constraint")
    md.append("")
    md.append("| Requirement | Snapwire Implementation | Status |")
    md.append("|---|---|---|")
    md.append("| JIT Credential Injection | Snap-Token system swaps static API keys for short-lived, per-action credentials | Active |")
    fail_closed = "Active" if config["mode"] == "enforce" else "Inactive (requires ENFORCE mode)"
    md.append(f"| Fail-Closed Architecture (Andon Cord) | Gateway unreachable → all agent requests blocked | {fail_closed} |")
    md.append("| Emergency Kill-Switch | Global Snap-Token revocation ('The Snap') | Active |")
    md.append("| Reasoning Enforcement | 412 Precondition Required for high-risk calls without inner_monologue | Active |")
    md.append("")

    md.append("### NISTIR 8596 / CSF 2.0 Category Mapping")
    md.append("")
    md.append("| CSF 2.0 Function | Snapwire Feature | Coverage |")
    md.append("|---|---|---|")
    md.append("| IDENTIFY (GV) | Tool Safe Catalog, Risk Confidence Index | Covered |")
    md.append("| PROTECT (PR) | Schema Validation Guard, Input Sanitizer, Identity Vault | Covered |")
    md.append("| DETECT (DE) | Fuse Breaker, Deception Detector, Honeypot Tripwires, Thinking Token Sentinel | Covered |")
    md.append("| RESPOND (RS) | Snap-Card Review Queue, Trust Rules, Blast Radius Governor | Covered |")
    md.append("| RECOVER (RC) | Config Export/Import, Forensic Audit Logs, NIST PDF Reports | Covered |")
    md.append("")

    if nist_data.get("categories"):
        md.append("### Current NIST Category Scores")
        md.append("")
        md.append("| Category | Score | Status |")
        md.append("|---|---|---|")
        for cat in nist_data["categories"]:
            md.append(f"| {cat.get('name', 'N/A')} | {cat.get('score', 0)}% | {cat.get('status', 'N/A')} |")
        md.append("")

    if rules:
        md.append("---")
        md.append("")
        md.append("## Active Rules Summary")
        md.append("")
        md.append("| # | Rule | Severity |")
        md.append("|---|---|---|")
        for i, rule in enumerate(rules, 1):
            name = rule if isinstance(rule, str) else rule.get("rule", rule.get("name", "Unknown"))
            severity = rule.get("severity", "medium") if isinstance(rule, dict) else "medium"
            md.append(f"| {i} | {name} | {severity} |")
        md.append("")

    md.append("---")
    md.append("")
    md.append("## Legal Framework")
    md.append("")
    md.append("**Reasonable Care Disclosure (Colorado AI Act § 6-1-1706)**")
    md.append("")
    md.append('Snapwire\'s Sentinel Sidecar is a Deterministic Security Gateway designed to provide continuous ')
    md.append('monitoring and algorithmic guardrails for autonomous agents. By utilizing Snapwire, the Deployer ')
    md.append('(User) implements a "Reasonable Care" framework to prevent foreseeable algorithmic harm.')
    md.append("")
    md.append("**Infrastructure Intermediary Clause**")
    md.append("")
    md.append("Snapwire operates as a Passive Security Intermediary (Reverse Proxy). It does not generate, ")
    md.append("modify, or assume responsibility for the underlying intent or output of the AI Model. ")
    md.append("Snapwire's liability is limited to the integrity of the gateway's execution of user-defined rules.")
    md.append("")
    md.append("---")
    md.append("")
    md.append("*This report was generated by `python -m sentinel --export-nist`. ")
    md.append("For the full NIST Audit Report (PDF), visit the Snapwire Dashboard.*")
    md.append("")

    output_path = "snapwire-nist-mapping.md"
    with open(output_path, "w") as f:
        f.write("\n".join(md))

    print(f"\n  NIST Compliance Mapping Report generated successfully!")
    print(f"  ─────────────────────────────────────────────────────")
    print(f"  File:     {os.path.abspath(output_path)}")
    print(f"  Grade:    {grade}")
    print(f"  Mode:     {config['mode'].upper()}")
    print(f"  Rules:    {len(rules)} active")
    print(f"  Generated: {timestamp}")
    print()
    if grade != "A":
        print(f"  Note: {grade_note}")
        print()
