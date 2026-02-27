from fpdf import FPDF
from datetime import datetime
import hashlib


def generate_safety_pdf():
    from src.nist_mapping import generate_compliance_report
    from models import ConstitutionRule, AuditLogEntry

    rule_names = set()
    try:
        rules = ConstitutionRule.query.all()
        rule_names = {r.rule_name for r in rules}
    except Exception:
        pass

    report = generate_compliance_report(rule_names)
    score = report.get("overall_score", 0)
    grade = report.get("grade", "D")
    covered = report.get("covered", 0)
    partial = report.get("partial", 0)
    gaps = report.get("gaps", 0)
    total = report.get("total_categories", 0)

    safeguard_list = [
        "Constitutional Rule Engine",
        "OpenClaw CVE-2026-25253 Safeguard",
        "Loop Detector (Fuse Breaker)",
        "Input Sanitizer",
        "Blast Radius Controls",
        "Honeypot Tripwires",
        "Identity Vault (Snap-Tokens)",
        "Tool Safety Catalog",
        "Deception Detector",
        "Schema Guard",
        "Risk Index Scoring",
        "Thinking Token Sentinel",
        "Rate Limiter",
    ]

    audit_fingerprint = ""
    try:
        recent = AuditLogEntry.query.order_by(AuditLogEntry.created_at.desc()).limit(100).all()
        log_data = "|".join(
            f"{e.id}:{e.tool_name}:{e.status}:{e.created_at}" for e in recent
        )
        audit_fingerprint = hashlib.sha256(log_data.encode()).hexdigest()
    except Exception:
        audit_fingerprint = "N/A"

    now = datetime.utcnow()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.set_fill_color(20, 20, 30)
    pdf.rect(0, 0, 210, 50, 'F')
    pdf.set_text_color(255, 140, 0)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_y(12)
    pdf.cell(0, 10, "SNAPWIRE", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(200, 200, 210)
    pdf.cell(0, 6, "Public Safety Disclosure Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(150, 150, 160)
    pdf.cell(0, 6, f"Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(58)
    pdf.set_text_color(40, 40, 50)

    score_color = (0, 180, 150) if score >= 70 else (220, 170, 50) if score >= 40 else (220, 60, 80)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "1. NIST Grade & Coverage Score", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 48)
    pdf.set_text_color(*score_color)
    pdf.cell(60, 25, f"{grade}", new_x="RIGHT", new_y="TOP")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(60, 60, 70)
    x_start = pdf.get_x() + 5
    y_start = pdf.get_y()
    pdf.set_xy(x_start, y_start + 2)
    pdf.cell(0, 6, f"NIST IR 8596 Coverage: {score}%", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x_start)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, f"{total} categories | {covered} covered | {partial} partial | {gaps} gaps", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    readiness = "Excellent" if score >= 80 else "Good" if score >= 60 else "Developing" if score >= 40 else "Initial"
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(100, 100, 110)
    pdf.cell(0, 6, f"Readiness Grade: {readiness} - Based on CSF 2.0 function mapping of installed Snapwire rule packs.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "2. Coverage Breakdown", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_fill_color(240, 240, 245)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(60, 60, 70)
    pdf.cell(30, 8, "ID", border=1, fill=True)
    pdf.cell(25, 8, "Function", border=1, fill=True)
    pdf.cell(75, 8, "Category", border=1, fill=True)
    pdf.cell(25, 8, "Status", border=1, fill=True)
    pdf.cell(35, 8, "Packs", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 8)
    for cat in report.get("categories", []):
        pdf.set_text_color(40, 40, 50)
        status = cat["status"]
        if status == "covered":
            status_color = (16, 185, 129)
            status_label = "Covered"
        elif status == "partial":
            status_color = (245, 158, 11)
            status_label = "Partial"
        else:
            status_color = (239, 68, 68)
            status_label = "Gap"

        packs_str = ", ".join(cat["covering_packs"][:2]) if cat["covering_packs"] else "-"
        if len(packs_str) > 18:
            packs_str = packs_str[:15] + "..."

        name = cat["name"]
        if len(name) > 40:
            name = name[:37] + "..."

        pdf.cell(30, 7, cat["id"], border=1)
        pdf.cell(25, 7, cat["function"], border=1)
        pdf.cell(75, 7, name, border=1)
        pdf.set_text_color(*status_color)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(25, 7, status_label, border=1)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(40, 40, 50)
        pdf.cell(35, 7, packs_str, border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "3. Intended Use & Boundaries", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5, "Snapwire is a high-risk governance layer designed to sit between AI agents and their tool-call targets. It functions as a deterministic security gateway (reverse proxy) that intercepts, evaluates, and enforces policy on every tool call an autonomous agent makes.")
    pdf.ln(2)
    intended_uses = [
        "Real-time interception and policy enforcement for AI agent tool calls",
        "Human-in-the-loop review queue for high-risk or ambiguous actions",
        "Constitutional rule engine with severity-based blocking and monitoring",
        "Immutable forensic audit trail of all agent decisions and delegations",
    ]
    for item in intended_uses:
        pdf.cell(5, 5, "")
        pdf.cell(0, 5, f"- {item}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(0, 5, "Snapwire does not generate, modify, or assume responsibility for the underlying intent or output of the AI model. It operates as a passive security intermediary.")
    pdf.ln(4)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "4. Foreseeable Misuse & Mitigation", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    misuse_items = [
        "CVE-2026-25253 (OpenClaw): BASE_URL redirect, credential exfiltration, domain spoofing, WebSocket hijacking, and environment variable injection are detected and blocked",
        "Hallucination loops: The Fuse Breaker (Loop Detector) identifies and kills repetitive tool-call patterns before they drain budgets",
        "Prompt injection via tool parameters: Input sanitization strips injection attempts from agent-supplied parameters",
        "Credential theft: The Identity Vault ensures agents never see raw secrets; Snap-Tokens are used as proxies",
        "Unauthorized escalation: Blast Radius controls and Honeypot tripwires detect and contain rogue agent behavior",
    ]
    for item in misuse_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(4)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "5. Human Accountability Statement", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    accountability_items = [
        "X-Snapwire-Authorized-By header injected into every proxied request for immutable operator attribution",
        "X-Snapwire-Origin-ID header traces every request back to its originating Snapwire instance",
        "All blocked, approved, and pending decisions logged with timestamps, agent IDs, and operator context",
        "The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator",
    ]
    for item in accountability_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(4)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "6. Algorithmic Discrimination Protections", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    discrimination_items = [
        "Constitutional Auditor: Every tool call evaluated against configurable constitutional rules encoding equity and fairness policies",
        "Equity-aware rule templates: Pre-built rule packs include data protection rules to prevent PII leakage and discriminatory data handling",
        "Shadow Mode: New rules tested in observation mode before enforcement, preventing unintended discriminatory blocking",
        "Community Rules: Open, peer-reviewed rule contributions ensure diverse perspectives in governance policy",
        "Deception Detection: Heuristic analysis identifies agent circumvention of safety rules through obfuscation",
    ]
    for item in discrimination_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(4)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "7. Compliance Standards", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    standards = [
        "NIST IR 8596 - AI Agent Security Profile (CSF 2.0)",
        "Colorado SB24-205 - AI Consumer Protections",
        "Singapore Model Governance Framework v1.1",
        "OWASP Top 10 for LLM Applications",
    ]
    for item in standards:
        pdf.cell(5, 5, "")
        pdf.cell(0, 5, f"- {item}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "8. Active Safeguards", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.cell(0, 6, f"This instance has {len(safeguard_list)} active safeguards:", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    for i, safeguard in enumerate(safeguard_list, 1):
        pdf.cell(5, 5, "")
        pdf.cell(0, 5, f"{i}. {safeguard}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "9. Audit Log Fingerprint", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.cell(0, 6, "SHA-256 fingerprint of the most recent 100 audit log entries:", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Courier", "", 9)
    pdf.set_text_color(255, 140, 0)
    pdf.cell(0, 6, audit_fingerprint, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_fill_color(245, 245, 248)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 130)
    disclaimer = (
        "This report is generated by Snapwire and is informational only. It does not constitute a formal "
        "NISTIR 8596 audit, certification, or legal compliance determination. It reflects CSF 2.0 alignment "
        "based on installed Snapwire rule packs. All blocks, alerts, and signals are heuristic and advisory "
        "in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with "
        "the human operator. Snapwire is provided under the Apache 2.0 license on an AS-IS basis."
    )
    pdf.multi_cell(0, 4, disclaimer, fill=True)

    pdf.ln(4)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(150, 150, 160)
    pdf.cell(0, 4, f"Snapwire  |  The Firewall for AI Agents  |  Report generated {now.strftime('%Y-%m-%d %H:%M UTC')}", align="C")

    return bytes(pdf.output())


def generate_vanguard_guide_pdf():
    now = datetime.utcnow()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.set_fill_color(20, 20, 30)
    pdf.rect(0, 0, 210, 50, 'F')
    pdf.set_text_color(255, 140, 0)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_y(12)
    pdf.cell(0, 10, "SNAPWIRE", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(200, 200, 210)
    pdf.cell(0, 6, "Vanguard User Guide", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(150, 150, 160)
    pdf.cell(0, 6, f"Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(58)
    pdf.set_text_color(40, 40, 50)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "1. Hold Window", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5,
        "The Hold Window is Snapwire's human-in-the-loop control mechanism. When an AI agent makes a "
        "tool call that triggers a constitutional rule, the action is held for human review instead of "
        "being immediately blocked or approved."
    )
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "How It Works", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    hold_items = [
        "When a tool call matches a hold-eligible rule, Snapwire returns HTTP 202 (Accepted) to the calling agent, signaling the action is pending review.",
        "The configurable hold timeout ranges from 0 to 60 seconds. If no human responds within the timeout, the action is auto-released according to your configured policy (approve or deny).",
        "Operators can approve or deny held actions from the Snapwire dashboard, Slack, or via the API.",
        "All hold decisions are logged in the immutable audit trail with the operator identity, timestamp, and decision rationale.",
    ]
    for item in hold_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "Configuration", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5,
        "Set the hold window duration in your tenant settings (0-60 seconds). A value of 0 disables the "
        "hold window and reverts to immediate block/approve behavior. The recommended setting for "
        "production deployments is 30 seconds."
    )
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "2. Slack Alerts", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5,
        "Snapwire integrates with Slack via Socket Mode to deliver real-time alerts when actions are "
        "held for review. This enables operators to triage agent actions without leaving their existing workflow."
    )
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "Setup", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    setup_items = [
        "Create a Slack app at api.slack.com with Socket Mode enabled.",
        "Add the SLACK_BOT_TOKEN and SLACK_APP_TOKEN environment variables to your Snapwire instance.",
        "Configure the notification channel in your Snapwire dashboard under Settings > Webhooks & Notifications.",
        "Snapwire will send Block Kit messages to the configured channel whenever an action is held.",
    ]
    for item in setup_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "Approve / Kill Buttons", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5,
        "Each Slack alert includes interactive Approve and Kill buttons. Clicking Approve releases the "
        "held action and allows the agent to proceed. Clicking Kill permanently denies the action. Both "
        "decisions are recorded in the audit log with the Slack user identity (slack:<username>) as the "
        "resolver, providing full traceability."
    )
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "3. Weekly Compliance Digest", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5,
        "Every Friday at 9:00 AM UTC, Snapwire generates and distributes a Weekly Compliance Digest "
        "summarizing the prior week's agent activity, enforcement decisions, and compliance posture."
    )
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "Digest Contents", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    digest_items = [
        "Total tool calls intercepted and evaluated during the week.",
        "Breakdown of approved, blocked, held, and shadow-blocked actions.",
        "Top triggered rules and most active agents.",
        "Risk score trends and high-risk action summary.",
        "SHA-256 fingerprint of the audit log for the reporting period, enabling independent verification of log integrity.",
    ]
    for item in digest_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "Distribution", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5,
        "The digest is sent via Slack (if configured) and email (if email notifications are enabled in "
        "tenant settings). It can also be accessed on-demand via the Snapwire dashboard."
    )
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "4. Safety PDF & Compliance Reporting", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.multi_cell(0, 5,
        "Snapwire generates a comprehensive Safety Disclosure PDF that documents your instance's "
        "compliance posture, active safeguards, and NIST IR 8596 coverage grade."
    )
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "Using the Safety PDF", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    usage_items = [
        "Download from the /safety page or via /safety/pdf at any time.",
        "The PDF includes your current NIST grade, coverage breakdown by CSF 2.0 function, active safeguards list, and audit log fingerprint.",
        "Use it as supporting documentation for NIST AI RMF compliance filings.",
        "Attach it to Colorado SB24-205 impact assessments as evidence of algorithmic discrimination protections and human oversight.",
        "The audit log fingerprint (SHA-256) enables independent verification that your logs have not been tampered with.",
    ]
    for item in usage_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 6, "Regulatory Alignment", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    reg_items = [
        "NIST IR 8596 (AI Agent Security Profile / CSF 2.0): Coverage grading across Govern, Protect, Detect, Respond, and Recover functions.",
        "Colorado SB24-205 (AI Consumer Protections): Affirmative defense evidence including human oversight records, discrimination testing, and safety disclosures.",
        "OWASP Top 10 for LLM Applications: Safeguards mapped to prompt injection, insecure output handling, and other LLM-specific threats.",
    ]
    for item in reg_items:
        pdf.cell(5, 5, "")
        pdf.multi_cell(0, 5, f"- {item}")
        pdf.ln(1)
    pdf.ln(6)

    pdf.set_fill_color(245, 245, 248)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 130)
    disclaimer = (
        "This guide is provided by Snapwire for informational purposes only. It does not constitute legal advice, "
        "formal certification, or a guarantee of regulatory compliance. Snapwire operates as a technical monitoring "
        "utility. All blocks, alerts, and signals are heuristic and advisory in nature. The final Duty of Care for "
        "all agent actions and budgetary releases remains solely with the human operator."
    )
    pdf.multi_cell(0, 4, disclaimer, fill=True)

    pdf.ln(4)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(150, 150, 160)
    pdf.cell(0, 4, f"Snapwire  |  Vanguard User Guide  |  Generated {now.strftime('%Y-%m-%d %H:%M UTC')}", align="C")

    return bytes(pdf.output())
