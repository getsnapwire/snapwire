from fpdf import FPDF
from datetime import datetime


def generate_compliance_pdf(tenant_id):
    from models import AuditLogEntry, ConstitutionRule
    from src.nist_mapping import generate_compliance_report
    from src.action_queue import get_stats, get_weekly_digest
    from sqlalchemy import func

    rules = ConstitutionRule.query.filter_by(tenant_id=tenant_id).all()
    installed_rule_names = {r.rule_name for r in rules}
    nist_report = generate_compliance_report(installed_rule_names)

    stats = get_stats(tenant_id=tenant_id)
    digest = get_weekly_digest(tenant_id=tenant_id)

    unique_agents = set()
    parent_chain_count = 0
    recent_entries = AuditLogEntry.query.filter_by(tenant_id=tenant_id).order_by(AuditLogEntry.created_at.desc()).limit(500).all()
    for entry in recent_entries:
        if entry.agent_id:
            unique_agents.add(entry.agent_id)
        if entry.parent_agent_id:
            parent_chain_count += 1

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
    pdf.cell(0, 6, "NISTIR 8596 Cyber AI Profile  |  Compliance Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(150, 150, 160)
    pdf.cell(0, 6, f"Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(58)
    pdf.set_text_color(40, 40, 50)

    score = nist_report["overall_score"]
    covered = nist_report["covered"]
    partial = nist_report["partial"]
    gaps = nist_report["gaps"]
    total = nist_report["total_categories"]

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "1. Compliance Score Overview", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    score_color = (0, 180, 150) if score >= 70 else (220, 170, 50) if score >= 40 else (220, 60, 80)
    pdf.set_font("Helvetica", "B", 48)
    pdf.set_text_color(*score_color)
    pdf.cell(60, 25, f"{score}%", new_x="RIGHT", new_y="TOP")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(60, 60, 70)
    x_start = pdf.get_x() + 5
    y_start = pdf.get_y()
    pdf.set_xy(x_start, y_start + 2)
    pdf.cell(0, 6, f"Overall NISTIR 8596 Readiness Score", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x_start)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, f"{total} categories assessed  |  {covered} covered  |  {partial} partial  |  {gaps} gaps", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    grade = "Excellent" if score >= 80 else "Good" if score >= 60 else "Developing" if score >= 40 else "Initial"
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(100, 100, 110)
    pdf.cell(0, 6, f"Readiness Grade: {grade} — Based on CSF 2.0 function mapping of installed Snapwire rule packs.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "2. NIST Category Breakdown", new_x="LMARGIN", new_y="NEXT")
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
    for cat in nist_report["categories"]:
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

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "3. Audit Activity Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)

    total_actions = stats.get("total", 0)
    allowed_count = stats.get("allowed", 0)
    blocked_count = stats.get("blocked", 0)
    pending_count = stats.get("pending", 0)
    approval_rate = stats.get("approval_rate", 0)

    col_w = 38
    pdf.set_fill_color(245, 247, 250)
    for label, value in [("Total Actions", str(total_actions)), ("Allowed", str(allowed_count)), ("Blocked", str(blocked_count)), ("Pending", str(pending_count))]:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(40, 40, 50)
        pdf.cell(col_w, 10, value, align="C", fill=True, border=1)
    pdf.ln()
    for label, value in [("Total Actions", str(total_actions)), ("Allowed", str(allowed_count)), ("Blocked", str(blocked_count)), ("Pending", str(pending_count))]:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 100, 110)
        pdf.cell(col_w, 6, label, align="C", border=1)
    pdf.ln(8)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.cell(0, 6, f"Approval Rate: {approval_rate}%", new_x="LMARGIN", new_y="NEXT")

    top_violations = stats.get("top_violations", {})
    if top_violations:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(40, 40, 50)
        pdf.cell(0, 7, "Top Violations:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 60, 70)
        for rule_name, count in list(top_violations.items())[:5]:
            display_name = rule_name.replace("_", " ").title()
            if len(display_name) > 50:
                display_name = display_name[:47] + "..."
            pdf.cell(0, 5, f"  {display_name}: {count} occurrence(s)", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(40, 40, 50)
    pdf.cell(0, 10, "4. Identity Attribution Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.cell(0, 6, f"Unique Agents Tracked: {len(unique_agents)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Actions with Parent Agent Chain: {parent_chain_count}", new_x="LMARGIN", new_y="NEXT")

    chain_pct = round((parent_chain_count / len(recent_entries)) * 100, 1) if recent_entries else 0
    pdf.cell(0, 6, f"Chain-of-Command Coverage: {chain_pct}%", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 100, 110)
    pdf.cell(0, 5, "NISTIR 8596 requires unique identities, defined permissions, and traceable decision logs for AI agents.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, "Parent Agent ID attribution enables full Human > Agent > Sub-agent chain-of-command traceability.", new_x="LMARGIN", new_y="NEXT")

    digest_period = digest.get("period", "N/A")
    digest_total = digest.get("total_audited", 0)
    if digest_total > 0:
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(40, 40, 50)
        pdf.cell(0, 10, "5. Weekly Digest", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(60, 60, 70)
        pdf.cell(0, 6, f"Period: {digest_period}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Total Audited: {digest_total}  |  Allowed: {digest.get('allowed', 0)}  |  Blocked: {digest.get('blocked', 0)}", new_x="LMARGIN", new_y="NEXT")

        top_agents = digest.get("top_agents", {})
        if top_agents:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "Most Active Agents:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for agent_name, count in list(top_agents.items())[:5]:
                pdf.cell(0, 5, f"  {agent_name}: {count} actions", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(10)
    pdf.set_fill_color(245, 245, 248)
    y_before = pdf.get_y()
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
